//! Explicit retained ciphertext pages, never canonical inclusion/absence evidence.
use super::{fetch, Chain, ScanResult};
use crate::archive::HistoryBlock;
use crate::keys::Network;
use crate::Result;
use serde::{Deserialize, Serialize};
use solana_rpc_client_api::request::RpcRequest;
use std::time::Instant;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Token {
    segments: u32,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    network: Network,
    checkpoint: Token,
    retained_tip: u64,
    after_slot: u64,
    through_slot: u64,
    next_slot: u64,
    complete: bool,
    blocks: Vec<HistoryBlock>,
}

impl Chain {
    pub(super) fn scan_retained(&self, result: &mut ScanResult, target: u64) -> Result<bool> {
        let (method, page_blocks) = if self.retained_history_v2 {
            ("getWalletRetainedHistoryV2", 32768)
        } else {
            ("getWalletRetainedHistory", 16)
        };
        // Only public RPC inputs enter this worker. Keep at most one next page
        // in flight while the caller alone verifies and mutates wallet state.
        let rpc = &self.rpc;
        let compact_v2 = self.retained_history_v2;
        let fetch = |before: u64,
                     checkpoint: Option<Token>|
         -> std::result::Result<(Option<Page>, u128), String> {
            let began = Instant::now();
            // The optional fourth parameter explicitly requests a wider page;
            // old three-parameter V2 clients retain their 4096-header contract.
            let params = if compact_v2 {
                serde_json::json!([before, target, checkpoint, page_blocks])
            } else {
                serde_json::json!([before, target, checkpoint])
            };
            let page: Option<Page> = if compact_v2 {
                fetch::history_read(rpc, method, params)
            } else {
                rpc.send(RpcRequest::Custom { method }, params)
            }
            .map_err(|error| {
                format!(
                    "cannot read retained history; an updated invited gateway is required: {error}"
                )
            })?;
            Ok((page, began.elapsed().as_millis()))
        };
        let mut checkpoint: Option<Token> = None;
        let mut used = false;
        let mut prefetched = None;
        loop {
            let before = result.slot;
            let (page, fetched_ms) = match prefetched.take() {
                Some(page) => page,
                None => fetch(before, checkpoint.clone())?,
            };
            result.scan.fetch_ms += fetched_ms;
            result.scan.retained_rpc_requests += 1;
            let Some(page) = page else {
                if checkpoint.is_some() {
                    return Err("retained history disappeared during recovery".into());
                }
                return Ok(false);
            };
            // Include whole-page validation and replay, rather than rounding
            // each sub-millisecond empty block down to zero.
            let replayed = Instant::now();
            let through = target.min(page.retained_tip);
            if page.network != self.network
                || page.retained_tip == 0
                || page.after_slot != before
                || page.through_slot != through
                || !(1..=16384).contains(&page.checkpoint.segments)
                || page.checkpoint.sha256.len() != 64
                || !page
                    .checkpoint
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || checkpoint
                    .as_ref()
                    .is_some_and(|token| token != &page.checkpoint)
                || page.blocks.len() > page_blocks
                || serde_json::to_vec(&page)?.len() > 16 * 1024 * 1024
                || page.next_slot != page.blocks.last().map_or(before, |b| b.slot)
                || page.complete != (page.next_slot >= through)
                || (before < through && page.blocks.is_empty())
                || page.blocks.iter().any(|b| {
                    b.slot <= before
                        || b.slot > through
                        || serde_json::to_vec(b).map_or(true, |v| v.len() > 8 * 1024 * 1024)
                })
            {
                return Err("invalid, changed or incomplete retained history page".into());
            }
            let complete = page.complete;
            checkpoint = Some(page.checkpoint);
            prefetched = std::thread::scope(|scope| -> Result<_> {
                let next = if self.retained_history_v2 && !complete {
                    let token = checkpoint.clone();
                    let cursor = page.next_slot;
                    let fetch = &fetch;
                    Some(scope.spawn(move || fetch(cursor, token)))
                } else {
                    None
                };
                let applied = (|| -> Result<()> {
                    for block in page.blocks {
                        result.apply_retained_block(block)?;
                        result.scan.history_blocks_read += 1;
                        used = true;
                    }
                    Ok(())
                })();
                result.scan.replay_ms += replayed.elapsed().as_millis();
                // Join even after replay failure. No detached request survives
                // an error, and no partial replay can publish a scan cache.
                let fetched = next
                    .map(|worker| {
                        worker
                            .join()
                            .map_err(|_| "retained history read worker panicked".to_owned())
                            .and_then(|page| page)
                    })
                    .transpose();
                applied?;
                Ok(fetched?)
            })?;
            if complete {
                return Ok(used);
            }
        }
    }
}
