//! Full canonical RPC replay for pending outcomes; never retained metadata.
use super::{Chain, ScanResult};
use crate::archive::HistoryBlock;
use crate::keys::Network;
use crate::Result;
use serde::{Deserialize, Serialize};
use solana_rpc_client_api::request::RpcRequest;
use solana_transaction_status_client_types::UiConfirmedBlock;
use std::time::Instant;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Anchor {
    slot: u64,
    blockhash: String,
    block_height: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Block {
    slot: u64,
    block: UiConfirmedBlock,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    network: Network,
    anchor: Anchor,
    after_slot: u64,
    next_slot: u64,
    complete: bool,
    blocks: Vec<Block>,
}

impl Chain {
    pub(super) fn scan_archival(&self, result: &mut ScanResult, target: u64) -> Result<bool> {
        let mut anchor: Option<Anchor> = None;
        loop {
            let before = result.slot;
            let fetched = Instant::now();
            let page: Option<Page> = self
                .rpc
                .send(
                    RpcRequest::Custom {
                        method: "getWalletCanonicalHistory",
                    },
                    serde_json::json!([before, target, anchor]),
                )
                .map_err(|error| {
                    format!(
                        "canonical archival history unavailable; pending record retained: {error}"
                    )
                })?;
            result.scan.fetch_ms += fetched.elapsed().as_millis();
            result.scan.archival_rpc_requests += 1;
            let Some(page) = page else {
                if anchor.is_some() {
                    return Err("canonical archive disappeared during recovery".into());
                }
                return Ok(false);
            };
            if page.network != self.network
                || page.anchor.slot != target
                || !crate::archive::valid_hash(&page.anchor.blockhash)
                || anchor.as_ref().is_some_and(|pinned| pinned != &page.anchor)
                || page.after_slot != before
                || page.blocks.is_empty()
                || page.blocks.len() > 16
                || serde_json::to_vec(&page)?.len() > 16 * 1024 * 1024
                || page.next_slot != page.blocks.last().map_or(before, |b| b.slot)
                || page.complete != (page.next_slot == target)
                || page.blocks.iter().any(|b| {
                    b.slot <= before
                        || b.slot > target
                        || serde_json::to_vec(b).map_or(true, |v| v.len() > 8 * 1024 * 1024)
                })
            {
                return Err("invalid, changed or incomplete canonical archival page".into());
            }
            anchor = Some(page.anchor);
            for block in page.blocks {
                let replayed = Instant::now();
                result.apply_block(HistoryBlock::from_rpc(block.slot, block.block)?)?;
                result.scan.replay_ms += replayed.elapsed().as_millis();
                result.scan.blocks_fetched += 1;
            }
            if page.complete {
                let pinned = anchor.as_ref().unwrap();
                if result.block_hash.as_ref() != Some(&pinned.blockhash)
                    || result.block_height != pinned.block_height
                {
                    return Err(
                        "canonical archive does not reach the pinned finalized checkpoint".into(),
                    );
                }
                return Ok(true);
            }
        }
    }
}
