//! Explicit retained ciphertext pages, never canonical inclusion/absence evidence.
use super::*;
use solana_rpc_client_api::request::RpcRequest;

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
        let mut checkpoint: Option<Token> = None;
        let mut used = false;
        loop {
            let before = result.slot;
            let fetched = Instant::now();
            let page: Option<Page> = self.rpc.send(RpcRequest::Custom { method: "getWalletRetainedHistory" },
                serde_json::json!([before, target, checkpoint]))
                .map_err(|error| format!("cannot read retained history; an updated invited gateway is required: {error}"))?;
            result.scan.fetch_ms += fetched.elapsed().as_millis();
            result.scan.retained_rpc_requests += 1;
            let Some(page) = page else {
                if checkpoint.is_some() {
                    return Err("retained history disappeared during recovery".into());
                }
                return Ok(false);
            };
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
                || page.blocks.len() > 16
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
            checkpoint = Some(page.checkpoint);
            for block in page.blocks {
                let replayed = Instant::now();
                result.apply_retained_block(block)?;
                result.scan.replay_ms += replayed.elapsed().as_millis();
                result.scan.history_blocks_read += 1;
                used = true;
            }
            if page.complete {
                return Ok(used);
            }
        }
    }
}
