//! Lossless transport decoding only. The resulting Page enters exactly the
//! same retained-history verifier as V2; these bytes convey no new authority.
use super::{hash, parsed, Block, Page, Result, Token};
use native_wallet_seed::Network;
use serde::Deserialize;
use serde_json::Value;

const MAX_BLOCKS: usize = 32768;
const FORMAT: &str = "zolana-retained-headers-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Headers {
    format: String,
    count: usize,
    parent_slot: Option<u64>,
    previous_blockhash: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    network: Network,
    checkpoint: Token,
    retained_tip: u64,
    after_slot: u64,
    through_slot: u64,
    next_slot: u64,
    complete: bool,
    compact_headers: Headers,
    transactions: Vec<(usize, Vec<Value>)>,
}
fn invalid<T>() -> Result<T> {
    Err("invalid compact retained history encoding".into())
}
fn varint(raw: &[u8], offset: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    for index in 0..10 {
        let byte = *raw
            .get(*offset)
            .ok_or("truncated compact history integer")?;
        *offset += 1;
        if index == 9 && byte > 1 {
            return invalid();
        }
        result |= u64::from(byte & 127) << (index * 7);
        if byte & 128 == 0 {
            if index > 0 && byte == 0 {
                return invalid();
            }
            return Ok(result);
        }
    }
    invalid()
}
pub(super) fn decode(metadata_json: &str, raw: &[u8]) -> Result<Page> {
    // u64 varints use at most10 bytes each, followed by one32-byte hash.
    if raw.len() > MAX_BLOCKS * 52 {
        return invalid();
    }
    let meta: Metadata = parsed(metadata_json, 16 * 1024 * 1024)?;
    let headers = meta.compact_headers;
    if headers.format != FORMAT
        || headers.count > MAX_BLOCKS
        || meta.transactions.len() > headers.count
    {
        return invalid();
    }
    let mut blocks = Vec::with_capacity(headers.count);
    if headers.count == 0 {
        if headers.parent_slot.is_some()
            || headers.previous_blockhash.is_some()
            || !raw.is_empty()
            || !meta.transactions.is_empty()
        {
            return invalid();
        }
    } else {
        let mut parent = headers
            .parent_slot
            .ok_or("compact history anchor missing")?;
        let mut previous = headers
            .previous_blockhash
            .ok_or("compact history hash anchor missing")?;
        hash(&previous)?;
        let mut height = 0u64;
        let mut offset = 0usize;
        for index in 0..headers.count {
            let delta = varint(raw, &mut offset)?;
            let height_delta = varint(raw, &mut offset)?;
            if delta == 0 || (index > 0 && height_delta == 0) {
                return invalid();
            }
            let slot = parent
                .checked_add(delta)
                .ok_or("compact history slot overflow")?;
            height = height
                .checked_add(height_delta)
                .ok_or("compact history height overflow")?;
            let end = offset
                .checked_add(32)
                .ok_or("compact history offset overflow")?;
            let bytes = raw
                .get(offset..end)
                .ok_or("truncated compact history hash")?;
            offset = end;
            let blockhash = bs58::encode(bytes).into_string();
            blocks.push(Block {
                slot,
                parent_slot: parent,
                blockhash: blockhash.clone(),
                previous_blockhash: previous,
                block_height: height,
                transactions: Vec::new(),
            });
            parent = slot;
            previous = blockhash;
        }
        if offset != raw.len() {
            return invalid();
        }
    }
    let mut previous_index = None;
    for (index, transactions) in meta.transactions {
        if index >= blocks.len()
            || transactions.is_empty()
            || previous_index.is_some_and(|last| index <= last)
        {
            return invalid();
        }
        blocks[index].transactions = transactions;
        previous_index = Some(index);
    }
    Ok(Page {
        network: meta.network,
        checkpoint: meta.checkpoint,
        retained_tip: meta.retained_tip,
        after_slot: meta.after_slot,
        through_slot: meta.through_slot,
        next_slot: meta.next_slot,
        complete: meta.complete,
        blocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn metadata() -> Value {
        json!({"network":{"network":vec![7;32],"genesis_hash":"1".repeat(32)},
            "checkpoint":{"segments":1,"sha256":"a".repeat(64)},"retained_tip":9,
            "after_slot":2,"through_slot":9,"next_slot":9,"complete":true,
            "compact_headers":{"format":FORMAT,"count":2,"parent_slot":2,"previous_blockhash":"1".repeat(32)},
            "transactions":[[1,[{"transaction":["AQ==","base64"],"meta":{"err":null}}]]]})
    }
    fn raw() -> Vec<u8> {
        let mut bytes = vec![3, 5];
        bytes.extend([11; 32]);
        bytes.extend([4, 3]);
        bytes.extend([12; 32]);
        bytes
    }
    #[test]
    fn golden_sparse_payments_and_nonconsecutive_heights_are_lossless() {
        let page = decode(&metadata().to_string(), &raw()).unwrap();
        assert_eq!(
            (
                page.blocks[0].slot,
                page.blocks[0].parent_slot,
                page.blocks[0].block_height
            ),
            (5, 2, 5)
        );
        assert_eq!(
            (
                page.blocks[1].slot,
                page.blocks[1].parent_slot,
                page.blocks[1].block_height
            ),
            (9, 5, 8)
        );
        assert_eq!(page.blocks[1].previous_blockhash, page.blocks[0].blockhash);
        assert_eq!(
            page.blocks[0].blockhash,
            bs58::encode([11; 32]).into_string()
        );
        assert!(page.blocks[0].transactions.is_empty());
        assert_eq!(
            page.blocks[1].transactions,
            metadata()["transactions"][0][1].as_array().unwrap().clone()
        );
    }
    #[test]
    fn truncation_extra_bytes_noncanonical_integers_overflow_and_bad_rows_refuse() {
        let good = raw();
        for end in 0..good.len() {
            assert!(decode(&metadata().to_string(), &good[..end]).is_err());
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(decode(&metadata().to_string(), &extra).is_err());
        for prefix in [vec![0], vec![0x83, 0], vec![0xff; 10], vec![0x80; 11]] {
            let mut changed = prefix;
            changed.extend(&good[1..]);
            assert!(decode(&metadata().to_string(), &changed).is_err());
        }
        let mut changed = metadata();
        changed["compact_headers"]["parent_slot"] = json!(u64::MAX);
        assert!(decode(&changed.to_string(), &good).is_err());
        for rows in [
            json!([[2, [{}]]]),
            json!([[1, [{}]], [1, [{}]]]),
            json!([[1, [{}]], [0, [{}]]]),
            json!([[0, []]]),
        ] {
            let mut changed = metadata();
            changed["transactions"] = rows;
            assert!(decode(&changed.to_string(), &good).is_err());
        }
        let mut changed = metadata();
        changed["compact_headers"]["data_base64"] = json!("not accepted in metadata");
        assert!(decode(&changed.to_string(), &good).is_err());
        let mut changed = metadata();
        changed["compact_headers"]["count"] = json!(MAX_BLOCKS + 1);
        assert!(decode(&changed.to_string(), &good).is_err());
        let mut changed = metadata();
        changed["compact_headers"]["previous_blockhash"] = json!("bad hash");
        assert!(decode(&changed.to_string(), &good).is_err());
    }
    #[test]
    fn empty_page_has_no_hidden_anchor_or_bytes() {
        let mut meta = metadata();
        meta["compact_headers"] =
            json!({"format":FORMAT,"count":0,"parent_slot":null,"previous_blockhash":null});
        meta["transactions"] = json!([]);
        assert!(decode(&meta.to_string(), &[]).unwrap().blocks.is_empty());
        assert!(decode(&meta.to_string(), &[0]).is_err());
        meta["compact_headers"]["parent_slot"] = json!(0);
        assert!(decode(&meta.to_string(), &[]).is_err());
    }
}
