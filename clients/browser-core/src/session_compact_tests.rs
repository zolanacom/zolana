//! Retained V2/V3 parity through the actual wallet session. These isolated
//! transcripts reuse the parent's real proofs; they do not model consensus.
use super::*;

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

// Independent test encoder, cross-checked against the Python codec golden.
fn compact_page(v2: &Value) -> (Value, Vec<u8>) {
    let mut metadata = v2.clone();
    let blocks = metadata.as_object_mut().unwrap().remove("blocks").unwrap();
    let blocks = blocks.as_array().unwrap();
    let mut raw = Vec::new();
    let mut rows = Vec::new();
    let mut height = 0;
    for (index, block) in blocks.iter().enumerate() {
        varint(
            block["slot"].as_u64().unwrap() - block["parent_slot"].as_u64().unwrap(),
            &mut raw,
        );
        let next_height = block["block_height"].as_u64().unwrap();
        varint(next_height - height, &mut raw);
        height = next_height;
        let bytes = bs58::decode(block["blockhash"].as_str().unwrap())
            .into_vec()
            .unwrap();
        assert_eq!(bytes.len(), 32);
        raw.extend(bytes);
        if !block["transactions"].as_array().unwrap().is_empty() {
            rows.push(json!([index, block["transactions"]]));
        }
    }
    metadata["compact_headers"] = json!({"format":"zolana-retained-headers-v1", "count":blocks.len(),
        "parent_slot":blocks.first().map(|b| b["parent_slot"].clone()),
        "previous_blockhash":blocks.first().map(|b| b["previous_blockhash"].clone())});
    metadata["transactions"] = Value::Array(rows);
    (metadata, raw)
}

fn page(blocks: &[Value], after: u64, target: u64) -> Value {
    let next = blocks.last().map_or(after, |b| b["slot"].as_u64().unwrap());
    json!({"network":serde_json::from_str::<Value>(&network_json()).unwrap(),
        "checkpoint":{"segments":1,"sha256":"0".repeat(64)}, "retained_tip":target,
        "after_slot":after,"through_slot":target,"next_slot":next,"complete":next>=target,"blocks":blocks})
}

fn decoded_value(page: &Page) -> Value {
    json!({"network":page.network,"checkpoint":page.checkpoint,"retained_tip":page.retained_tip,
        "after_slot":page.after_slot,"through_slot":page.through_slot,"next_slot":page.next_slot,
        "complete":page.complete,"blocks":page.blocks})
}

fn apply_compact(wallet: &mut BrowserVault, v2: &Value) {
    let (metadata, raw) = compact_page(v2);
    wallet
        .apply_compact_history_page(&metadata.to_string(), &raw)
        .unwrap();
}

fn begin_funded(target: u64) -> BrowserVault {
    let f = fixture();
    let mut pool = PoolState::decode(&f.pool1).unwrap();
    for slot in 2..=target {
        pool.complete_slot(slot).unwrap();
    }
    let mut wallet = restored(&f.alice);
    wallet
        .begin_sync(
            &pool_reply(&pool.encode(), target),
            &header(target),
            &f.checkpoint,
            &header(1),
        )
        .unwrap();
    wallet
}

#[test]
fn cross_language_golden_preserves_every_header_and_original_sparse_transaction() {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../tools/fixtures/gateway_history_compact_v1.json"
    ))
    .unwrap();
    assert_eq!(golden["format"], "zolana-retained-codec-golden-v1");
    let mut metadata = golden["v3_result"].clone();
    let wire = metadata["compact_headers"]
        .as_object_mut()
        .unwrap()
        .remove("data_base64")
        .unwrap();
    let raw = STANDARD.decode(wire.as_str().unwrap()).unwrap();
    let decoded = compact::decode(&metadata.to_string(), &raw).unwrap();
    let mut v2 = metadata.clone();
    v2.as_object_mut().unwrap().remove("compact_headers");
    v2.as_object_mut().unwrap().remove("transactions");
    v2["blocks"] = golden["v2_blocks"].clone();
    let original: Page = serde_json::from_value(v2.clone()).unwrap();
    assert_eq!(decoded_value(&decoded), decoded_value(&original));
    assert_eq!(compact_page(&v2), (metadata, raw));
}

#[test]
fn real_signed_funding_send_balances_and_saved_checkpoint_are_v2_v3_identical() {
    let f = fixture();
    let blocks = vec![f.funding.clone(), f.send.clone()];
    let v2_page = page(&blocks, 0, 2);
    for (backup, expected) in [(&f.alice, "57"), (&f.bob, "40")] {
        let mut v2 = restored(backup);
        let mut v3 = restored(backup);
        for wallet in [&mut v2, &mut v3] {
            wallet
                .begin_sync(&pool_reply(&f.pool2, 2), &header(2), &[], "null")
                .unwrap();
        }
        v2.apply_history_page(&v2_page.to_string()).unwrap();
        apply_compact(&mut v3, &v2_page);
        let saved2 = v2.finish_sync().unwrap();
        let saved3 = v3.finish_sync().unwrap();
        let plain2: Value =
            serde_json::from_slice(&v2.unseal(CACHE_MAGIC, &saved2).unwrap()).unwrap();
        let plain3: Value =
            serde_json::from_slice(&v3.unseal(CACHE_MAGIC, &saved3).unwrap()).unwrap();
        assert_eq!(plain2, plain3); // Ciphertexts use independent random nonces.
        assert_eq!(v2.payment_status().unwrap(), v3.payment_status().unwrap());
        let status: Value = serde_json::from_str(&v3.payment_status().unwrap()).unwrap();
        assert_eq!(status["balance"], expected);
        let mut reopened = restored(backup);
        reopened
            .begin_sync(&pool_reply(&f.pool2, 2), &header(2), &saved3, &header(2))
            .unwrap();
        reopened.finish_sync().unwrap();
        assert_eq!(
            reopened.payment_status().unwrap(),
            v3.payment_status().unwrap()
        );
    }
}

#[test]
fn changed_token_after_a_valid_compact_page_cannot_publish_a_partial_checkpoint() {
    let mut wallet = begin_funded(4);
    apply_compact(&mut wallet, &page(&[block(2, vec![])], 1, 4));
    assert!(wallet.finish_sync().is_err());
    // finish_sync consumes the incomplete session; begin anew for token check.
    let mut wallet = begin_funded(4);
    apply_compact(&mut wallet, &page(&[block(2, vec![])], 1, 4));
    let (mut metadata, raw) = compact_page(&page(&[block(3, vec![]), block(4, vec![])], 2, 4));
    metadata["checkpoint"]["sha256"] = json!("1".repeat(64));
    assert!(wallet
        .apply_compact_history_page(&metadata.to_string(), &raw)
        .is_err());
    assert!(wallet.finish_sync().is_err());
    assert!(wallet.payment_status().is_err());
}

#[test]
fn compact_network_target_parent_hash_height_and_truncation_fail_closed() {
    let good = page(
        &[block(2, vec![]), block(3, vec![]), block(4, vec![])],
        1,
        4,
    );
    let (metadata, raw) = compact_page(&good);
    for mutation in [
        "network",
        "target",
        "parent",
        "previous_hash",
        "height",
        "truncated",
        "trailing",
        "row_order",
    ] {
        let mut wallet = begin_funded(4);
        let mut changed = metadata.clone();
        let mut bytes = raw.clone();
        match mutation {
            "network" => changed["network"]["network"][0] = json!(8),
            "target" => changed["through_slot"] = json!(3),
            "parent" => changed["compact_headers"]["parent_slot"] = json!(0),
            "previous_hash" => changed["compact_headers"]["previous_blockhash"] = json!(hash_at(9)),
            "height" => bytes[1] = 1, // Must advance beyond checkpoint height1.
            "truncated" => {
                bytes.pop();
            }
            "trailing" => bytes.push(0),
            "row_order" => changed["transactions"] = json!([[1, [{}]], [0, [{}]]]),
            _ => unreachable!(),
        }
        assert!(
            wallet
                .apply_compact_history_page(&changed.to_string(), &bytes)
                .is_err(),
            "{mutation}"
        );
        assert!(wallet.finish_sync().is_err(), "{mutation}");
        assert!(wallet.payment_status().is_err(), "{mutation}");
    }
}

#[test]
fn compact_decode_failure_discards_prior_page_and_final_hash_still_must_match_rpc() {
    let mut wallet = begin_funded(4);
    apply_compact(&mut wallet, &page(&[block(2, vec![])], 1, 4));
    let (metadata, mut raw) = compact_page(&page(&[block(3, vec![]), block(4, vec![])], 2, 4));
    raw.pop();
    assert!(wallet
        .apply_compact_history_page(&metadata.to_string(), &raw)
        .is_err());
    assert!(wallet.finish_sync().is_err());
    assert!(wallet.payment_status().is_err());

    let mut wallet = begin_funded(4);
    let mut changed = page(
        &[block(2, vec![]), block(3, vec![]), block(4, vec![])],
        1,
        4,
    );
    changed["blocks"][2]["blockhash"] = json!(hash_at(9));
    apply_compact(&mut wallet, &changed);
    assert!(wallet.finish_sync().is_err());
    assert!(wallet.payment_status().is_err());
}

#[test]
fn compact_retained_inclusion_and_absence_never_settle_a_pending_original() {
    let f = fixture();
    let mut wallet = restored(&f.alice);
    wallet
        .validate_pending_checkpoint(&f.pending, &f.checkpoint)
        .unwrap();
    wallet
        .begin_sync(
            &pool_reply(&f.pool2, 2),
            &header(2),
            &f.checkpoint,
            &header(1),
        )
        .unwrap();
    apply_compact(&mut wallet, &page(std::slice::from_ref(&f.send), 1, 2));
    wallet.finish_sync().unwrap();
    assert_eq!(decision(&wallet, &f.pending), "unknown");
    let original: Value =
        serde_json::from_str(&wallet.pending_packet(&f.pending).unwrap()).unwrap();
    assert_eq!(original["id"], f.id);

    let empties = vec![block(2, vec![]), block(3, vec![]), block(4, vec![])];
    let mut wallet = begin_funded(4);
    apply_compact(&mut wallet, &page(&empties, 1, 4));
    wallet.finish_sync().unwrap();
    assert_eq!(decision(&wallet, &f.pending), "unknown");
    // The identical complete canonical transcript retains its existing power
    // to establish expiry/absence; compact retained transport does not gain it.
    let mut wallet = begin_funded(4);
    wallet
        .apply_canonical_blocks(&serde_json::to_string(&empties).unwrap())
        .unwrap();
    wallet.finish_sync().unwrap();
    assert_eq!(decision(&wallet, &f.pending), "expired-absent");
}
