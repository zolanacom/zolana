//! Real proofs and signed transactions in an isolated synthetic RPC transcript.
//! No network, validator, storage durability or consensus/finality is simulated
//! by these unit tests. The host transcript explicitly supplies execution meta.
#[path = "session_compact_tests.rs"]
mod compact_tests;
#[path = "session_offline_fixture.rs"]
mod offline_fixture;
use super::*;
use native_payments::{envelope, staging::MAX_CHUNK_BYTES};
use native_wallet_core::replay::HistoryInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::sync::OnceLock;

const PASSWORD: &[u8] = b"disposable coordinator fixture password";
const EXPIRY: u64 = 3;
fn network_json() -> String {
    json!({"network":vec![7u8;32],"genesis_hash":"1".repeat(32)}).to_string()
}
fn hash_at(slot: u64) -> String {
    bs58::encode([slot as u8 + 30; 32]).into_string()
}
fn header(slot: u64) -> String {
    json!({"blockhash":hash_at(slot),"blockHeight":slot}).to_string()
}
fn block(slot: u64, transactions: Vec<Value>) -> Value {
    json!({"slot":slot,"parent_slot":slot-1,"blockhash":hash_at(slot),
        "previous_blockhash":hash_at(slot-1),"block_height":slot,"transactions":transactions})
}
fn pool_reply(pool: &[u8], slot: u64) -> String {
    let state = PoolState::decode(pool).unwrap();
    json!({"context":{"slot":slot},"value":{"owner":Pubkey::new_from_array(native_accounts::PROGRAM_ID).to_string(),
        "lamports":state.rent_floor+state.backing,"data":[STANDARD.encode(pool),"base64"]}}).to_string()
}
fn quote() -> String {
    json!({"format":"native-shielded-fee-quote-v1","network":serde_json::from_str::<Value>(&network_json()).unwrap(),
        "transport":"native-inline-v1","pool_format":"NPOOL004","fee":3,
        "payer":sponsor().pubkey().to_string()}).to_string()
}
fn sponsor() -> Keypair {
    Keypair::new_from_array([19; 32])
}
fn restored(backup: &[u8]) -> BrowserVault {
    BrowserVault::restore(&network_json(), backup.to_vec(), PASSWORD.to_vec()).unwrap()
}
fn instruction(accounts: Vec<([u8; 32], bool)>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(native_accounts::PROGRAM_ID),
        accounts: accounts
            .into_iter()
            .map(|(key, is_signer)| AccountMeta::new(Pubkey::new_from_array(key), is_signer))
            .collect(),
        data,
    }
}
fn signed(instructions: &[Instruction], buffer: Option<&Keypair>) -> VersionedTransaction {
    let payer = sponsor();
    let mut signers: Vec<&dyn Signer> = vec![&payer];
    if let Some(buffer) = buffer {
        signers.push(buffer);
    }
    Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &signers,
        Default::default(),
    )
    .into()
}
fn transaction(tx: &VersionedTransaction) -> Value {
    json!({"transaction":[STANDARD.encode(bincode::serialize(tx).unwrap()),"base64"],"meta":{"err":null}})
}
fn replay_instructions(replay: &mut Replay, instructions: &[Instruction], slot: u64) {
    for ix in instructions {
        replay
            .apply(
                &HistoryInstruction {
                    accounts: ix
                        .accounts
                        .iter()
                        .map(|a| (a.pubkey.to_bytes(), a.is_signer))
                        .collect(),
                    data: ix.data.clone(),
                },
                slot,
            )
            .unwrap();
    }
    replay.finish_slot(slot).unwrap();
}
fn staged(payload: &[u8], buffer: &Keypair) -> Vec<Instruction> {
    let payer = sponsor().pubkey().to_bytes();
    let buffer = buffer.pubkey().to_bytes();
    let mut initialize = vec![0];
    initialize.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    initialize.extend_from_slice(&payload_digest(payload));
    initialize.extend_from_slice(&100u64.to_le_bytes());
    let mut instructions = vec![instruction(vec![(buffer, true), (payer, true)], initialize)];
    for (index, chunk) in payload.chunks(MAX_CHUNK_BYTES).enumerate() {
        let mut data = vec![1];
        data.extend_from_slice(&((index * MAX_CHUNK_BYTES) as u32).to_le_bytes());
        data.extend_from_slice(chunk);
        instructions.push(instruction(vec![(buffer, false), (payer, true)], data));
    }
    instructions.push(instruction(vec![(buffer, false), (payer, true)], vec![2]));
    let payment = wire::decode([7; 32], payload).unwrap();
    let mut accounts = vec![
        (native_accounts::pool_address(), false),
        (buffer, false),
        (payer, true),
        (native_accounts::SYSTEM_ID, false),
    ];
    accounts.extend(payment.bundle.actions().iter().map(|a| {
        (
            native_accounts::nullifier_address(&a.nullifier().to_bytes()),
            false,
        )
    }));
    instructions.push(instruction(accounts, vec![3]));
    instructions
}
fn inline(payload: &[u8]) -> Instruction {
    let payment = wire::decode([7; 32], payload).unwrap();
    let mut data = vec![5];
    data.extend_from_slice(&envelope::encode([7; 32], payload).unwrap());
    let mut accounts = vec![
        (native_accounts::pool_address(), false),
        (payment.context.sponsor, true),
        (native_accounts::SYSTEM_ID, false),
    ];
    accounts.extend(payment.bundle.actions().iter().map(|a| {
        (
            native_accounts::nullifier_address(&a.nullifier().to_bytes()),
            false,
        )
    }));
    instruction(accounts, data)
}
fn sync(
    w: &mut BrowserVault,
    pool: &[u8],
    target: u64,
    checkpoint: &[u8],
    blocks: &[Value],
) -> Vec<u8> {
    let cached = if checkpoint.is_empty() {
        "null".into()
    } else {
        let info: Value = serde_json::from_str(&w.checkpoint_info(checkpoint).unwrap()).unwrap();
        header(info["slot"].as_u64().unwrap())
    };
    w.begin_sync(
        &pool_reply(pool, target),
        &header(target),
        checkpoint,
        &cached,
    )
    .unwrap();
    w.apply_canonical_blocks(&serde_json::to_string(blocks).unwrap())
        .unwrap();
    w.finish_sync().unwrap()
}
struct Fixture {
    alice: Vec<u8>,
    bob: Vec<u8>,
    pool1: Vec<u8>,
    pool2: Vec<u8>,
    funding: Value,
    send: Value,
    checkpoint: Vec<u8>,
    pending: Vec<u8>,
    id: String,
    payload: Vec<u8>,
}
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut alice = BrowserVault::create(&network_json(), PASSWORD.to_vec()).unwrap();
        let bob = BrowserVault::create(&network_json(), PASSWORD.to_vec()).unwrap();
        let initial = PoolState::new_slot_anchored([7; 32], 1).unwrap();
        let (mut replay, funding_payload) = with_prover(|p| {
            let state =
                WalletState::with_key_for_pool(&alice, &initial, p.verifying_key()).map_err(err)?;
            let payload = p
                .build(
                    &alice,
                    &state,
                    sponsor().pubkey().to_bytes(),
                    100,
                    Payment::Deposit {
                        amount: 100,
                        recipient: &alice.identity()?.private_address,
                    },
                )
                .map_err(err)?;
            Ok((Replay::from_state(state), payload))
        })
        .unwrap();
        let buffer = Keypair::new_from_array([29; 32]);
        let instructions = staged(&funding_payload, &buffer);
        let funding = block(1, vec![transaction(&signed(&instructions, Some(&buffer)))]);
        replay_instructions(&mut replay, &instructions, 1);
        let pool1 = replay.state.pool.encode();
        let checkpoint = sync(&mut alice, &pool1, 1, &[], std::slice::from_ref(&funding));
        let built: Value = serde_json::from_str(
            &alice
                .build_payment(
                    &bob.identity().unwrap().private_address,
                    40,
                    3,
                    &quote(),
                    EXPIRY,
                    &checkpoint,
                )
                .unwrap(),
        )
        .unwrap();
        let timings = built["build_timings_ms"].as_object().unwrap();
        let expected = [
            "checkpoint",
            "wallet_build",
            "validation",
            "anchor",
            "keys",
            "inputs",
            "bundle",
            "authorization",
            "proof",
            "signatures",
            "encoding",
            "seal",
        ];
        assert_eq!(timings.len(), expected.len());
        for phase in expected {
            assert!(timings[phase].as_u64().is_some(), "numeric phase {phase}");
        }
        let pending: Vec<u8> = serde_json::from_value(built["encrypted_pending"].clone()).unwrap();
        let packet: Value = serde_json::from_str(&alice.pending_packet(&pending).unwrap()).unwrap();
        let payload = STANDARD
            .decode(packet["packet"]["payload"].as_str().unwrap())
            .unwrap();
        let ix = inline(&payload);
        let send = block(
            2,
            vec![transaction(&signed(std::slice::from_ref(&ix), None))],
        );
        replay_instructions(&mut replay, &[ix], 2);
        Fixture {
            alice: alice.encrypted_backup(),
            bob: bob.encrypted_backup(),
            pool1,
            pool2: replay.state.pool.encode(),
            funding,
            send,
            checkpoint,
            pending,
            id: built["packet_id"].as_str().unwrap().into(),
            payload,
        }
    })
}
fn funded() -> BrowserVault {
    let f = fixture();
    let mut w = restored(&f.alice);
    sync(&mut w, &f.pool1, 1, &[], std::slice::from_ref(&f.funding));
    w
}
fn decision(w: &BrowserVault, pending: &[u8]) -> String {
    serde_json::from_str::<Value>(&w.pending_outcome(pending).unwrap()).unwrap()["decision"]
        .as_str()
        .unwrap()
        .into()
}
fn retained(blocks: &[Value], after: u64, through: u64) -> String {
    json!({"network":serde_json::from_str::<Value>(&network_json()).unwrap(),
        "checkpoint":{"segments":1,"sha256":"0".repeat(64)},"retained_tip":through,
        "after_slot":after,"through_slot":through,"next_slot":through,"complete":true,"blocks":blocks}).to_string()
}
fn archival(blocks: &[Value], after: u64, target: u64) -> Value {
    json!({"network":serde_json::from_str::<Value>(&network_json()).unwrap(),
        "anchor":{"slot":target,"blockhash":hash_at(target),"block_height":target},
        "after_slot":after,"next_slot":blocks.last().unwrap()["slot"],"complete":blocks.last().unwrap()["slot"]==target,
        "blocks":blocks.iter().map(|b|json!({"slot":b["slot"],"block":{"parentSlot":b["parent_slot"],
            "blockhash":b["blockhash"],"previousBlockhash":b["previous_blockhash"],
            "blockHeight":b["block_height"],"transactions":b["transactions"]}})).collect::<Vec<_>>()})
}

#[test]
fn signed_funding_private_send_restart_and_recipient_notes_use_original_packet() {
    let f = fixture();
    let mut recovered = restored(&f.alice);
    recovered
        .validate_pending_checkpoint(&f.pending, &f.checkpoint)
        .unwrap();
    assert!(recovered.pending_outcome(&f.pending).is_err());
    let packet: Value =
        serde_json::from_str(&recovered.pending_packet(&f.pending).unwrap()).unwrap();
    assert_eq!(packet["id"], f.id);
    assert_eq!(
        STANDARD
            .decode(packet["packet"]["payload"].as_str().unwrap())
            .unwrap(),
        f.payload
    );
    let saved = sync(
        &mut recovered,
        &f.pool2,
        2,
        &f.checkpoint,
        std::slice::from_ref(&f.send),
    );
    assert_eq!(decision(&recovered, &f.pending), "accepted");
    assert_eq!(
        serde_json::from_str::<Value>(&recovered.payment_status().unwrap()).unwrap()["balance"],
        "57"
    );
    let outcome: Value =
        serde_json::from_str(&recovered.pending_outcome(&f.pending).unwrap()).unwrap();
    assert!(outcome["signature"].as_str().is_some());
    assert_eq!(outcome["slot"], 2);
    assert_ne!(saved, f.checkpoint);
    let mut bob = restored(&f.bob);
    sync(
        &mut bob,
        &f.pool2,
        2,
        &[],
        &[f.funding.clone(), f.send.clone()],
    );
    assert_eq!(
        serde_json::from_str::<Value>(&bob.payment_status().unwrap()).unwrap()["balance"],
        "40"
    );
    assert!(bob
        .validate_pending_checkpoint(&f.pending, &f.checkpoint)
        .is_err());
    // A reload discards the session; encrypted pending/checkpoint are sufficient
    // to repeat canonical reconciliation without creating a second payment.
    recovered.lock();
    assert!(recovered.payment_status().is_err());
    assert!(recovered.pending_packet(&f.pending).is_err());
    recovered.unlock(PASSWORD.to_vec()).unwrap();
    assert!(recovered.payment_status().is_err());
    sync(
        &mut recovered,
        &f.pool2,
        2,
        &f.checkpoint,
        std::slice::from_ref(&f.send),
    );
    assert_eq!(decision(&recovered, &f.pending), "accepted");
}

#[test]
fn authenticated_pending_checkpoint_tampering_and_explicit_fee_expiry_bounds_fail_closed() {
    let f = fixture();
    let mut w = funded();
    let mut corrupt = f.pending.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(w.pending_packet(&corrupt).is_err());
    let mut corrupt = f.checkpoint.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(w.checkpoint_info(&corrupt).is_err());
    assert!(w.validate_pending_checkpoint(&f.pending, &corrupt).is_err());
    // The same logical checkpoint sealed with a different nonce is not the
    // exact originally reserved ciphertext.
    let plain = w.unseal(CACHE_MAGIC, &f.checkpoint).unwrap();
    let different = w.seal(CACHE_MAGIC, &plain).unwrap();
    assert!(w.checkpoint_info(&different).is_ok());
    assert!(w
        .validate_pending_checkpoint(&f.pending, &different)
        .is_err());
    let recipient = restored(&f.bob).identity().unwrap().private_address;
    for expiry in [1, 1 + native_payments::verification::MAX_EXPIRY_WINDOW + 1] {
        assert!(w
            .build_payment(&recipient, 1, 3, &quote(), expiry, &f.checkpoint)
            .is_err());
    }
    for mutation in ["network", "fee", "payer", "transport"] {
        let mut q: Value = serde_json::from_str(&quote()).unwrap();
        match mutation {
            "network" => q["network"]["network"][0] = 8.into(),
            "fee" => q["fee"] = 4.into(),
            "payer" => {
                q["payer"] = Pubkey::new_from_array(native_accounts::pool_address())
                    .to_string()
                    .into()
            }
            _ => q["transport"] = "staged".into(),
        }
        assert!(w
            .build_payment(&recipient, 1, 3, &q.to_string(), EXPIRY, &f.checkpoint)
            .is_err());
    }
    assert!(w
        .build_payment(&recipient, 0, 3, &quote(), EXPIRY, &f.checkpoint)
        .is_err());
    assert!(w
        .build_payment(&recipient, 100, 3, &quote(), EXPIRY, &f.checkpoint)
        .is_err());
    w.lock();
    assert!(w
        .validate_pending_checkpoint(&f.pending, &f.checkpoint)
        .is_err());
}

#[test]
fn only_complete_canonical_coverage_after_expiry_can_release_an_absent_original() {
    let f = fixture();
    let empty2 = block(2, vec![]);
    let empty3 = block(3, vec![]);
    let empty4 = block(4, vec![]);
    let mut pool = PoolState::decode(&f.pool1).unwrap();
    pool.complete_slot(2).unwrap();
    pool.complete_slot(3).unwrap();
    let mut w = restored(&f.alice);
    sync(
        &mut w,
        &pool.encode(),
        EXPIRY,
        &f.checkpoint,
        &[empty2.clone(), empty3.clone()],
    );
    assert_eq!(decision(&w, &f.pending), "unknown"); // valid at exact expiry
    pool.complete_slot(4).unwrap();
    sync(
        &mut w,
        &pool.encode(),
        4,
        &f.checkpoint,
        &[empty2.clone(), empty3.clone(), empty4.clone()],
    );
    assert_eq!(decision(&w, &f.pending), "expired-absent");
    w.begin_sync(
        &pool_reply(&pool.encode(), 4),
        &header(4),
        &f.checkpoint,
        &header(1),
    )
    .unwrap();
    w.apply_history_page(&retained(&[empty2, empty3, empty4], 1, 4))
        .unwrap();
    w.finish_sync().unwrap();
    assert_eq!(decision(&w, &f.pending), "unknown"); // retained cannot prove absence
    w.begin_sync(
        &pool_reply(&f.pool2, 2),
        &header(2),
        &f.checkpoint,
        &header(1),
    )
    .unwrap();
    w.apply_history_page(&retained(std::slice::from_ref(&f.send), 1, 2))
        .unwrap();
    w.finish_sync().unwrap();
    assert_eq!(decision(&w, &f.pending), "unknown"); // nor inclusion
    assert_eq!(
        serde_json::from_str::<Value>(&w.payment_status().unwrap()).unwrap()["balance"],
        "57"
    );
}

#[test]
fn wrong_pool_headers_unsigned_or_incomplete_history_never_publish_verified_state() {
    let f = fixture();
    let mut w = restored(&f.alice);
    for mutation in ["owner", "network", "backing", "target"] {
        let mut pool: Value = serde_json::from_str(&pool_reply(&f.pool1, 1)).unwrap();
        match mutation {
            "owner" => pool["value"]["owner"] = Pubkey::new_from_array([42; 32]).to_string().into(),
            "backing" => pool["value"]["lamports"] = 0.into(),
            "target" => pool["context"]["slot"] = 2.into(),
            _ => {
                let mut state = PoolState::decode(&f.pool1).unwrap();
                state.network = [8; 32];
                pool["value"]["data"][0] = STANDARD.encode(state.encode()).into();
            }
        }
        assert!(w
            .begin_sync(&pool.to_string(), &header(1), &[], "null")
            .is_err());
        assert!(w.payment_status().is_err());
    }
    assert!(w
        .begin_sync(
            &pool_reply(&f.pool2, 2),
            &header(2),
            &f.checkpoint,
            &header(9)
        )
        .is_err());
    for mutation in ["unsigned", "parent", "previous", "missing"] {
        w.begin_sync(&pool_reply(&f.pool1, 1), &header(1), &[], "null")
            .unwrap();
        let mut b = f.funding.clone();
        match mutation {
            "unsigned" => {
                let raw = STANDARD
                    .decode(b["transactions"][0]["transaction"][0].as_str().unwrap())
                    .unwrap();
                let mut tx: VersionedTransaction = bincode::deserialize(&raw).unwrap();
                tx.signatures[0] = Default::default();
                b["transactions"][0] = transaction(&tx);
            }
            "parent" => b["parent_slot"] = 9.into(),
            "previous" => {
                // With a saved checkpoint the previous hash is authenticated.
                w.begin_sync(
                    &pool_reply(&f.pool2, 2),
                    &header(2),
                    &f.checkpoint,
                    &header(1),
                )
                .unwrap();
                b = f.send.clone();
                b["previous_blockhash"] = hash_at(9).into();
            }
            _ => b["transactions"] = json!([]),
        }
        let applied = w.apply_canonical_blocks(&json!([b]).to_string());
        if mutation == "missing" {
            applied.unwrap();
            assert!(w.finish_sync().is_err());
        } else {
            assert!(applied.is_err());
        }
        assert!(w.payment_status().is_err());
    }
    w.begin_sync(&pool_reply(&f.pool1, 1), &header(9), &[], "null")
        .unwrap();
    w.apply_canonical_blocks(&json!([f.funding.clone()]).to_string())
        .unwrap();
    assert!(w.finish_sync().is_err());
    assert!(w.payment_status().is_err());
    // Message mutation is refused independently of a structurally valid signature.
    let raw = STANDARD
        .decode(
            f.send["transactions"][0]["transaction"][0]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let mut tx: VersionedTransaction = bincode::deserialize(&raw).unwrap();
    match &mut tx.message {
        VersionedMessage::Legacy(m) => m.instructions[0].data[0] ^= 1,
        _ => unreachable!(),
    }
    let mutated = block(2, vec![transaction(&tx)]);
    w.begin_sync(
        &pool_reply(&f.pool2, 2),
        &header(2),
        &f.checkpoint,
        &header(1),
    )
    .unwrap();
    assert!(w
        .apply_canonical_blocks(&json!([mutated]).to_string())
        .is_err());
    assert!(w.payment_status().is_err());
}

#[test]
fn archival_anchor_and_cursor_are_pinned_before_original_payment_can_be_settled() {
    let f = fixture();
    let mut w = restored(&f.alice);
    let good = archival(std::slice::from_ref(&f.send), 1, 2);
    for mutation in [
        "anchor_hash",
        "anchor_slot",
        "anchor_height",
        "cursor",
        "next",
        "complete",
        "network",
        "missing_height",
    ] {
        w.begin_sync(
            &pool_reply(&f.pool2, 2),
            &header(2),
            &f.checkpoint,
            &header(1),
        )
        .unwrap();
        let mut page = good.clone();
        match mutation {
            "anchor_hash" => page["anchor"]["blockhash"] = hash_at(9).into(),
            "anchor_slot" => page["anchor"]["slot"] = 9.into(),
            "anchor_height" => page["anchor"]["block_height"] = 9.into(),
            "cursor" => page["after_slot"] = 0.into(),
            "next" => page["next_slot"] = 9.into(),
            "complete" => page["complete"] = false.into(),
            "network" => page["network"]["network"][0] = 8.into(),
            _ => page["blocks"][0]["block"]
                .as_object_mut()
                .unwrap()
                .remove("blockHeight")
                .map(|_| ())
                .unwrap(),
        }
        assert!(
            w.apply_archival_page(&page.to_string()).is_err(),
            "{mutation}"
        );
        assert!(w.payment_status().is_err());
        assert!(w.pending_outcome(&f.pending).is_err());
    }
    w.begin_sync(
        &pool_reply(&f.pool2, 2),
        &header(2),
        &f.checkpoint,
        &header(1),
    )
    .unwrap();
    w.apply_archival_page(&good.to_string()).unwrap();
    w.finish_sync().unwrap();
    assert_eq!(decision(&w, &f.pending), "accepted");
}

#[test]
fn exact_verified_checkpoint_reuses_replay_but_resealed_checkpoint_restores() {
    let f = fixture();
    let mut w = restored(&f.alice);
    let checkpoint = sync(&mut w, &f.pool1, 1, &[], std::slice::from_ref(&f.funding));
    let note_ptr = w.session.as_ref().unwrap().replay.state.unspent()[0] as *const _ as usize;
    w.begin_sync(
        &pool_reply(&f.pool1, 1),
        &header(1),
        &checkpoint,
        &header(1),
    )
    .unwrap();
    let s = w.session.as_ref().unwrap();
    assert_eq!(s.replay.state.unspent()[0] as *const _ as usize, note_ptr);
    assert!(!s.verified);
    assert!(s.checkpoint_pin.is_none());
    assert!(s.accepted.is_empty());
    assert!(w.payment_status().is_err());
    let checkpoint = w.finish_sync().unwrap();
    let plain = w.unseal(CACHE_MAGIC, &checkpoint).unwrap();
    let resealed = w.seal(CACHE_MAGIC, &plain).unwrap();
    assert_ne!(resealed, checkpoint);
    let note_ptr = w.session.as_ref().unwrap().replay.state.unspent()[0] as *const _ as usize;
    w.begin_sync(&pool_reply(&f.pool1, 1), &header(1), &resealed, &header(1))
        .unwrap();
    // The prior allocation remains live during restore, so this proves the
    // alternate valid ciphertext did not select the warm replay.
    assert_ne!(
        w.session.as_ref().unwrap().replay.state.unspent()[0] as *const _ as usize,
        note_ptr
    );
    w.finish_sync().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&w.payment_status().unwrap()).unwrap()["balance"],
        "100"
    );
}

#[test]
fn stale_checkpoint_failed_begin_and_lock_never_reuse_newer_verified_history() {
    let f = fixture();
    let mut w = restored(&f.alice);
    let checkpoint = sync(&mut w, &f.pool1, 1, &[], std::slice::from_ref(&f.funding));
    sync(
        &mut w,
        &f.pool2,
        2,
        &checkpoint,
        std::slice::from_ref(&f.send),
    );
    w.begin_sync(
        &pool_reply(&f.pool2, 2),
        &header(2),
        &checkpoint,
        &header(1),
    )
    .unwrap();
    assert_eq!(w.session.as_ref().unwrap().slot, 1);
    assert!(w.payment_status().is_err());
    assert!(w.finish_sync().is_err());
    assert!(w.session.is_none());
    sync(
        &mut w,
        &f.pool2,
        2,
        &checkpoint,
        std::slice::from_ref(&f.send),
    );
    assert_eq!(decision(&w, &f.pending), "accepted");
    assert!(w
        .begin_sync(
            &pool_reply(&f.pool2, 2),
            &header(2),
            &checkpoint,
            &header(2)
        )
        .is_err());
    assert!(w.session.is_none());
    assert!(w.payment_status().is_err());
    sync(
        &mut w,
        &f.pool2,
        2,
        &checkpoint,
        std::slice::from_ref(&f.send),
    );
    w.lock();
    assert!(w.session.is_none());
    w.unlock(PASSWORD.to_vec()).unwrap();
    assert!(w.session.is_none());
    sync(
        &mut w,
        &f.pool2,
        2,
        &checkpoint,
        std::slice::from_ref(&f.send),
    );
    assert_eq!(decision(&w, &f.pending), "accepted");
}
