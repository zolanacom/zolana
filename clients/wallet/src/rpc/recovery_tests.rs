//! Regression coverage for RPC replay, fees, submission and recovery.
use super::{fetch, Chain, Pending, ScanResult, ScanStats, StagingRecovery};
use crate::archive::{Archive, HistoryBlock, Writer};
use crate::cache;
use crate::cache::Checkpoint;
use crate::history::{HistoryInstruction, Replay, WalletState};
use crate::keys::{read_private, write_private_new, Network, WalletKey};
use crate::operation::WalletOperation;
use base64::Engine;
use native_payment_program::staging::{Buffer, ACCOUNT_BYTES};
use native_payment_program::{id, instructions, pool_address};
use native_payments::staging::payload_digest;
use native_payments::state::PoolState;
use native_payments::wire;
use serde_json::json;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::mock_sender::MocksMap;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::request::RpcRequest;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction as system;
use solana_transaction::Transaction;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

#[test]
fn v4_scanner_finishes_empty_blocks_for_all_views_and_keeps_profile_explicit() {
    let network = Network {
        network: [43; 32],
        genesis_hash: bs58::encode([44; 32]).into_string(),
    };
    let alice = WalletKey::generate(network.clone()).unwrap();
    let bob = WalletKey::generate(network.clone()).unwrap();
    let key = std::sync::Arc::new(orchard::circuit::VerifyingKey::build(
        native_payments::verification::bundle_version().circuit_version(),
    ));
    let pool = PoolState::new_slot_anchored(network.network, 1000)
        .unwrap()
        .with_completed_slot(0)
        .unwrap();
    let mut scan = ScanResult {
        replay: Replay::from_state(
            WalletState::with_key_for_pool(&alice, &pool, key.clone()).unwrap(),
        ),
        secondary: vec![WalletState::with_key_for_pool(&bob, &pool, key.clone()).unwrap()],
        slot: 0,
        block_hash: None,
        block_height: 0,
        accepted: BTreeSet::new(),
        canonical_from_slot: 0,
        withdrawals: BTreeMap::new(),
        finalizations: BTreeMap::new(),
        payment_digests: BTreeMap::new(),
        payment_slots: BTreeMap::new(),
        scan: ScanStats::default(),
    };
    scan.apply_block(
        HistoryBlock::from_rpc(3, serde_json::from_value(block(3, 0)).unwrap()).unwrap(),
    )
    .unwrap();
    scan.apply_retained_block(
        HistoryBlock::from_rpc(5, serde_json::from_value(block(5, 3)).unwrap()).unwrap(),
    )
    .unwrap();
    let expected = pool
        .with_completed_slot(3)
        .unwrap()
        .with_completed_slot(5)
        .unwrap();
    scan.replay.state.reconcile(&expected).unwrap();
    scan.secondary[0].reconcile(&expected).unwrap();
    assert!(scan.accepted.is_empty());
    let restored = Replay::restore_with_key(&alice, scan.replay.snapshot(), Some(key)).unwrap();
    assert_eq!(restored.state.pool.encode(), expected.encode());
    assert!(restored.state.spendable_anchor().is_ok());

    let chain = Chain {
        rpc: RpcClient::new_mock("succeeds"),
        network,
        sponsor_budget: None,
        user_fees: None,
        history_batches: false,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
    };
    let legacy = PoolState::new([43; 32], 1000).unwrap();
    chain.check_pool_format(&legacy).unwrap();
    assert!(chain.check_pool_format(&expected).is_err());
    let chain = chain.with_pool_format("NPOOL004").unwrap();
    chain.check_pool_format(&expected).unwrap();
    assert!(chain.check_pool_format(&legacy).is_err());
    assert!(chain.with_pool_format("NPOOL002").is_err());
}

#[test]
fn shielded_quote_cap_and_untrusted_receipts_cannot_clear_or_replace_intent() {
    use crate::{
        payments::{Payment, PaymentProver},
        shielded::{self, Packet},
    };
    let network = Network {
        network: [3; 32],
        genesis_hash: bs58::encode([4; 32]).into_string(),
    };
    let wallet = WalletKey::generate(network.clone()).unwrap();
    let relay = Keypair::new();
    let make_chain = |mocks| Chain {
        rpc: RpcClient::new_mock_with_mocks_map("fails", mocks),
        network: network.clone(),
        sponsor_budget: None,
        user_fees: None,
        history_batches: false,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
    };
    let quote_method = RpcRequest::Custom {
        method: "getShieldedFeeQuote",
    };
    for (fee, quoted_network) in [
        (0, network.clone()),
        (31, network.clone()),
        (
            30,
            Network {
                network: [5; 32],
                ..network.clone()
            },
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let chain = make_chain(MocksMap::from_iter([(
            quote_method,
            json!({"format":"native-shielded-fee-quote-v1",
                "network":quoted_network,"payer":relay.pubkey().to_string(),"fee":fee}),
        )]));
        assert!(
            shielded::send(&chain, &wallet, &operation, 100, &wallet.address_text(), 30).is_err()
        );
        assert!(
            !operation.shielded.exists()
                && !operation.pending.exists()
                && !operation.staging.exists()
        );
    }
    let prover = PaymentProver::new();
    let mut state = WalletState::with_key(&wallet, 1000, prover.verifying_key()).unwrap();
    let deposit = prover
        .build(
            &wallet,
            &state,
            relay.pubkey().to_bytes(),
            100,
            Payment::Deposit {
                amount: 1000,
                recipient: &wallet.address_text(),
            },
        )
        .unwrap();
    let decoded = wire::decode(network.network, &deposit).unwrap();
    state.accept(&decoded.bundle, &decoded.context, 1).unwrap();
    let bytes = prover
        .build(
            &wallet,
            &state,
            relay.pubkey().to_bytes(),
            100,
            Payment::ShieldedSend {
                amount: 100,
                recipient: &wallet.address_text(),
                fee: 30,
            },
        )
        .unwrap();
    let packet = Packet {
        network: network.clone(),
        payload: base64::engine::general_purpose::STANDARD.encode(bytes),
    };
    let id = packet.id().unwrap();
    for (ack, status) in [
        (json!({"id":"substituted"}), json!({})),
        (
            json!({"id":id}),
            json!({"id":"substituted","state":"accepted"}),
        ),
        (
            json!({"id":id}),
            json!({"id":id,"state":"accepted","signature":"invented"}),
        ),
        (json!({"id":id}), json!({"id":id,"state":"aborted"})),
    ] {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let raw = serde_json::to_vec(&packet).unwrap();
        write_private_new(&operation.shielded, &raw).unwrap();
        let chain = make_chain(MocksMap::from_iter([
            (
                RpcRequest::Custom {
                    method: "submitShieldedPayment",
                },
                ack,
            ),
            (
                RpcRequest::Custom {
                    method: "getShieldedPaymentStatus",
                },
                status,
            ),
        ]));
        assert!(shielded::recover(&chain, &wallet, &operation, false).is_err());
        assert_eq!(
            read_private(&operation.shielded, 20000).unwrap().as_slice(),
            raw.as_slice()
        );
        assert!(operation.ensure_resolved().is_err());
        assert!(!operation.pending.exists() && !operation.staging.exists());
    }
}

#[test]
fn confirmed_failed_burst_repairs_once_with_a_new_identity_before_finalization() {
    let network = Network {
        network: [3; 32],
        genesis_hash: bs58::encode([4; 32]).into_string(),
    };
    let wallet = WalletKey::generate(network.clone()).unwrap();
    let sponsor = Keypair::new();
    let prover = crate::payments::PaymentProver::new();
    let state = WalletState::with_key(&wallet, 1000, prover.verifying_key()).unwrap();
    let bytes = prover
        .build(
            &wallet,
            &state,
            sponsor.pubkey().to_bytes(),
            100,
            crate::payments::Payment::Deposit {
                amount: 1,
                recipient: &wallet.address_text(),
            },
        )
        .unwrap();
    let count = crate::upload::remaining(Pubkey::new_unique(), sponsor.pubkey(), &bytes).len();
    let mut prefix = Buffer::initialize(
        &vec![0; ACCOUNT_BYTES],
        sponsor.pubkey().to_bytes(),
        bytes.len() as u32,
        payload_digest(&bytes),
        100,
    )
    .unwrap();
    prefix
        .write(0, &bytes[..native_payments::staging::MAX_CHUNK_BYTES])
        .unwrap();
    let account = |data: Vec<u8>| {
        json!({"context":{"slot":10},"value":{"lamports":1000,"owner":id().to_string(),
            "executable":false,"rentEpoch":0,"data":[bs58::encode(data).into_string(),"base58"]}})
    };
    for new_hash in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let mut mocks = MocksMap::from_iter([
            (RpcRequest::GetAccountInfo, account(state.pool.encode())),
            (RpcRequest::GetAccountInfo, account(prefix.bytes().to_vec())),
            (
                RpcRequest::GetAccountInfo,
                json!({"context":{"slot":10},"value":null}),
            ),
            (
                RpcRequest::GetSignatureStatuses,
                json!({"context":{"slot":10},"value":[{"slot":10,"confirmations":null,
                    "err":null,"status":{"Ok":null},"confirmationStatus":"finalized"}]}),
            ),
            (
                RpcRequest::GetSignatureStatuses,
                json!({"context":{"slot":10},"value":vec![json!({"slot":10,"confirmations":null,
                    "err":{"InstructionError":[0,"InvalidInstructionData"]},"status":{"Err":{"InstructionError":[0,"InvalidInstructionData"]}},
                    "confirmationStatus":"finalized"});count]}),
            ),
        ]);
        for byte in [1u8, if new_hash { 2 } else { 1 }, 3] {
            mocks.insert(
                RpcRequest::GetLatestBlockhash,
                json!({"context":{"slot":10},"value":{
                    "blockhash":bs58::encode([byte;32]).into_string(),"lastValidBlockHeight":150}}),
            );
        }
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
            network: network.clone(),
            sponsor_budget: None,
            user_fees: None,
            history_batches: false,
            retained_history_v2: false,
            standard_reads: None,
            verification_key: None,
            pool_format: "NPOOL003",
        };
        let result = chain.submit(&sponsor, &bytes, &operation);
        if new_hash {
            let receipt = result.unwrap();
            assert_eq!(receipt.upload_failed_transactions, count);
            assert_eq!(receipt.upload_repair_transactions, count);
            assert_eq!(receipt.upload_transactions, 1 + 2 * count);
            assert!(receipt.staging_rent_reclaimed);
            assert!(!operation.pending.exists() && !operation.staging.exists());
        } else {
            assert!(result
                .err()
                .unwrap()
                .to_string()
                .contains("fresh blockhash"));
            assert!(operation.staging.exists() && !operation.pending.exists());
        }
    }
}

#[test]
fn failed_initialization_or_invalid_burst_observations_never_record_a_payment() {
    let network = Network {
        network: [3; 32],
        genesis_hash: bs58::encode([4; 32]).into_string(),
    };
    let wallet = WalletKey::generate(network.clone()).unwrap();
    let sponsor = Keypair::new();
    let prover = crate::payments::PaymentProver::new();
    let state = WalletState::with_key(&wallet, 1000, prover.verifying_key()).unwrap();
    let bytes = prover
        .build(
            &wallet,
            &state,
            sponsor.pubkey().to_bytes(),
            100,
            crate::payments::Payment::Deposit {
                amount: 1,
                recipient: &wallet.address_text(),
            },
        )
        .unwrap();
    let count = crate::upload::remaining(Pubkey::new_unique(), sponsor.pubkey(), &bytes).len();
    let failed = json!({"slot":2,"confirmations":null,"err":{"InstructionError":[0,"InvalidAccountData"]},
            "status":{"Err":{"InstructionError":[0,"InvalidAccountData"]}},"confirmationStatus":"finalized"});
    let succeeded = json!({"slot":1,"confirmations":1,"err":null,"status":{"Ok":null},"confirmationStatus":"confirmed"});
    for mode in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let mut mocks = MocksMap::from_iter([(
            RpcRequest::GetAccountInfo,
            json!({"context":{"slot":1},"value":{"lamports":1000,"owner":id().to_string(),
                    "executable":false,"rentEpoch":0,"data":[bs58::encode(state.pool.encode()).into_string(),"base58"]}}),
        )]);
        mocks.insert(RpcRequest::GetSignatureStatuses, json!({"context":{"slot":2},"value":[if mode == 0 {failed.clone()} else {succeeded.clone()}]}));
        if mode != 0 {
            mocks.insert(RpcRequest::GetSignatureStatuses, json!({"context":{"slot":2},"value": if mode == 1 {vec![failed.clone();count]} else {vec![]}}));
            // Even confirmed statuses cannot authorize a fabricated prefix.
            mocks.insert(RpcRequest::GetAccountInfo, json!({"context":{"slot":2},"value":{"lamports":1000,"owner":id().to_string(),
                    "executable":false,"rentEpoch":0,"data":[bs58::encode(vec![0; ACCOUNT_BYTES]).into_string(),"base58"]}}));
        }
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
            network: network.clone(),
            sponsor_budget: None,
            user_fees: None,
            history_batches: false,
            retained_history_v2: false,
            standard_reads: None,
            verification_key: None,
            pool_format: "NPOOL003",
        };
        assert!(chain.submit(&sponsor, &bytes, &operation).is_err());
        assert!(operation.staging.exists());
        assert!(!operation.pending.exists());
        let saved: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
        assert_eq!(saved.payload_digest, payload_digest(&bytes));
        assert_eq!(saved.sponsor, sponsor.pubkey().to_string());
        // Arbitrary value-changing instructions cannot use the no-preflight path.
        let forbidden = Transaction::new_with_payer(
            &[instructions::close(Pubkey::new_unique(), sponsor.pubkey())],
            Some(&sponsor.pubkey()),
        );
        assert!(chain.send_uploads(&[forbidden]).is_err());
    }
}

#[test]
fn sponsor_checks_rpc_fee_plus_native_debit_before_broadcast() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("policy");
    let payer = Keypair::new();
    let network = Network {
        network: [3; 32],
        genesis_hash: bs58::encode([4; 32]).into_string(),
    };
    crate::sponsor::Policy {
        format: "native-sponsor-policy-v1".into(),
        network: network.clone(),
        sponsor: payer.pubkey().to_string(),
        operation_allowance: 10,
        lifetime_allowance: 10,
        max_deposit: 100,
        max_send: 100,
        max_withdraw: None,
        max_requests_per_wallet: 1,
    }
    .create(&path)
    .unwrap();
    let budget = crate::sponsor::Budget::reserve(
        &path,
        &network,
        &payer.pubkey(),
        "wallet",
        "deposit",
        1,
        "fee-test-request-0001",
    )
    .unwrap();
    let chain = Chain {
        rpc: RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter(std::iter::repeat_n(
                (
                    RpcRequest::GetFeeForMessage,
                    json!({"context":{"slot":1},"value":7}),
                ),
                3,
            )),
        ),
        network,
        sponsor_budget: Some(budget),
        user_fees: None,
        history_batches: false,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
    };
    let tx = Transaction::new_signed_with_payer(
        &[system::transfer(&payer.pubkey(), &Pubkey::new_unique(), 1)],
        Some(&payer.pubkey()),
        &[&payer],
        Default::default(),
    );
    assert!(chain.charge_sponsor(&tx, 4).is_err());
    chain.charge_sponsor(&tx, 3).unwrap();
    assert!(chain.charge_sponsor(&tx, 0).is_err());
    let ledger: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("policy.reservations.json")).unwrap())
            .unwrap();
    assert_eq!(ledger["requests"][0]["charged"], 10);
}

fn cached_fixture(
    target: u64,
    blocks: Vec<serde_json::Value>,
    slots: Vec<u64>,
) -> (WalletKey, Checkpoint, Chain) {
    let network = Network {
        network: [9; 32],
        genesis_hash: bs58::encode([8; 32]).into_string(),
    };
    let wallet = WalletKey::generate(network.clone()).unwrap();
    let replay = Replay::new(&wallet, 1000).unwrap();
    let pool = replay.state.pool.encode();
    let checkpoint = Checkpoint {
        network: network.clone(),
        address: wallet.address_text(),
        slot: 4,
        block_hash: Some(bs58::encode([4; 32]).into_string()),
        block_height: 4,
        accepted: BTreeSet::new(),
        canonical_from_slot: 0,
        replay: replay.snapshot(),
    };
    let mut mocks = MocksMap::from_iter([
        (
            RpcRequest::GetAccountInfo,
            json!({"context":{"slot":target},"value":{
                "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                "data":[bs58::encode(pool).into_string(),"base58"]}}),
        ),
        (RpcRequest::GetBlocks, json!(slots)),
    ]);
    for block in blocks {
        mocks.insert(RpcRequest::GetBlock, block);
    }
    let chain = Chain {
        rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
        sponsor_budget: None,
        user_fees: None,
        history_batches: false,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
        network,
    };
    (wallet, checkpoint, chain)
}

fn block(slot: u64, parent: u64) -> serde_json::Value {
    json!({"blockhash":bs58::encode([slot as u8;32]).into_string(),
            "previousBlockhash":bs58::encode([parent as u8;32]).into_string(),
            "parentSlot":parent,"blockHeight":slot,"blockTime":null,"transactions":[],"rewards":[]})
}

#[test]
fn inline_history_authenticates_canonical_receipts_fanout_and_restart_replay() {
    use crate::payments::{Payment, PaymentProver};

    // Synthetic RPC blocks exercise scanner trust boundaries, not consensus
    // finality or the currently unchanged Agave network packet size limit.
    let network = Network {
        network: [9; 32],
        genesis_hash: bs58::encode([8; 32]).into_string(),
    };
    let alice = WalletKey::generate(network.clone()).unwrap();
    let bob = WalletKey::generate(network.clone()).unwrap();
    let relay = Keypair::new();
    let prover = PaymentProver::new();
    let key = prover.verifying_key();
    let mut sender = WalletState::with_key(&alice, 1000, key.clone()).unwrap();
    let mut recipient = WalletState::with_key(&bob, 1000, key.clone()).unwrap();
    let funding = prover
        .build(
            &alice,
            &sender,
            relay.pubkey().to_bytes(),
            100,
            Payment::Deposit {
                amount: 1000,
                recipient: &alice.address_text(),
            },
        )
        .unwrap();
    let deposit = wire::decode(network.network, &funding).unwrap();
    for state in [&mut sender, &mut recipient] {
        state.accept(&deposit.bundle, &deposit.context, 1).unwrap();
    }
    let payload = prover
        .build(
            &alice,
            &sender,
            relay.pubkey().to_bytes(),
            100,
            Payment::ShieldedSend {
                amount: 100,
                recipient: &bob.address_text(),
                fee: 30,
            },
        )
        .unwrap();
    let inline = instructions::inline(network.network, &payload).unwrap();
    let tx = Transaction::new_signed_with_payer(
        std::slice::from_ref(&inline),
        Some(&relay.pubkey()),
        &[&relay],
        Default::default(),
    );
    let signature = tx.signatures[0].to_string();
    let expected_digest = payload_digest(&payload);
    let sender_snapshot = serde_json::to_value(Replay::from_state(sender).snapshot()).unwrap();
    let recipient_snapshot =
        serde_json::to_value(Replay::from_state(recipient).snapshot()).unwrap();
    let make_scan = || ScanResult {
        replay: Replay::restore_with_key(
            &alice,
            serde_json::from_value(sender_snapshot.clone()).unwrap(),
            Some(key.clone()),
        )
        .unwrap(),
        secondary: vec![
            Replay::restore_with_key(
                &bob,
                serde_json::from_value(recipient_snapshot.clone()).unwrap(),
                Some(key.clone()),
            )
            .unwrap()
            .state,
        ],
        slot: 1,
        block_hash: Some(bs58::encode([1; 32]).into_string()),
        block_height: 1,
        accepted: BTreeSet::new(),
        canonical_from_slot: 0,
        withdrawals: BTreeMap::new(),
        finalizations: BTreeMap::new(),
        payment_digests: BTreeMap::new(),
        payment_slots: BTreeMap::new(),
        scan: ScanStats::default(),
    };
    let source_block = |transaction: &Transaction, failed: bool| {
        let err = if failed {
            json!({"InstructionError":[0,{"Custom":1}]})
        } else {
            serde_json::Value::Null
        };
        let status = if failed {
            json!({"Err":err})
        } else {
            json!({"Ok":null})
        };
        let mut rpc_block = block(2, 1);
        rpc_block["transactions"] = json!([{
            "transaction":[base64::engine::general_purpose::STANDARD.encode(
                bincode::serialize(transaction).unwrap()),"base64"],
            "meta":{"err":err,"status":status,"fee":5000,
                "preBalances":[],"postBalances":[]}
        }]);
        HistoryBlock::from_rpc(2, serde_json::from_value(rpc_block).unwrap()).unwrap()
    };

    let mut canonical = make_scan();
    let retained_block = canonical.apply_block(source_block(&tx, false)).unwrap();
    assert_eq!(canonical.replay.state.balance().unwrap(), 870);
    assert_eq!(canonical.secondary[0].balance().unwrap(), 100);
    canonical.secondary[0]
        .reconcile(&canonical.replay.state.pool)
        .unwrap();
    assert_eq!(canonical.accepted, BTreeSet::from([signature.clone()]));
    assert_eq!(
        canonical.payment_digests,
        BTreeMap::from([(signature.clone(), expected_digest)])
    );
    assert_eq!(
        canonical.payment_slots,
        BTreeMap::from([(signature.clone(), 2)])
    );
    assert_eq!(canonical.scan.payments_verified, 1);
    assert!(canonical.finalizations.is_empty() && canonical.withdrawals.is_empty());
    assert_eq!(retained_block.transactions.len(), 1);

    let snapshot = canonical.replay.snapshot();
    let mut restored = Replay::restore_with_key(&alice, snapshot, Some(key.clone())).unwrap();
    assert_eq!(restored.state.balance().unwrap(), 870);
    let before = restored.state.pool.encode();
    let instruction = HistoryInstruction {
        accounts: inline
            .accounts
            .iter()
            .map(|meta| (meta.pubkey, meta.is_signer))
            .collect(),
        data: inline.data.clone(),
    };
    assert!(restored.apply_verified(&instruction, 3).is_err());
    assert_eq!(restored.state.pool.encode(), before);
    assert_eq!(restored.state.balance().unwrap(), 870);
    let expected_cached_pool = canonical.replay.state.pool.encode();
    let expected_cached_lamports = 1000 + canonical.replay.state.pool.backing;
    for synced in canonical.finish() {
        assert_eq!(
            synced.payment_digests.get(&signature),
            Some(&expected_digest)
        );
        assert!(synced.accepted_finalizations.contains(&signature));
    }

    let mut retained = make_scan();
    retained.apply_retained_block(retained_block).unwrap();
    assert_eq!(retained.replay.state.balance().unwrap(), 870);
    assert_eq!(retained.secondary[0].balance().unwrap(), 100);
    assert_eq!(retained.scan.payments_verified, 1);
    assert_eq!(retained.canonical_from_slot, 3);
    assert!(retained.accepted.is_empty() && retained.payment_digests.is_empty());
    assert!(retained.payment_slots.is_empty());

    // Resume a real encrypted checkpoint before this same private send.
    // A stale compact suffix must apply the proof exactly once, preserve
    // its spent markers across another cache write/read, and never turn
    // retained metadata into a canonical transaction receipt.
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let checkpoint = Checkpoint {
        network: network.clone(),
        address: alice.address_text(),
        slot: 1,
        block_hash: Some(block(1, 0)["blockhash"].as_str().unwrap().into()),
        block_height: 1,
        accepted: BTreeSet::new(),
        canonical_from_slot: 0,
        replay: serde_json::from_value(sender_snapshot.clone()).unwrap(),
    };
    cache::write(&operation.scan_cache, &alice, &checkpoint).unwrap();
    let target = 1 + fetch::WINDOW as u64;
    let tail =
        HistoryBlock::from_rpc(target, serde_json::from_value(block(target, 2)).unwrap()).unwrap();
    let chain = Chain {
        rpc: RpcClient::new_mock_with_mocks_map(
            "fails",
            MocksMap::from_iter([
                (
                    RpcRequest::GetAccountInfo,
                    json!({"context":{"slot":target},"value":{"lamports":expected_cached_lamports,
                        "owner":id().to_string(),"executable":false,"rentEpoch":0,
                        "data":[bs58::encode(expected_cached_pool).into_string(),"base58"]}}),
                ),
                (RpcRequest::GetBlock, block(1, 0)),
                (
                    RpcRequest::Custom {
                        method: "getWalletRetainedHistoryV2",
                    },
                    json!({"network":network,"checkpoint":{"segments":1,"sha256":"a".repeat(64)},
                        "retained_tip":target,"after_slot":1,"through_slot":target,"next_slot":target,
                        "complete":true,"blocks":[source_block(&tx,false),tail]}),
                ),
                (RpcRequest::GetBlock, block(target, 2)),
            ]),
        ),
        network: network.clone(),
        sponsor_budget: None,
        user_fees: None,
        history_batches: true,
        retained_history_v2: true,
        standard_reads: None,
        verification_key: Some(key.clone()),
        pool_format: "NPOOL003",
    };
    let synced = chain.sync_cached(&alice, &operation).unwrap();
    assert_eq!(synced.state.balance().unwrap(), 870);
    assert!(synced.scan.cache_used && synced.scan.cache_saved);
    assert_eq!(synced.scan.retained_rpc_requests, 1);
    assert_eq!(synced.scan.history_blocks_read, 2);
    assert_eq!(synced.scan.blocks_fetched, 0);
    assert_eq!(synced.scan.payments_verified, 1);
    assert_eq!(synced.canonical_from_slot, target + 1);
    assert!(synced.accepted_finalizations.is_empty() && synced.payment_digests.is_empty());
    let saved = cache::read(&operation.scan_cache, &alice).unwrap();
    assert_eq!(saved.slot, target);
    assert_eq!(saved.canonical_from_slot, target + 1);
    let mut resumed = Replay::restore_with_key(&alice, saved.replay, Some(key.clone())).unwrap();
    assert_eq!(resumed.state.balance().unwrap(), 870);
    assert!(resumed.apply_verified(&instruction, target + 1).is_err());
    assert_eq!(resumed.state.balance().unwrap(), 870);

    let mut failed = make_scan();
    let before = failed.replay.state.pool.encode();
    failed.apply_block(source_block(&tx, true)).unwrap();
    assert_eq!(failed.replay.state.pool.encode(), before);
    assert_eq!(failed.replay.state.balance().unwrap(), 1000);
    assert_eq!(failed.secondary[0].balance().unwrap(), 0);
    assert_eq!(failed.scan.payments_verified, 0);
    assert!(failed.accepted.is_empty() && failed.payment_digests.is_empty());

    let mut forged = tx;
    forged.signatures[0] = Signature::from([12; 64]);
    for failed_status in [false, true] {
        let mut result = make_scan();
        let before = result.replay.state.pool.encode();
        assert!(result
            .apply_block(source_block(&forged, failed_status))
            .is_err());
        assert_eq!(result.replay.state.pool.encode(), before);
        assert_eq!(result.replay.state.balance().unwrap(), 1000);
        assert_eq!(result.secondary[0].balance().unwrap(), 0);
        assert_eq!(result.slot, 1);
        assert!(result.accepted.is_empty() && result.payment_digests.is_empty());
    }
}

#[test]
fn history_batches_require_every_requested_block_in_order_and_full_continuity() {
    for mode in 0..6 {
        let (wallet, _, mut chain) = cached_fixture(2, vec![], vec![1, 2]);
        chain.history_batches = true;
        let mut first = block(1, 0);
        if mode == 4 {
            first.as_object_mut().unwrap().remove("transactions");
        }
        let mut response = vec![
            json!({"slot":1,"block":first}),
            json!({"slot":2,"block":block(2, if mode == 3 { 0 } else { 1 })}),
        ];
        if mode == 1 {
            response.pop();
        }
        if mode == 2 {
            response.reverse();
        }
        if mode == 5 {
            response[1]["slot"] = json!(3);
        }
        let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
        chain.rpc = RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter([
                (
                    RpcRequest::GetAccountInfo,
                    json!({"context":{"slot":2},"value":{
                    "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                    "data":[bs58::encode(pool).into_string(),"base58"]}}),
                ),
                (RpcRequest::GetBlocks, json!([1, 2])),
                (
                    RpcRequest::Custom {
                        method: "getWalletHistoryBlocks",
                    },
                    json!(response),
                ),
            ]),
        );
        let result = chain.scan(&[&wallet], None);
        if mode == 0 {
            let result = result.unwrap();
            assert_eq!(result.slot, 2);
            assert_eq!(result.scan.blocks_fetched, 2);
            assert_eq!(result.scan.block_rpc_requests, 1);
        } else {
            assert!(result.is_err(), "invalid batch mode {mode} accepted");
        }
    }
}

#[test]
fn remote_pages_pin_identity_cursor_continuity_and_live_header() {
    for (compact_v2, mode) in [false, true]
        .into_iter()
        .flat_map(|compact| (0..12).map(move |mode| (compact, mode)))
    {
        let (wallet, _, mut chain) = cached_fixture(2, vec![], vec![]);
        chain.history_batches = true;
        chain.retained_history_v2 = compact_v2;
        let method = if compact_v2 {
            "getWalletRetainedHistoryV2"
        } else {
            "getWalletRetainedHistory"
        };
        let token = json!({"segments":1,"sha256":"a".repeat(64)});
        let compact = |slot, parent| {
            serde_json::to_value(
                HistoryBlock::from_rpc(slot, serde_json::from_value(block(slot, parent)).unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        let page = |after, slot, complete| {
            json!({"network":wallet.network,"checkpoint":token,"retained_tip":2,
                "after_slot":after,"through_slot":2,"next_slot":slot,"complete":complete,"blocks":[compact(slot,after)]})
        };
        let mut first = page(0, 1, false);
        let mut second = page(1, 2, true);
        match mode {
            1 => second["checkpoint"]["sha256"] = json!("b".repeat(64)),
            2 => first["network"]["network"][0] = json!(99),
            3 => first["blocks"] = json!([]),
            4 => second["blocks"][0]["parent_slot"] = json!(0),
            5 => first["next_slot"] = json!(2),
            6 => first["complete"] = json!(true),
            7 => second = serde_json::Value::Null,
            8 => first["blocks"][0]["slot"] = json!(3),
            9 => first["extra"] = json!("denied"),
            // Join the bounded second read when first-page replay fails.
            11 => first["blocks"][0]["parent_slot"] = json!(999),
            _ => (),
        }
        let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
        chain.rpc = RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter([
                (
                    RpcRequest::GetAccountInfo,
                    json!({"context":{"slot":2},"value":{
                    "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                    "data":[bs58::encode(pool).into_string(),"base58"]}}),
                ),
                (RpcRequest::Custom { method }, first),
                (RpcRequest::Custom { method }, second),
                (
                    RpcRequest::GetBlock,
                    block(if mode == 10 { 3 } else { 2 }, 1),
                ),
            ]),
        );
        let scanned = chain.scan(&[&wallet], None);
        if mode == 0 {
            let scanned = scanned.unwrap();
            assert_eq!(scanned.slot, 2);
            assert_eq!(scanned.canonical_from_slot, 3);
            assert_eq!(scanned.scan.history_blocks_read, 2);
            assert_eq!(scanned.scan.retained_rpc_requests, 2);
            assert!(scanned.accepted.is_empty());
        } else {
            assert!(
                scanned.is_err(),
                "invalid retained mode {mode}; compact_v2={compact_v2}"
            );
        }
    }
}

#[test]
fn compact_history_opt_in_requires_invited_https_connection() {
    let make = |url, invited| Chain {
        rpc: RpcClient::new(url),
        network: Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        },
        sponsor_budget: None,
        user_fees: None,
        history_batches: invited,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
    };
    assert!(
        !make("https://rpc.example.invalid", true)
            .with_retained_history_format(None)
            .unwrap()
            .retained_history_v2
    );
    assert!(
        make("https://rpc.example.invalid", true)
            .with_retained_history_format(Some("compact-v2"))
            .unwrap()
            .retained_history_v2
    );
    assert!(make("https://rpc.example.invalid", false)
        .with_retained_history_format(Some("compact-v2"))
        .is_err());
    assert!(make("http://127.0.0.1:18899", true)
        .with_retained_history_format(Some("compact-v2"))
        .is_err());
    assert!(make("https://rpc.example.invalid", true)
        .with_retained_history_format(Some("automatic"))
        .is_err());
}

#[test]
fn stale_compact_cached_suffix_pins_pages_and_both_finalized_headers() {
    let network = Network {
        network: [9; 32],
        genesis_hash: bs58::encode([8; 32]).into_string(),
    };
    let wallet = WalletKey::generate(network.clone()).unwrap();
    let key = std::sync::Arc::new(orchard::circuit::VerifyingKey::build(
        native_payments::verification::bundle_version().circuit_version(),
    ));
    let pool = PoolState::new_slot_anchored(network.network, 1000).unwrap();
    let mut prefix =
        Replay::from_state(WalletState::with_key_for_pool(&wallet, &pool, key.clone()).unwrap());
    prefix.finish_slot(4).unwrap();
    let snapshot = serde_json::to_value(prefix.snapshot()).unwrap();
    let target = 4 + fetch::WINDOW as u64;
    let middle = 4 + fetch::PAGE as u64;
    let expected = prefix
        .state
        .pool
        .with_completed_slot(middle)
        .unwrap()
        .with_completed_slot(target)
        .unwrap();
    let page = |after, next, complete| {
        json!({"network":network,
            "checkpoint":{"segments":2,"sha256":"a".repeat(64)},"retained_tip":target,
            "after_slot":after,"through_slot":target,"next_slot":next,"complete":complete,
            "blocks":[HistoryBlock::from_rpc(next,serde_json::from_value(block(next,after)).unwrap()).unwrap()]})
    };
    for mode in 0..5 {
        let checkpoint = Checkpoint {
            network: network.clone(),
            address: wallet.address_text(),
            slot: 4,
            block_hash: Some(block(4, 0)["blockhash"].as_str().unwrap().into()),
            block_height: 4,
            accepted: BTreeSet::new(),
            canonical_from_slot: 0,
            replay: serde_json::from_value(snapshot.clone()).unwrap(),
        };
        let mut first = page(4, middle, false);
        let mut second = page(middle, target, true);
        if mode == 1 {
            second["checkpoint"]["sha256"] = json!("b".repeat(64));
        }
        if mode == 2 {
            first["blocks"][0]["parent_slot"] = json!(0);
        }
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map(
                "fails",
                MocksMap::from_iter([
                    (
                        RpcRequest::GetAccountInfo,
                        json!({"context":{"slot":target},"value":{
                        "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                        "data":[bs58::encode(expected.encode()).into_string(),"base58"]}}),
                    ),
                    (
                        RpcRequest::GetBlock,
                        block(if mode == 4 { 5 } else { 4 }, 0),
                    ),
                    (
                        RpcRequest::Custom {
                            method: "getWalletRetainedHistoryV2",
                        },
                        first,
                    ),
                    (
                        RpcRequest::Custom {
                            method: "getWalletRetainedHistoryV2",
                        },
                        second,
                    ),
                    (
                        RpcRequest::GetBlock,
                        block(if mode == 3 { target + 1 } else { target }, middle),
                    ),
                ]),
            ),
            network: network.clone(),
            sponsor_budget: None,
            user_fees: None,
            history_batches: true,
            retained_history_v2: true,
            standard_reads: None,
            verification_key: Some(key.clone()),
            pool_format: "NPOOL004",
        };
        let result = chain.scan(&[&wallet], Some(checkpoint));
        if mode == 0 {
            let result = result.unwrap();
            assert!(result.scan.cache_used);
            assert_eq!(result.scan.retained_rpc_requests, 2);
            assert_eq!(result.scan.history_blocks_read, 2);
            assert_eq!(result.scan.blocks_fetched, 0);
            assert_eq!(result.slot, target);
            assert_eq!(result.block_height, target);
            assert_eq!(result.canonical_from_slot, target + 1);
            assert!(result.accepted.is_empty() && result.payment_digests.is_empty());
            result.replay.state.reconcile(&expected).unwrap();
        } else {
            assert!(result.is_err(), "stale cached retained mode {mode}");
        }
    }
}

#[test]
fn cached_retained_attempt_keeps_recent_legacy_and_canonical_recovery_paths() {
    let network = Network {
        network: [9; 32],
        genesis_hash: bs58::encode([8; 32]).into_string(),
    };
    let wallet = WalletKey::generate(network.clone()).unwrap();
    let key = std::sync::Arc::new(orchard::circuit::VerifyingKey::build(
        native_payments::verification::bundle_version().circuit_version(),
    ));
    let pool = PoolState::new_slot_anchored(network.network, 1000).unwrap();
    let mut prefix =
        Replay::from_state(WalletState::with_key_for_pool(&wallet, &pool, key.clone()).unwrap());
    prefix.finish_slot(4).unwrap();
    let snapshot = serde_json::to_value(prefix.snapshot()).unwrap();
    // No retained response is supplied for the first three cases: any
    // accidental new retained request fails the scan. The last case probes
    // an archive older than the cache, then verifies the canonical tail.
    for (gap, compact, allow_retained, old_store) in [
        (fetch::WINDOW as u64 - 1, true, true, false),
        (fetch::WINDOW as u64, false, true, false),
        (fetch::WINDOW as u64, true, false, false),
        (fetch::WINDOW as u64, true, true, true),
    ] {
        let target = 4 + gap;
        let expected = prefix.state.pool.with_completed_slot(target).unwrap();
        let checkpoint = Checkpoint {
            network: network.clone(),
            address: wallet.address_text(),
            slot: 4,
            block_hash: Some(block(4, 0)["blockhash"].as_str().unwrap().into()),
            block_height: 4,
            accepted: BTreeSet::new(),
            canonical_from_slot: 0,
            replay: serde_json::from_value(snapshot.clone()).unwrap(),
        };
        let mut mocks = MocksMap::from_iter([
            (
                RpcRequest::GetAccountInfo,
                json!({"context":{"slot":target},"value":{
                    "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                    "data":[bs58::encode(expected.encode()).into_string(),"base58"]}}),
            ),
            (RpcRequest::GetBlock, block(4, 0)),
            (RpcRequest::GetBlocks, json!([target])),
            (
                RpcRequest::Custom {
                    method: "getWalletHistoryBlocks",
                },
                json!([{"slot":target,"block":block(target,4)}]),
            ),
        ]);
        if old_store {
            mocks.insert(RpcRequest::Custom { method:"getWalletRetainedHistoryV2" },
                    json!({"network":network,"checkpoint":{"segments":1,"sha256":"a".repeat(64)},
                        "retained_tip":2,"after_slot":4,"through_slot":2,"next_slot":4,"complete":true,"blocks":[]}));
        }
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map("fails", mocks),
            network: network.clone(),
            sponsor_budget: None,
            user_fees: None,
            history_batches: true,
            retained_history_v2: compact,
            standard_reads: None,
            verification_key: Some(key.clone()),
            pool_format: "NPOOL004",
        };
        let result = chain
            .scan_source_mode(&[&wallet], Some(checkpoint), None, None, allow_retained)
            .unwrap();
        assert!(result.scan.cache_used);
        assert_eq!(result.scan.retained_rpc_requests, usize::from(old_store));
        assert_eq!(result.scan.history_blocks_read, 0);
        assert_eq!(result.scan.blocks_fetched, 1);
        assert_eq!(result.canonical_from_slot, 0);
        result.replay.state.reconcile(&expected).unwrap();
    }
}

#[test]
fn compact_history_page_bound_is_explicit_and_preserves_every_block() {
    let network = Network {
        network: [9; 32],
        genesis_hash: bs58::encode([8; 32]).into_string(),
    };
    let wallet = WalletKey::generate(network.clone()).unwrap();
    let key = std::sync::Arc::new(orchard::circuit::VerifyingKey::build(
        native_payments::verification::bundle_version().circuit_version(),
    ));
    for (compact_v2, count, valid) in [
        (false, 16, true),
        (false, 17, false),
        (true, 4096, true),
        (true, 16384, true),
        (true, 32768, true),
        (true, 32769, false),
    ] {
        let pool = PoolState::new_slot_anchored(network.network, 1000).unwrap();
        let mut expected = pool.with_completed_slot(0).unwrap();
        let mut blocks = Vec::with_capacity(count);
        for slot in 1..=count as u64 {
            blocks.push(
                HistoryBlock::from_rpc(
                    slot,
                    serde_json::from_value(block(slot, slot - 1)).unwrap(),
                )
                .unwrap(),
            );
            expected = expected.with_completed_slot(slot).unwrap();
        }
        let method = if compact_v2 {
            "getWalletRetainedHistoryV2"
        } else {
            "getWalletRetainedHistory"
        };
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map(
                "fails",
                MocksMap::from_iter([
                    (
                        RpcRequest::GetAccountInfo,
                        json!({"context":{"slot":count},"value":{
                        "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                        "data":[bs58::encode(expected.encode()).into_string(),"base58"]}}),
                    ),
                    (
                        RpcRequest::Custom { method },
                        json!({"network":network,
                        "checkpoint":{"segments":4,"sha256":"a".repeat(64)},
                        "retained_tip":count,"after_slot":0,"through_slot":count,
                        "next_slot":count,"complete":true,"blocks":blocks}),
                    ),
                    (RpcRequest::GetBlock, block(count as u64, count as u64 - 1)),
                ]),
            ),
            network: network.clone(),
            sponsor_budget: None,
            user_fees: None,
            history_batches: true,
            retained_history_v2: compact_v2,
            standard_reads: None,
            verification_key: Some(key.clone()),
            pool_format: "NPOOL004",
        };
        let scanned = chain.scan(&[&wallet], None);
        if valid {
            let scanned = scanned.unwrap();
            assert_eq!(scanned.scan.history_blocks_read, count);
            assert_eq!(scanned.scan.retained_rpc_requests, 1);
            assert_eq!(scanned.scan.blocks_fetched, 0);
            assert_eq!(scanned.canonical_from_slot, count as u64 + 1);
            assert!(scanned.accepted.is_empty());
            scanned.replay.state.reconcile(&expected).unwrap();
        } else {
            assert!(scanned.is_err(), "count {count}; compact_v2={compact_v2}");
        }
    }
}

#[test]
fn archival_pages_require_full_continuity_fixed_anchor_and_primary_header() {
    for mode in 0..13 {
        let (wallet, _, mut chain) = cached_fixture(2, vec![], vec![]);
        chain.history_batches = true;
        let anchor = json!({"slot":2,"blockhash":block(2,1)["blockhash"],"block_height":2});
        let page = |after, slot| {
            json!({"network":wallet.network,"anchor":anchor,
                "after_slot":after,"next_slot":slot,"complete":slot==2,"blocks":[{"slot":slot,"block":block(slot,after)}]})
        };
        let mut first = page(0, 1);
        let mut second = page(1, 2);
        match mode {
            1 => second["anchor"]["blockhash"] = json!(bs58::encode([33; 32]).into_string()),
            2 => first["network"]["network"][0] = json!(99),
            3 => first["blocks"] = json!([]),
            4 => second["blocks"][0]["block"]["parentSlot"] = json!(0),
            5 => first["next_slot"] = json!(2),
            6 => first["complete"] = json!(true),
            7 => second = serde_json::Value::Null,
            8 => first["blocks"][0]["slot"] = json!(3),
            9 => first["extra"] = json!("denied"),
            11 => first["blocks"][0]["parent_slot"] = json!(999),
            12 => {
                first["anchor"]["block_height"] = json!(3);
                second["anchor"]["block_height"] = json!(3);
            }
            _ => (),
        }
        let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
        chain.rpc = RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter([
                (
                    RpcRequest::GetAccountInfo,
                    json!({"context":{"slot":2},"value":{
                    "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                    "data":[bs58::encode(pool).into_string(),"base58"]}}),
                ),
                (
                    RpcRequest::Custom {
                        method: "getWalletCanonicalHistory",
                    },
                    first,
                ),
                (
                    RpcRequest::Custom {
                        method: "getWalletCanonicalHistory",
                    },
                    second,
                ),
                (
                    RpcRequest::GetBlock,
                    block(if mode == 10 { 3 } else { 2 }, 1),
                ),
            ]),
        );
        let scanned = chain.scan_source_mode(&[&wallet], None, None, None, false);
        if mode == 0 {
            let scanned = scanned.unwrap();
            assert_eq!(scanned.slot, 2);
            assert_eq!(scanned.canonical_from_slot, 0);
            assert_eq!(scanned.scan.archival_rpc_requests, 2);
            assert_eq!(scanned.scan.retained_rpc_requests, 0);
        } else {
            assert!(scanned.is_err(), "invalid archival mode {mode}");
        }
    }
}

#[test]
fn canonical_failed_finalization_requires_a_valid_signature_and_preserves_staging_identity() {
    let (wallet, _, chain) = cached_fixture(0, vec![], vec![]);
    let payer = Keypair::new();
    let staging = Pubkey::new_unique();
    let instruction = Instruction {
        program_id: id(),
        accounts: vec![
            solana_instruction::AccountMeta::new(pool_address(), false),
            solana_instruction::AccountMeta::new(staging, false),
        ],
        data: vec![3],
    };
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        Default::default(),
    );
    let signature = tx.signatures[0].to_string();
    let encoded = json!({"transaction":[base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap()),"base64"],
            "meta":{"err":{"InstructionError":[0,{"Custom":1}]},"status":{"Err":{"InstructionError":[0,{"Custom":1}]}},"fee":5000,"preBalances":[],"postBalances":[]}});
    let malformed = Transaction::new_signed_with_payer(
        &[Instruction {
            program_id: id(),
            accounts: vec![],
            data: vec![3],
        }],
        Some(&payer.pubkey()),
        &[&payer],
        Default::default(),
    );
    let mut malformed_encoded = encoded.clone();
    malformed_encoded["transaction"][0] =
        json!(base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&malformed).unwrap()));
    let mut canonical = block(1, 0);
    canonical["transactions"] = json!([encoded, malformed_encoded]);
    let mut result = chain.scan(&[&wallet], None).unwrap();
    result
        .apply_block(
            HistoryBlock::from_rpc(1, serde_json::from_value(canonical.clone()).unwrap()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        result.finalizations.get(&signature),
        Some(&(staging.to_string(), true))
    );
    assert!(result.accepted.is_empty());
    assert_eq!(result.finalizations.len(), 1);
    assert_eq!(result.scan.payments_verified, 0);
    let (retained_wallet, _, retained_chain) = cached_fixture(0, vec![], vec![]);
    let mut retained = retained_chain.scan(&[&retained_wallet], None).unwrap();
    retained
        .apply_retained_block(
            HistoryBlock::from_rpc(1, serde_json::from_value(canonical).unwrap()).unwrap(),
        )
        .unwrap();
    assert!(retained.finalizations.is_empty());
    let mut bad = tx;
    bad.signatures[0] = Signature::from([12; 64]);
    let mut block = block(2, 1);
    block["transactions"] = json!([{"transaction":[base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&bad).unwrap()),"base64"],"meta":{"err":"AccountNotFound","status":{"Err":"AccountNotFound"},"fee":5000,"preBalances":[],"postBalances":[]}}]);
    assert!(result
        .apply_block(HistoryBlock::from_rpc(2, serde_json::from_value(block).unwrap()).unwrap())
        .is_err());
}

#[test]
fn old_pending_archival_absence_requires_complete_coverage_and_expiry() {
    for mode in 0..5 {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let (wallet, mut checkpoint, mut chain) = cached_fixture(6, vec![], vec![]);
        checkpoint.canonical_from_slot = u64::MAX;
        cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
        chain.history_batches = true;
        let payer = Keypair::new();
        let staging = Pubkey::new_unique();
        let tx = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: id(),
                accounts: vec![
                    solana_instruction::AccountMeta::new(pool_address(), false),
                    solana_instruction::AccountMeta::new(staging, false),
                ],
                data: vec![3],
            }],
            Some(&payer.pubkey()),
            &[&payer],
            Default::default(),
        );
        let mut old = block(2, 0);
        if mode == 2 || mode == 3 {
            old["transactions"] = json!([{"transaction":[base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap()),"base64"],
                    "meta":{"err":"AccountNotFound","status":{"Err":"AccountNotFound"},"fee":5000,"preBalances":[],"postBalances":[]}}]);
        }
        let mut page = json!({"network":wallet.network,"anchor":{"slot":6,"blockhash":block(6,2)["blockhash"],"block_height":6},
                "after_slot":0,"next_slot":6,"complete":true,"blocks":[{"slot":2,"block":old},{"slot":6,"block":block(6,2)}]});
        if mode == 4 {
            page["blocks"][1]["block"]["parentSlot"] = json!(4);
        }
        let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
        let account = json!({"context":{"slot":6},"value":{"lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,"data":[bs58::encode(pool).into_string(),"base58"]}});
        chain.rpc = RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter([
                (RpcRequest::GetAccountInfo, account.clone()),
                (RpcRequest::GetAccountInfo, account),
                (RpcRequest::GetBlock, block(4, 3)),
                (RpcRequest::GetBlock, block(6, 2)),
                (RpcRequest::GetBlocks, json!([6])),
                (
                    RpcRequest::Custom {
                        method: "getWalletHistoryBlocks",
                    },
                    json!([{"slot":6,"block":block(6,4)}]),
                ),
                (
                    RpcRequest::Custom {
                        method: "getWalletCanonicalHistory",
                    },
                    page,
                ),
            ]),
        );
        let pending = Pending {
            network: wallet.network.clone(),
            signature: tx.signatures[0].to_string(),
            staging_account: if mode == 3 {
                Pubkey::new_unique().to_string()
            } else {
                staging.to_string()
            },
            last_valid_block_height: if mode == 1 { 100 } else { 0 },
            withdrawal: None,
        };
        let original = serde_json::to_vec(&pending).unwrap();
        write_private_new(&operation.pending, &original).unwrap();
        let outcome = chain.resolve(&wallet, &operation);
        if mode == 0 || mode == 2 {
            let outcome = outcome.unwrap();
            assert_eq!(outcome["accepted"], false);
            assert_eq!(outcome["failed"], mode == 2);
            assert_eq!(outcome["expired_without_execution"], mode == 0);
            assert!(!operation.pending.exists());
            assert_eq!(outcome["sync"]["archival_rpc_requests"], 1);
        } else {
            assert!(outcome.is_err());
            assert_eq!(fs::read(&operation.pending).unwrap(), original);
        }
    }
}

#[test]
fn retained_and_legacy_checkpoints_cannot_clear_unknown_expired_payments() {
    for canonical_from_slot in [5, u64::MAX] {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let (wallet, mut checkpoint, chain) =
            cached_fixture(6, vec![block(4, 3), block(6, 4)], vec![6]);
        checkpoint.canonical_from_slot = canonical_from_slot;
        cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
        let pending = Pending {
            network: wallet.network.clone(),
            signature: Signature::from([12; 64]).to_string(),
            staging_account: Pubkey::new_unique().to_string(),
            last_valid_block_height: 0,
            withdrawal: None,
        };
        let original = serde_json::to_vec(&pending).unwrap();
        write_private_new(&operation.pending, &original).unwrap();
        let error = chain.resolve(&wallet, &operation).unwrap_err().to_string();
        assert!(error.contains("cannot prove absence"), "{error}");
        assert_eq!(fs::read(&operation.pending).unwrap(), original);
        assert!(
            cache::read(&operation.scan_cache, &wallet)
                .unwrap()
                .canonical_from_slot
                > 0
        );
    }
}

#[test]
fn legacy_unknown_outcome_recovers_with_a_complete_canonical_rescan() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let (wallet, mut checkpoint, mut chain) = cached_fixture(6, vec![], vec![]);
    checkpoint.canonical_from_slot = u64::MAX;
    cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
    let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
    let account = json!({"context":{"slot":6},"value":{"lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,"data":[bs58::encode(pool).into_string(),"base58"]}});
    chain.rpc = RpcClient::new_mock_with_mocks_map(
        "succeeds",
        MocksMap::from_iter([
            (RpcRequest::GetAccountInfo, account.clone()),
            (RpcRequest::GetAccountInfo, account),
            (RpcRequest::GetBlocks, json!([6])),
            (RpcRequest::GetBlocks, json!([2, 6])),
            (RpcRequest::GetBlock, block(4, 3)),
            (RpcRequest::GetBlock, block(6, 4)),
            (RpcRequest::GetBlock, block(2, 0)),
            (RpcRequest::GetBlock, block(6, 2)),
        ]),
    );
    let pending = Pending {
        network: wallet.network.clone(),
        signature: Signature::from([12; 64]).to_string(),
        staging_account: Pubkey::new_unique().to_string(),
        last_valid_block_height: 0,
        withdrawal: None,
    };
    write_private_new(&operation.pending, &serde_json::to_vec(&pending).unwrap()).unwrap();
    let resolved = chain.resolve(&wallet, &operation).unwrap();
    assert_eq!(resolved["expired_without_execution"], true);
    assert!(!operation.pending.exists());
    assert_eq!(resolved["sync"]["cache_used"], false);
}

#[test]
fn retained_prefix_and_rpc_tail_must_reconcile_with_the_live_finalized_header() {
    for valid in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        let (wallet, _, chain) = cached_fixture(
            6,
            vec![block(6, 2), block(if valid { 6 } else { 7 }, 2)],
            vec![6],
        );
        let mut writer = Writer::open(&path, &wallet.network).unwrap();
        writer
            .push(HistoryBlock::from_rpc(2, serde_json::from_value(block(2, 0)).unwrap()).unwrap())
            .unwrap();
        writer.commit().unwrap();
        let history = Archive::open(&path, &wallet.network).unwrap();
        let result = chain.scan_source(&[&wallet], None, Some(&history), None);
        if valid {
            let result = result.unwrap();
            assert_eq!(result.scan.history_blocks_read, 1);
            assert_eq!(result.scan.blocks_fetched, 1);
            assert_eq!(result.replay.state.balance().unwrap(), 0);
        } else {
            assert!(result
                .err()
                .unwrap()
                .to_string()
                .contains("finalized RPC block hash"));
        }
    }
    for cached in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        let headers = if cached {
            vec![block(4, 0), block(4, 0)]
        } else {
            vec![block(4, 0)]
        };
        let (wallet, mut checkpoint, chain) = cached_fixture(4, headers, vec![]);
        checkpoint
            .accepted
            .insert("metadata-is-not-canonical-inclusion".into());
        let mut writer = Writer::open(&path, &wallet.network).unwrap();
        let mut archived =
            HistoryBlock::from_rpc(4, serde_json::from_value(block(4, 0)).unwrap()).unwrap();
        archived.block_height = u64::MAX;
        writer.push(archived).unwrap();
        writer.commit().unwrap();
        let history = Archive::open(&path, &wallet.network).unwrap();
        let result = chain
            .scan_source(
                &[&wallet],
                cached.then_some(checkpoint),
                Some(&history),
                None,
            )
            .unwrap();
        assert_eq!(
            result.block_height, 4,
            "use finalized RPC height, not retained metadata"
        );
        assert!(
            result.accepted.is_empty(),
            "never expose retained identities as canonical inclusion"
        );
    }
}

#[test]
fn public_history_export_extends_immutable_prefix_and_refuses_rpc_rollback() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("history");
    let (_, _, chain) = cached_fixture(6, vec![block(2, 0), block(6, 2), block(6, 2)], vec![2, 6]);
    let first = chain.export_history(&path).unwrap();
    assert_eq!(first["new_blocks"], 2);
    let (_, _, next) = cached_fixture(8, vec![block(8, 6), block(8, 6)], vec![8]);
    let second = next.export_history(&path).unwrap();
    assert_eq!(second["new_blocks"], 1);
    assert_eq!(second["retained_blocks_verified"], 2);
    let before = fs::read(path.join("manifest.json")).unwrap();
    let (_, _, behind) = cached_fixture(7, vec![], vec![]);
    assert!(behind
        .export_history(&path)
        .unwrap_err()
        .to_string()
        .contains("refusing archive rollback"));
    assert_eq!(fs::read(path.join("manifest.json")).unwrap(), before);
}

#[test]
fn incremental_scan_checks_canonical_checkpoint_and_extension_continuity() {
    let (wallet, checkpoint, chain) = cached_fixture(6, vec![block(4, 3), block(6, 4)], vec![6]);
    let result = chain.scan(&[&wallet], Some(checkpoint)).unwrap();
    assert!(result.scan.cache_used);
    assert_eq!(result.scan.from_slot, 5);
    assert_eq!(result.scan.blocks_fetched, 1);
    assert_eq!(result.scan.payments_verified, 0);
    for parent in [0, 5] {
        let (wallet, checkpoint, chain) =
            cached_fixture(6, vec![block(4, 3), block(6, parent)], vec![6]);
        assert!(chain
            .scan(&[&wallet], Some(checkpoint))
            .err()
            .unwrap()
            .to_string()
            .contains("discontinuous"));
    }
}

#[test]
fn private_pending_resolution_extends_authenticated_checkpoint_without_genesis_rescan() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let (wallet, mut checkpoint, chain) =
        cached_fixture(6, vec![block(4, 3), block(6, 4)], vec![6]);
    let signature = Signature::from([11; 64]).to_string();
    checkpoint.accepted.insert(signature.clone());
    cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
    let pending = Pending {
        network: wallet.network.clone(),
        signature: signature.clone(),
        staging_account: Pubkey::new_unique().to_string(),
        last_valid_block_height: 100,
        withdrawal: None,
    };
    write_private_new(&operation.pending, &serde_json::to_vec(&pending).unwrap()).unwrap();
    let resolution = chain.resolve(&wallet, &operation).unwrap();
    assert_eq!(resolution["signature"], signature);
    assert_eq!(resolution["accepted"], true);
    assert_eq!(resolution["sync"]["cache_used"], true);
    assert_eq!(resolution["sync"]["blocks_fetched"], 1);
    assert!(!operation.pending.exists());
    assert_eq!(cache::read(&operation.scan_cache, &wallet).unwrap().slot, 6);
}

#[test]
fn pending_resolution_preserves_journal_on_rpc_rollback_and_missing_withdrawal_history() {
    for withdrawal in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let (wallet, mut checkpoint, chain) = if withdrawal {
            cached_fixture(6, vec![block(6, 4)], vec![6])
        } else {
            cached_fixture(3, vec![], vec![])
        };
        let signature = Signature::from([12; 64]).to_string();
        checkpoint.accepted.insert(signature.clone());
        cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
        let pending = Pending {
            network: wallet.network.clone(),
            signature,
            staging_account: Pubkey::new_unique().to_string(),
            last_valid_block_height: 100,
            withdrawal: withdrawal.then(|| crate::payments::WithdrawalReceipt {
                recipient: Pubkey::new_unique().to_string(),
                amount: 10,
                sponsor: Pubkey::new_unique().to_string(),
            }),
        };
        let original = serde_json::to_vec(&pending).unwrap();
        write_private_new(&operation.pending, &original).unwrap();
        let error = chain.resolve(&wallet, &operation).unwrap_err().to_string();
        assert!(
            error.contains(if withdrawal {
                "discontinuous"
            } else {
                "behind the verified"
            }),
            "{error}"
        );
        assert_eq!(fs::read(&operation.pending).unwrap(), original);
    }
}

#[test]
fn lagging_rpc_and_missing_archive_cannot_authorize_cached_balance() {
    let (wallet, checkpoint, chain) = cached_fixture(3, vec![], vec![]);
    assert!(chain
        .scan(&[&wallet], Some(checkpoint))
        .err()
        .unwrap()
        .to_string()
        .contains("behind the verified"));
    let (wallet, checkpoint, chain) =
        cached_fixture(6, vec![serde_json::Value::Null, block(6, 4)], vec![6]);
    assert!(chain
        .scan(&[&wallet], Some(checkpoint))
        .err()
        .unwrap()
        .to_string()
        .contains("discontinuous"));
    let (wallet, checkpoint, chain) = cached_fixture(6, vec![block(4, 3)], vec![]);
    assert!(chain
        .scan(&[&wallet], Some(checkpoint))
        .err()
        .unwrap()
        .to_string()
        .contains("does not reach"));
}

#[test]
fn changed_checkpoint_requires_complete_rescan_before_cache_replacement() {
    let (wallet, checkpoint, chain) =
        cached_fixture(6, vec![block(5, 3), block(2, 0), block(6, 2)], vec![2, 6]);
    let result = chain.scan(&[&wallet], Some(checkpoint)).unwrap();
    assert!(!result.scan.cache_used);
    assert_eq!(
        result.scan.cache_reset.as_deref(),
        Some("checkpoint_unavailable_or_changed")
    );
    assert_eq!(result.scan.from_slot, 0);
    assert_eq!(result.scan.blocks_fetched, 2);
}

#[test]
fn cache_storage_failure_does_not_discard_verified_state() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    fs::create_dir(&operation.scan_cache).unwrap();
    let (wallet, _, chain) = cached_fixture(0, vec![], vec![]);
    let synced = chain.sync_cached(&wallet, &operation).unwrap();
    assert_eq!(synced.state.balance().unwrap(), 0);
    assert!(!synced.scan.cache_saved);
    assert_eq!(synced.scan.cache_reset.as_deref(), Some("invalid_cache"));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

fn fixture(operation: &WalletOperation, sponsor: &Keypair, height: u64) -> Network {
    let network = Network {
        network: [9; 32],
        genesis_hash: bs58::encode([8; 32]).into_string(),
    };
    let recovery = StagingRecovery {
        network: network.clone(),
        sponsor: sponsor.pubkey().to_string(),
        staging_account: Pubkey::new_unique().to_string(),
        initialize_signature: Signature::from([3; 64]).to_string(),
        last_valid_block_height: height,
        expiry: 2000,
        payload_len: 10,
        payload_digest: [7; 32],
        sponsor_request_id: None,
        user_fee: None,
    };
    write_private_new(&operation.staging, &serde_json::to_vec(&recovery).unwrap()).unwrap();
    network
}

fn absent_chain(network: Network, slot: u64, url: &str) -> Chain {
    let response = json!({"context":{"slot":slot},"value":null});
    let mocks = MocksMap::from_iter([
        (RpcRequest::GetAccountInfo, response.clone()),
        (RpcRequest::GetAccountInfo, response),
    ]);
    Chain {
        rpc: RpcClient::new_mock_with_mocks_map(url, mocks),
        sponsor_budget: None,
        user_fees: None,
        history_batches: false,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
        network,
    }
}

#[test]
fn aggregated_upload_fees_fail_closed_and_charge_only_attempted_messages() {
    for mode in ["missing", "null", "substituted", "cap"] {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let payer = Keypair::new();
        let network = fixture(&operation, &payer, 100);
        let mut record: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
        let mut authorization = crate::fees::Authorization::new(100, 10).unwrap();
        authorization.charged = 80;
        record.user_fee = Some(authorization);
        crate::sponsor::replace(&operation.staging, &serde_json::to_vec(&record).unwrap()).unwrap();
        let original = fs::read(&operation.staging).unwrap();
        let transactions: Vec<_> = (0..2)
            .map(|_| {
                Transaction::new_signed_with_payer(
                    &[instructions::seal(Pubkey::new_unique(), payer.pubkey())],
                    Some(&payer.pubkey()),
                    &[&payer],
                    Default::default(),
                )
            })
            .collect();
        let mut response: Vec<_> = transactions.iter().map(|tx| json!({
                "request":{"method":"getFeeForMessage","params":[base64::engine::general_purpose::STANDARD.encode(tx.message.serialize()),{"commitment":"confirmed"}]},
                "result":{"context":{"slot":34},"value":7}
            })).collect();
        match mode {
            "missing" => {
                response.pop();
            }
            "null" => response[1]["result"]["value"] = json!(null),
            "substituted" => response[1]["request"]["params"][0] = json!("AAAA"),
            _ => (),
        }
        let mocks = MocksMap::from_iter([
            (
                RpcRequest::Custom {
                    method: "getWalletReadBatch",
                },
                json!(response),
            ),
            (
                RpcRequest::SendTransaction,
                json!(transactions[0].signatures[0].to_string()),
            ),
        ]);
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
            network,
            sponsor_budget: None,
            user_fees: Some((payer.pubkey(), 100, operation.staging.clone())),
            history_batches: true,
            retained_history_v2: false,
            standard_reads: None,
            verification_key: None,
            pool_format: "NPOOL003",
        };
        assert!(chain.send_uploads(&transactions).is_err());
        assert!(!operation.pending.exists());
        let saved: StagingRecovery =
            serde_json::from_slice(&fs::read(&operation.staging).unwrap()).unwrap();
        let saved = saved.user_fee.unwrap();
        assert_eq!(saved.cleanup_reserve, 10);
        assert_eq!(saved.charged, if mode == "cap" { 87 } else { 80 });
        if mode != "cap" {
            assert_eq!(fs::read(&operation.staging).unwrap(), original);
        }
    }
}

#[test]
fn user_fee_charges_are_durable_and_original_cap_survives_recovery() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let payer = Keypair::new();
    let network = fixture(&operation, &payer, 100);
    let mut record: StagingRecovery =
        serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
    record.user_fee = Some(crate::fees::Authorization::new(100, 10).unwrap());
    crate::sponsor::replace(&operation.staging, &serde_json::to_vec(&record).unwrap()).unwrap();
    let mocks = MocksMap::from_iter(std::iter::repeat_n(
        (
            RpcRequest::GetFeeForMessage,
            json!({"context":{"slot":34},"value":7}),
        ),
        4,
    ));
    let chain = Chain {
        rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
        network: network.clone(),
        sponsor_budget: None,
        user_fees: Some((payer.pubkey(), 100, operation.staging.clone())),
        history_batches: false,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
    };
    let tx = Transaction::new_with_payer(
        &[instructions::seal(Pubkey::new_unique(), payer.pubkey())],
        Some(&payer.pubkey()),
    );
    chain.charge_sponsor(&tx, 80).unwrap();
    assert!(chain.charge_sponsor(&tx, 0).is_err());
    let restored: StagingRecovery =
        serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
    assert_eq!(restored.user_fee.unwrap().charged, 87);
    assert_eq!(
        chain
            .recovery_user_limit(&operation, payer.pubkey())
            .unwrap(),
        Some(100)
    );
    assert!(chain
        .recovery_user_limit(&operation, Keypair::new().pubkey())
        .is_err());
    let close = Transaction::new_with_payer(
        &[instructions::close(Pubkey::new_unique(), payer.pubkey())],
        Some(&payer.pubkey()),
    );
    chain.charge_sponsor(&close, 0).unwrap();
    let restored: StagingRecovery =
        serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
    assert_eq!(restored.user_fee.unwrap().charged, 94);
    let other = chain
        .with_user_fees(payer.pubkey(), 101, &operation)
        .unwrap();
    assert!(other.charge_sponsor(&close, 0).is_err());
}

#[test]
fn user_paid_recovery_cannot_silently_bypass_its_recorded_cap() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let payer = Keypair::new();
    let network = fixture(&operation, &payer, 100);
    let mut record: StagingRecovery =
        serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
    record.user_fee = Some(crate::fees::Authorization::new(100, 10).unwrap());
    crate::sponsor::replace(&operation.staging, &serde_json::to_vec(&record).unwrap()).unwrap();
    let chain = Chain {
        rpc: RpcClient::new_mock("succeeds"),
        network,
        sponsor_budget: None,
        user_fees: None,
        history_batches: false,
        retained_history_v2: false,
        standard_reads: None,
        verification_key: None,
        pool_format: "NPOOL003",
    };
    assert!(chain
        .reclaim(&payer, &operation)
        .unwrap_err()
        .to_string()
        .contains("original recorded fee mode"));
    assert!(operation.staging.exists());
}

#[test]
fn absent_live_initialization_is_retained_until_finalized_expiry() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let sponsor = Keypair::new();
    let network = fixture(&operation, &sponsor, 100);
    let chain = absent_chain(network.clone(), 34, "sig_not_found");
    assert!(chain
        .reclaim(&sponsor, &operation)
        .unwrap_err()
        .to_string()
        .contains("still pending"));
    assert!(operation.staging.exists());
    let mut recovery: StagingRecovery =
        serde_json::from_slice(&fs::read(&operation.staging).unwrap()).unwrap();
    recovery.last_valid_block_height = 20; // A synthetic unit fixture, never broadcast.
    fs::write(&operation.staging, serde_json::to_vec(&recovery).unwrap()).unwrap();
    let cleared = absent_chain(network, 34, "sig_not_found")
        .reclaim(&sponsor, &operation)
        .unwrap();
    assert_eq!(cleared["recovery_cleared"], true);
    assert_eq!(cleared["rent_reclaimed"], false);
    assert!(!operation.staging.exists());
}

#[test]
fn stale_absence_cannot_clear_an_expired_initialization() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let sponsor = Keypair::new();
    let network = fixture(&operation, &sponsor, 20);
    let error = absent_chain(network, 1, "sig_not_found")
        .reclaim(&sponsor, &operation)
        .unwrap_err();
    assert!(error.to_string().contains("checkpoint is older"));
    assert!(operation.staging.exists());
}

#[test]
fn pending_payment_and_wrong_signer_block_reclamation() {
    let root = tempfile::tempdir().unwrap();
    let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
    let sponsor = Keypair::new();
    let network = fixture(&operation, &sponsor, 20);
    let chain = absent_chain(network, 34, "sig_not_found");
    write_private_new(&operation.pending, b"unresolved").unwrap();
    assert!(chain
        .reclaim(&sponsor, &operation)
        .unwrap_err()
        .to_string()
        .contains("unresolved payment"));
    fs::remove_file(&operation.pending).unwrap();
    assert!(chain
        .reclaim(&Keypair::new(), &operation)
        .unwrap_err()
        .to_string()
        .contains("sponsor mismatch"));
    assert!(operation.staging.exists());
}
