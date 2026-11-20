//! Pins the values the examples print and the claims `sdk/README.md` makes.
//! Offline. One test builds real proofs; the others are immediate.
use native_payments::{
    native_accounts::{nullifier_address, pool_address, PROGRAM_ID},
    state::{PoolState, SLOT_STATE_BYTES, STATE_BYTES},
    wire,
};
use native_wallet_core::{
    decode_address,
    history::WalletState,
    payments::{Payment, PaymentProver},
};
use native_wallet_seed::{decrypt, encrypt, Error as SeedError, Network};
use zolana_sdk_examples::{DemoWallet, GENESIS, NETWORK};

fn base58(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

#[test]
fn demo_wallet_address_matches_the_browser_core_reference() {
    // The browser core publishes a reference identity for the same public
    // seed and network. Both paths must derive the same private address.
    let reference: serde_json::Value =
        serde_json::from_str(&browser_core::vault::reference_json().unwrap()).unwrap();
    let wallet = DemoWallet::new(NETWORK, GENESIS, [7; 32]);
    let address = wallet.address().unwrap();
    assert_eq!(reference["identity"]["private_address"], address.as_str());
    assert!(address.starts_with("npriv1"));
    assert!(decode_address(NETWORK, GENESIS, &address).is_ok());
    assert!(decode_address([8; 32], GENESIS, &address).is_err());
    assert_ne!(
        address,
        DemoWallet::new(NETWORK, GENESIS, [8; 32])
            .address()
            .unwrap()
    );
}

#[test]
fn seed_backup_round_trips_and_refuses_other_passwords_and_networks() {
    let network = Network {
        network: NETWORK,
        genesis_hash: GENESIS.to_owned(),
    };
    let backup = encrypt(&[7; 32], b"disposable example password", &network).unwrap();
    assert_eq!(
        *decrypt(&backup, b"disposable example password", &network).unwrap(),
        [7; 32]
    );
    assert_eq!(
        decrypt(&backup, b"another password", &network).unwrap_err(),
        SeedError::Authentication
    );
    let other = Network {
        network: [8; 32],
        ..network
    };
    assert_eq!(
        decrypt(&backup, b"disposable example password", &other).unwrap_err(),
        SeedError::FormatOrNetworkMismatch
    );
}

#[test]
fn account_addresses_are_the_published_development_values() {
    assert_eq!(
        base58(&PROGRAM_ID),
        "78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh"
    );
    assert_eq!(
        base58(&pool_address()),
        "4mJMnxFhRVMQ3aNcyn2LgW8fztTjgckUvaaWrXggdAAL"
    );
    assert_eq!(
        base58(&nullifier_address(&[0x11; 32])),
        "GuqZuJN89WRqYmKAiu35HeEoXbTzzpn6i4Xadwn8zVeN"
    );
    assert_ne!(
        nullifier_address(&[0x11; 32]),
        nullifier_address(&[0x12; 32])
    );
}

#[test]
fn pool_state_sizes_tags_and_anchor_window() {
    let mut pool = PoolState::new_slot_anchored(NETWORK, 1_000_000).unwrap();
    pool.complete_slot(0).unwrap();
    pool.complete_slot(7).unwrap();
    let bytes = pool.encode();
    assert_eq!(
        (bytes.len(), &bytes[..8]),
        (SLOT_STATE_BYTES, &b"NPOOL004"[..])
    );
    assert_eq!(SLOT_STATE_BYTES, 25_728);
    let decoded = PoolState::decode(&bytes).unwrap();
    assert_eq!(decoded.encode(), bytes);
    let root = decoded.root();
    assert!(decoded.accepted_roots(518).unwrap().contains(&root));
    assert!(!decoded.accepted_roots(519).unwrap().contains(&root));
    let legacy = PoolState::new(NETWORK, 1_000_000).unwrap().encode();
    assert_eq!(
        (legacy.len(), &legacy[..8]),
        (STATE_BYTES, &b"NPOOL003"[..])
    );
    assert_eq!(STATE_BYTES, 3_137);
}

#[test]
fn deposit_has_the_documented_header_and_replays_into_a_balance() {
    let alice = DemoWallet::new(NETWORK, GENESIS, [7; 32]);
    let prover = PaymentProver::new();
    let mut state = WalletState::with_key(&alice, 1, prover.verifying_key()).unwrap();
    let payment = Payment::Deposit {
        amount: 25,
        recipient: &alice.address().unwrap(),
    };
    let bytes = prover
        .build(&alice, &state, [0x53; 32], 100, payment)
        .unwrap();
    assert_eq!(bytes.len(), 9_222);
    assert_eq!(&bytes[..8], b"NPAY0001");
    assert_eq!(bytes[8..40], NETWORK);
    assert_eq!(u64::from_le_bytes(bytes[40..48].try_into().unwrap()), 100);
    assert_eq!(i64::from_le_bytes(bytes[48..56].try_into().unwrap()), -25);
    assert_eq!(bytes[56..88], [0x53; 32]);
    let decoded = wire::decode(NETWORK, &bytes).unwrap();
    assert_eq!(
        wire::encode(NETWORK, &decoded.context, &decoded.bundle).unwrap(),
        bytes
    );
    state.accept(&decoded.bundle, &decoded.context, 1).unwrap();
    assert_eq!(state.balance().unwrap(), 25);
    assert_eq!(state.pool.backing, 25);
    assert!(state.accept(&decoded.bundle, &decoded.context, 1).is_err());
}
