//! Tests of the payment inspector, and the source of `sdk/fixtures/`.
//!
//! Offline. The fixtures are real payments with real proofs, made by the
//! ignored test at the end of this file. The other tests read them back, so a
//! change to the wire format, the verifier or the inspector shows up here.
use native_payments::{
    envelope, staging::payload_digest, state::PoolState, verification::MAX_EXPIRY_WINDOW, wire,
    Error,
};
use native_wallet_core::{
    history::WalletState,
    payments::{Payment, PaymentProver},
};
use serde_json::{json, Value};
use std::{path::PathBuf, process::Command, sync::Arc};
use zolana_sdk_examples::{
    hex,
    inspect::{inspect, parse_input, verifying_key, Inspection, Kind, ENVELOPE_TAG},
    DemoWallet, GENESIS, NETWORK,
};

const PAYMENTS: [&str; 3] = ["deposit", "shielded-send", "withdrawal"];
/// The public account that funds the deposit and receives the shielded fee.
const SPONSOR: [u8; 32] = [0x53; 32];
/// The public account the withdrawal fixture pays. A withdrawal recipient
/// must be a valid Ed25519 public key; this one is the curve's base point.
const RECIPIENT: [u8; 32] = {
    let mut key = [0x66; 32];
    key[0] = 0x58;
    key
};
const EXPIRY: u64 = 100;
/// Order of the field that anchors, nullifiers and commitments are elements
/// of, as 64 hex digits, most significant first. An encoding is canonical when
/// it is below this number; `field_elements_must_be_canonical` checks that the
/// decoder draws the line exactly here.
const FIELD_MODULUS: &str = "40000000000000000000000000000000224698fc094cf91b992d30ed00000001";
/// Slots at which `expected.json` records the roots the pool accepts.
const ROOT_SLOTS: [u64; 3] = [4, 513, 600];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

fn read(name: &str) -> Vec<u8> {
    let path = fixtures().join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn payment(name: &str) -> Vec<u8> {
    parse_input(&read(&format!("{name}.hex"))).unwrap()
}

fn report(bytes: &[u8]) -> Inspection {
    inspect(bytes, Some(NETWORK), &verifying_key()).unwrap()
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let group = chunk
            .iter()
            .fold(0u32, |group, byte| (group << 8) | u32::from(*byte))
            << (8 * (3 - chunk.len()));
        for index in 0..4 {
            text.push(if index <= chunk.len() {
                DIGITS[(group >> (18 - 6 * index)) as usize & 63] as char
            } else {
                '='
            });
        }
    }
    text
}

/// Everything `expected.json` records, computed from the fixture bytes.
fn describe(payments: &[Vec<u8>], pool: &[u8]) -> Value {
    let key = verifying_key();
    let inspected = |bytes: &[u8]| -> Value {
        let report = inspect(bytes, Some(NETWORK), &key).unwrap();
        assert_eq!(report.verification, Ok(()));
        serde_json::from_str(&report.json()).unwrap()
    };
    let reports: serde_json::Map<String, Value> = PAYMENTS
        .iter()
        .zip(payments)
        .map(|(name, bytes)| (name.to_string(), inspected(bytes)))
        .collect();
    let frame = envelope::encode(NETWORK, &payments[1]).unwrap();
    let state = PoolState::decode(pool).unwrap();
    let anchors: Vec<Value> = state
        .slot_anchors()
        .unwrap()
        .entries()
        .iter()
        .map(|entry| {
            json!({
                "slot": entry.slot.to_string(),
                "note_count": entry.note_count.to_string(),
                "root": hex(&entry.root),
            })
        })
        .collect();
    let accepted: serde_json::Map<String, Value> = ROOT_SLOTS
        .iter()
        .map(|slot| {
            let roots = state.accepted_roots(*slot).unwrap();
            (
                slot.to_string(),
                roots.iter().map(|root| hex(root)).collect(),
            )
        })
        .collect();
    let address = |seed| {
        DemoWallet::new(NETWORK, GENESIS, [seed; 32])
            .address()
            .unwrap()
    };
    json!({
        "network": hex(&NETWORK),
        "genesis_hash": GENESIS,
        "field_modulus": FIELD_MODULUS,
        "addresses": { "alice": address(7), "bob": address(8) },
        "payments": reports,
        "envelope": {
            "header": hex(&frame[..envelope::ENVELOPE_HEADER_BYTES]),
            "inspection": inspected(&frame),
        },
        "pool": {
            "tag": std::str::from_utf8(&pool[..8]).unwrap(),
            "bytes": pool.len(),
            "network": hex(&state.network),
            "rent_floor": state.rent_floor.to_string(),
            "backing": state.backing.to_string(),
            "note_count": state.note_count().to_string(),
            "root": hex(&state.root()),
            "slot_anchors": anchors,
            "accepted_roots": accepted,
        },
    })
}

#[test]
fn the_fixtures_are_what_the_inspector_reports() {
    let payments: Vec<Vec<u8>> = PAYMENTS.iter().map(|name| payment(name)).collect();
    let pool = parse_input(&read("pool-account.base64")).unwrap();
    let expected: Value = serde_json::from_slice(&read("expected.json")).unwrap();
    assert_eq!(describe(&payments, &pool), expected);

    // The values a reader is told to expect in the documentation.
    let deposit = report(&payments[0]);
    assert_eq!(
        (deposit.kind, deposit.tag.as_str(), deposit.bytes),
        (Kind::Deposit, "NPAY0001", 9_222)
    );
    assert_eq!(
        (deposit.public_value_balance, deposit.shielded_fee),
        (-100, None)
    );
    let send = report(&payments[1]);
    assert_eq!(
        (send.kind, send.tag.as_str(), send.bytes),
        (Kind::ShieldedFeePayment, "NPAY0003", 9_230)
    );
    assert_eq!((send.public_value_balance, send.shielded_fee), (3, Some(3)));
    assert_eq!(
        (send.expires_at, send.sponsor, send.withdrawal_recipient),
        (EXPIRY, SPONSOR, None)
    );
    assert_eq!(send.payment_id, payload_digest(&payments[1]));
    // The send spends the note the deposit created: it is anchored in a tree
    // that holds the deposit's commitments, not in the empty tree.
    assert_ne!(send.anchor, deposit.anchor);
    let withdrawal = report(&payments[2]);
    assert_eq!(
        (withdrawal.kind, withdrawal.tag.as_str(), withdrawal.bytes),
        (Kind::RecipientWithdrawal, "NPAY0002", 9_254)
    );
    assert_eq!(
        (
            withdrawal.public_value_balance,
            withdrawal.withdrawal_recipient
        ),
        (20, Some(RECIPIENT))
    );
    // 100 entered, the fee of 3 and the withdrawal of 20 left.
    assert_eq!(expected["pool"]["backing"], "77");
    assert_eq!(expected["pool"]["note_count"], "6");
}

#[test]
fn the_text_report_is_the_committed_one_and_the_command_prints_it() {
    let text = String::from_utf8(read("shielded-send.inspect.txt")).unwrap();
    assert_eq!(report(&payment("shielded-send")).text(), text);
    assert!(text.contains(&format!(
        "from slot {} through slot {EXPIRY}",
        EXPIRY.saturating_sub(MAX_EXPIRY_WINDOW)
    )));

    let command = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_inspect-payment"))
            .args(arguments)
            .output()
            .unwrap()
    };
    let path = fixtures().join("shielded-send.hex");
    let printed = command(&[path.to_str().unwrap()]);
    assert_eq!(printed.status.code(), Some(0));
    assert_eq!(String::from_utf8(printed.stdout).unwrap(), text);

    let json = command(&[
        "--json",
        "--network",
        &hex(&NETWORK),
        path.to_str().unwrap(),
    ]);
    assert_eq!(json.status.code(), Some(0));
    let expected: Value = serde_json::from_slice(&read("expected.json")).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&json.stdout).unwrap(),
        expected["payments"]["shielded-send"]
    );

    // A payment for another network, and bytes that are no payment: status 2.
    let other = command(&["--network", &hex(&[9; 32]), path.to_str().unwrap()]);
    assert_eq!(other.status.code(), Some(2));
    assert!(String::from_utf8(other.stderr)
        .unwrap()
        .contains("WrongNetwork"));
    assert_eq!(command(&["00ff"]).status.code(), Some(2));
    assert_eq!(command(&[]).status.code(), Some(2));

    // Bytes that decode but do not verify: status 1, and the report says so.
    let mut tampered = payment("shielded-send");
    let inside_proof = tampered.len() - 64 - 100;
    tampered[inside_proof] ^= 1;
    let refused = command(&[&hex(&tampered)]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8(refused.stdout)
        .unwrap()
        .contains("NOT VERIFIED         InvalidProof"));
}

#[test]
fn changed_bytes_decode_but_do_not_verify() {
    let bytes = payment("shielded-send");
    let key = verifying_key();
    let verification = |bytes: &[u8]| inspect(bytes, None, &key).map(|report| report.verification);

    // One bit inside the proof.
    let mut changed = bytes.clone();
    let inside_proof = changed.len() - 64 - 100;
    changed[inside_proof] ^= 1;
    assert_eq!(verification(&changed), Ok(Err(Error::InvalidProof)));
    // One bit of the binding signature, the last 64 bytes.
    let mut changed = bytes.clone();
    let last = changed.len() - 1;
    changed[last - 40] ^= 1;
    assert_eq!(
        verification(&changed),
        Ok(Err(Error::InvalidBindingSignature))
    );
    // The signed expiry. The signatures cover it, so a later one is refused.
    let mut changed = bytes.clone();
    changed[40] ^= 1;
    let later = inspect(&changed, None, &key).unwrap();
    assert_eq!(later.expires_at, EXPIRY ^ 1);
    assert_eq!(later.verification, Err(Error::InvalidSpendAuthorization));
    // The sponsor, the public account the fee is paid to.
    let mut changed = bytes.clone();
    changed[56] ^= 1;
    assert_eq!(
        verification(&changed),
        Ok(Err(Error::InvalidSpendAuthorization))
    );
    // The fee no longer matches the value balance: refused while decoding.
    let mut changed = bytes.clone();
    changed[88] ^= 1;
    assert_eq!(verification(&changed), Err(Error::InvalidContext));
    // The network. The bytes still decode, for the network they now name.
    let mut changed = bytes.clone();
    changed[8] ^= 1;
    assert_eq!(
        verification(&changed),
        Ok(Err(Error::InvalidSpendAuthorization))
    );
    assert_eq!(
        inspect(&changed, Some(NETWORK), &key).unwrap_err(),
        Error::WrongNetwork
    );

    assert_eq!(
        verification(&bytes[..bytes.len() - 1]),
        Err(Error::InvalidLength)
    );
    assert_eq!(verification(&bytes[..20]), Err(Error::InvalidLength));
    // An unknown tag is read with the length of the plain layout, so it is
    // reported as unsupported only when the bytes have that length.
    let unknown = [b"NPAY9999".as_slice(), &bytes[8..]].concat();
    assert_eq!(verification(&unknown), Err(Error::InvalidLength));
    let unknown = [b"NPAY9999".as_slice(), &payment("deposit")[8..]].concat();
    assert_eq!(verification(&unknown), Err(Error::UnsupportedVersion));
    // Nothing above changed the original.
    assert_eq!(verification(&bytes), Ok(Ok(())));
}

/// `refusals.json` lists changes to the fixtures and the error each one must
/// produce. The JavaScript readers are tested against the same list, so the
/// two decoders are held to the same refusals.
#[test]
fn the_shared_refusal_list_matches_the_decoders() {
    let cases: Vec<Value> = serde_json::from_slice(&read("refusals.json")).unwrap();
    let key = verifying_key();
    assert!(cases.len() >= 30);
    for case in &cases {
        let fixture = case["fixture"].as_str().unwrap();
        let mut bytes = match fixture {
            "pool-account" => parse_input(&read("pool-account.base64")).unwrap(),
            name => payment(name),
        };
        for change in case["set"].as_array().into_iter().flatten() {
            let offset = change["offset"].as_u64().unwrap() as usize;
            let value = parse_input(change["hex"].as_str().unwrap().as_bytes()).unwrap();
            bytes[offset..offset + value.len()].copy_from_slice(&value);
        }
        bytes.truncate(bytes.len() - case["truncate"].as_u64().unwrap_or(0) as usize);
        let refusal = match fixture {
            "pool-account" => PoolState::decode(&bytes).map(|_| ()).unwrap_err(),
            _ => inspect(&bytes, None, &key).map(|_| ()).unwrap_err(),
        };
        assert_eq!(refusal.to_string(), case["error"], "{}", case["why"]);
    }
}

#[test]
fn field_elements_must_be_canonical() {
    // 32 little-endian bytes: the field order itself, and the largest element.
    let mut modulus = parse_input(FIELD_MODULUS.as_bytes()).unwrap();
    modulus.reverse();
    let mut largest = modulus.clone();
    largest[0] -= 1;
    let bytes = payment("deposit");
    let key = verifying_key();
    // The anchor is at offset 88; the first action's nullifier follows the
    // 122-byte header and its commitment comes 64 bytes later.
    for offset in [88, wire::HEADER_BYTES, wire::HEADER_BYTES + 64] {
        let mut changed = bytes.clone();
        changed[offset..offset + 32].copy_from_slice(&modulus);
        assert_eq!(
            inspect(&changed, None, &key).unwrap_err(),
            Error::InvalidEncoding
        );
        // One less is a field element: the bytes decode, and no longer verify.
        changed[offset..offset + 32].copy_from_slice(&largest);
        assert!(inspect(&changed, None, &key).unwrap().verification.is_err());
    }
}

#[test]
fn an_inline_envelope_is_opened_and_its_payment_inspected() {
    let bytes = payment("shielded-send");
    let frame = envelope::encode(NETWORK, &bytes).unwrap();
    assert_eq!(&frame[..8], ENVELOPE_TAG);
    let (bare, framed) = (report(&bytes), report(&frame));
    assert!(framed.enveloped && !bare.enveloped);
    assert_eq!(
        (framed.bytes, framed.payment_bytes),
        (bytes.len() + envelope::ENVELOPE_HEADER_BYTES, bytes.len())
    );
    assert_eq!(framed.payment_id, bare.payment_id);
    assert_eq!(framed.actions, bare.actions);
    assert_eq!(framed.verification, Ok(()));
    assert!(framed.text().starts_with(
        "input                9332 bytes, an inline envelope around a 9230-byte NPAY0003 payment\n"
    ));
    // The envelope names the payment id. A frame whose payment differs from
    // that id is refused before anything is verified.
    let mut changed = frame.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert_eq!(
        inspect(&changed, None, &verifying_key()).unwrap_err(),
        Error::DigestMismatch
    );
    // Only shielded-fee payments have an envelope.
    assert!(envelope::encode(NETWORK, &payment("deposit")).is_err());
}

#[test]
fn input_is_accepted_as_bytes_hex_or_base64() {
    let bytes = payment("deposit");
    assert_eq!(parse_input(&bytes).unwrap(), bytes);
    assert_eq!(parse_input(hex(&bytes).as_bytes()).unwrap(), bytes);
    let spaced = format!(
        "  {}\n{}\n",
        hex(&bytes[..9]),
        hex(&bytes[9..]).to_uppercase()
    );
    assert_eq!(parse_input(spaced.as_bytes()).unwrap(), bytes);
    for length in [bytes.len(), bytes.len() - 1, bytes.len() - 2] {
        let encoded = base64(&bytes[..length]);
        assert_eq!(parse_input(encoded.as_bytes()).unwrap(), bytes[..length]);
        let unpadded = encoded.trim_end_matches('=');
        assert_eq!(parse_input(unpadded.as_bytes()).unwrap(), bytes[..length]);
    }
    for refused in [
        "",
        "   ",
        "abd",
        "not a payment!",
        "AAAA=A",
        "A",
        "QUJD====",
    ] {
        assert!(parse_input(refused.as_bytes()).is_err(), "{refused:?}");
    }
    assert!(parse_input(&[0xff, 0xfe]).is_err());
}

/// Builds the three payments the fixtures hold, in order, with the pool
/// account after them. Proofs are randomized, so every call differs.
fn build() -> (Vec<Vec<u8>>, Vec<u8>) {
    let alice = DemoWallet::new(NETWORK, GENESIS, [7; 32]);
    let bob = DemoWallet::new(NETWORK, GENESIS, [8; 32]);
    let prover = PaymentProver::new();
    let pool = PoolState::new_slot_anchored(NETWORK, 1).unwrap();
    let mut state =
        WalletState::with_key_for_pool(&alice, &pool, Arc::clone(&prover.verifying_key())).unwrap();
    let steps = [
        Payment::Deposit {
            amount: 100,
            recipient: &alice.address().unwrap(),
        },
        Payment::ShieldedSend {
            amount: 40,
            recipient: &bob.address().unwrap(),
            fee: 3,
        },
        Payment::WithdrawTo {
            amount: 20,
            recipient: RECIPIENT,
        },
    ];
    let mut payments = Vec::new();
    for (index, step) in steps.into_iter().enumerate() {
        let slot = index as u64 + 1;
        let bytes = prover.build(&alice, &state, SPONSOR, EXPIRY, step).unwrap();
        let decoded = wire::decode(NETWORK, &bytes).unwrap();
        state
            .accept(&decoded.bundle, &decoded.context, slot)
            .unwrap();
        state.finish_slot(slot).unwrap();
        payments.push(bytes);
    }
    assert_eq!(state.balance().unwrap(), 37);
    (payments, state.pool.encode())
}

#[test]
fn every_kind_is_named_from_the_tag_and_the_value_balance() {
    // The fixtures cover a deposit, a shielded-fee payment and a withdrawal to
    // a recipient. Build the two remaining kinds here: both carry NPAY0001.
    let alice = DemoWallet::new(NETWORK, GENESIS, [7; 32]);
    let bob = DemoWallet::new(NETWORK, GENESIS, [8; 32]);
    let prover = PaymentProver::new();
    let key = prover.verifying_key();
    let mut state = WalletState::with_key(&alice, 1, Arc::clone(&key)).unwrap();
    let deposit = Payment::Deposit {
        amount: 100,
        recipient: &alice.address().unwrap(),
    };
    let send = Payment::Send {
        amount: 40,
        recipient: &bob.address().unwrap(),
    };
    let withdraw = Payment::Withdraw { amount: 25 };
    let mut reports = Vec::new();
    for (index, step) in [deposit, send, withdraw].into_iter().enumerate() {
        let bytes = prover.build(&alice, &state, SPONSOR, EXPIRY, step).unwrap();
        let decoded = wire::decode(NETWORK, &bytes).unwrap();
        state
            .accept(&decoded.bundle, &decoded.context, index as u64 + 1)
            .unwrap();
        let report = inspect(&bytes, Some(NETWORK), &key).unwrap();
        assert_eq!(report.verification, Ok(()));
        assert_eq!((report.tag.as_str(), report.bytes), ("NPAY0001", 9_222));
        reports.push(report);
    }
    let kinds: Vec<(Kind, i64, String)> = reports
        .iter()
        .map(|report| {
            (
                report.kind,
                report.public_value_balance,
                report.public_value(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            (
                Kind::Deposit,
                -100,
                "100 units enter the pool, debited from the sponsor".to_owned()
            ),
            (Kind::PrivateSend, 0, "none moves".to_owned()),
            (
                Kind::SponsorWithdrawal,
                25,
                "25 units leave the pool to the sponsor".to_owned()
            ),
        ]
    );
    // A private send and a withdrawal reveal the nullifiers of what they spend;
    // no two payments share one.
    let mut nullifiers: Vec<[u8; 32]> = reports
        .iter()
        .flat_map(|report| report.actions.iter().map(|action| action.nullifier))
        .collect();
    nullifiers.sort();
    nullifiers.dedup();
    assert_eq!(nullifiers.len(), 6);
}

/// Writes `sdk/fixtures/`. Run it only to replace the fixtures:
///
///     sh tools/dev.sh test --offline --locked -p zolana-sdk-examples --test inspect -- --ignored write_the_fixtures
#[test]
#[ignore = "rewrites sdk/fixtures with new randomized payments"]
fn write_the_fixtures() {
    let (payments, pool) = build();
    let write = |name: &str, content: String| std::fs::write(fixtures().join(name), content);
    for (name, bytes) in PAYMENTS.iter().zip(&payments) {
        let lines: Vec<String> = bytes.chunks(32).map(hex).collect();
        write(&format!("{name}.hex"), lines.join("\n") + "\n").unwrap();
    }
    write("pool-account.base64", base64(&pool) + "\n").unwrap();
    refresh_the_derived_fixtures();
}

/// Rewrites `expected.json` and the text report from the payments and the pool
/// account already in `sdk/fixtures/`, without replacing those. Run it after a
/// change to what the inspector reports:
///
///     sh tools/dev.sh test --offline --locked -p zolana-sdk-examples --test inspect -- --ignored refresh_the_derived_fixtures
#[test]
#[ignore = "rewrites the derived files in sdk/fixtures"]
fn refresh_the_derived_fixtures() {
    let payments: Vec<Vec<u8>> = PAYMENTS.iter().map(|name| payment(name)).collect();
    let pool = parse_input(&read("pool-account.base64")).unwrap();
    let write = |name: &str, content: String| std::fs::write(fixtures().join(name), content);
    let expected = serde_json::to_string_pretty(&describe(&payments, &pool)).unwrap();
    write("expected.json", expected + "\n").unwrap();
    write("shielded-send.inspect.txt", report(&payments[1]).text()).unwrap();
}
