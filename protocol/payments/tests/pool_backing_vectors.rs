//! Pins the pool-account encodings that `tools/supply_monitor.py` decodes.
//!
//! The supply monitor reads the pool account over RPC and parses its header in
//! Python. Its tests replay the account bytes written here by the real encoder
//! through a deposit, a private send and two withdrawals, in both pool formats.
//! This test fails when the encoder and the committed vectors disagree.
//!
//! Regenerate after an intended format change:
//!
//!     WRITE_POOL_BACKING_VECTORS=1 sh tools/dev.sh test --offline --locked \
//!         -p native-payments --test pool_backing_vectors
use native_payments::{
    native_accounts::{pool_address, PROGRAM_ID},
    state::{PoolState, SLOT_STATE_BYTES, STATE_BYTES},
    verification::VerifiedPayment,
};
use solana_pubkey::Pubkey;
use std::fmt::Write;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tools/fixtures/pool_backing_vectors_v1.json"
);
/// Public synthetic domain; not a network.
const NETWORK: [u8; 32] = [7; 32];
/// The default rent schedule of the validator: two years of 3,480 units per
/// byte-year over the data and 128 bytes of account overhead.
const RENT_OVERHEAD_BYTES: u64 = 128;
const RENT_PER_BYTE: u64 = 3_480 * 2;
/// A zero run this long ends a segment; shorter runs stay inside it.
const GAP: usize = 16;

/// Public movement of each step: negative deposits, zero is a private send,
/// positive withdraws. The last withdrawal empties the pool.
const STEPS: [(&str, i64); 5] = [
    ("deposit", -1_000),
    ("deposit", -250),
    ("send", 0),
    ("withdrawal", 400),
    ("withdrawal", 850),
];

fn rent_floor(bytes: usize) -> u64 {
    (RENT_OVERHEAD_BYTES + bytes as u64) * RENT_PER_BYTE
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The non-zero runs of an account, as `[offset, hex]` pairs.
fn segments(data: &[u8]) -> Vec<(usize, &[u8])> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < data.len() {
        if data[index] == 0 {
            index += 1;
            continue;
        }
        let start = index;
        let mut end = index + 1;
        let mut zeros = 0;
        index += 1;
        while index < data.len() && zeros < GAP {
            if data[index] == 0 {
                zeros += 1;
            } else {
                zeros = 0;
                end = index + 1;
            }
            index += 1;
        }
        found.push((start, &data[start..end]));
        index = end;
    }
    found
}

fn step(out: &mut String, event: &str, movement: i64, pool: &PoolState, bytes: usize, last: bool) {
    let data = pool.encode();
    assert_eq!(data.len(), bytes);
    // The monitor only ever sees bytes the validator would accept.
    assert_eq!(PoolState::decode(&data).unwrap().encode(), data);
    let mut rebuilt = vec![0; bytes];
    let parts = segments(&data);
    for (offset, part) in &parts {
        rebuilt[*offset..*offset + part.len()].copy_from_slice(part);
    }
    assert_eq!(rebuilt, data);
    writeln!(out, "        {{").unwrap();
    writeln!(out, "          \"event\": \"{event}\",").unwrap();
    writeln!(out, "          \"public_value_balance\": {movement},").unwrap();
    writeln!(out, "          \"backing\": {},", pool.backing).unwrap();
    writeln!(out, "          \"note_count\": {},", pool.note_count()).unwrap();
    writeln!(out, "          \"segments\": [").unwrap();
    for (index, (offset, part)) in parts.iter().enumerate() {
        let comma = if index + 1 == parts.len() { "" } else { "," };
        writeln!(out, "            [{offset}, \"{}\"]{comma}", hex(part)).unwrap();
    }
    writeln!(out, "          ]").unwrap();
    writeln!(out, "        }}{}", if last { "" } else { "," }).unwrap();
}

fn sequence(out: &mut String, tag: &str, bytes: usize, slot_anchored: bool, last: bool) {
    let floor = rent_floor(bytes);
    let mut pool = if slot_anchored {
        PoolState::new_slot_anchored(NETWORK, floor).unwrap()
    } else {
        PoolState::new(NETWORK, floor).unwrap()
    };
    let mut slot = 0;
    if slot_anchored {
        pool.complete_slot(slot).unwrap();
    }
    writeln!(out, "    {{").unwrap();
    writeln!(out, "      \"pool_format\": \"{tag}\",").unwrap();
    writeln!(out, "      \"data_bytes\": {bytes},").unwrap();
    writeln!(out, "      \"rent_floor\": {floor},").unwrap();
    writeln!(out, "      \"steps\": [").unwrap();
    step(out, "genesis", 0, &pool, bytes, false);
    for (index, (event, movement)) in STEPS.iter().enumerate() {
        // Distinct canonical field elements; the monitor never interprets them.
        let seed = 2 * index as u8 + 1;
        pool = pool
            .with_payment(&VerifiedPayment {
                nullifiers: [[seed; 32], [seed + 1; 32]],
                commitments: [[seed; 32], [seed + 1; 32]],
                public_value_balance: *movement,
            })
            .unwrap();
        if slot_anchored {
            slot += 3;
            pool.complete_slot(slot).unwrap();
        }
        step(
            out,
            event,
            *movement,
            &pool,
            bytes,
            index + 1 == STEPS.len(),
        );
    }
    assert_eq!(pool.backing, 0);
    writeln!(out, "      ]").unwrap();
    writeln!(out, "    }}{}", if last { "" } else { "," }).unwrap();
}

fn vectors() -> String {
    let mut out = String::new();
    writeln!(out, "{{").unwrap();
    writeln!(out, "  \"format\": \"native-pool-backing-vectors-v1\",").unwrap();
    writeln!(
        out,
        "  \"program\": \"{}\",",
        Pubkey::new_from_array(PROGRAM_ID)
    )
    .unwrap();
    writeln!(
        out,
        "  \"pool\": \"{}\",",
        Pubkey::new_from_array(pool_address())
    )
    .unwrap();
    writeln!(out, "  \"network\": \"{}\",", hex(&NETWORK)).unwrap();
    writeln!(out, "  \"rent_overhead_bytes\": {RENT_OVERHEAD_BYTES},").unwrap();
    writeln!(out, "  \"rent_per_byte\": {RENT_PER_BYTE},").unwrap();
    writeln!(out, "  \"sequences\": [").unwrap();
    sequence(&mut out, "NPOOL003", STATE_BYTES, false, false);
    sequence(&mut out, "NPOOL004", SLOT_STATE_BYTES, true, true);
    writeln!(out, "  ]").unwrap();
    writeln!(out, "}}").unwrap();
    out
}

#[test]
fn committed_vectors_are_what_the_encoder_writes() {
    let expected = vectors();
    if std::env::var_os("WRITE_POOL_BACKING_VECTORS").is_some() {
        std::fs::write(VECTORS, &expected).unwrap();
    }
    let committed = std::fs::read_to_string(VECTORS).unwrap();
    assert!(
        committed == expected,
        "tools/fixtures/pool_backing_vectors_v1.json differs from the encoder; see this file's header"
    );
}

#[test]
fn header_offsets_the_monitor_reads_are_the_encoder_offsets() {
    // Both formats share the header the monitor parses: tag, network domain,
    // rent floor, backing and note count, all little-endian.
    for (bytes, slot_anchored) in [(STATE_BYTES, false), (SLOT_STATE_BYTES, true)] {
        let mut pool = if slot_anchored {
            PoolState::new_slot_anchored(NETWORK, 0x0102_0304_0506_0708).unwrap()
        } else {
            PoolState::new(NETWORK, 0x0102_0304_0506_0708).unwrap()
        };
        pool = pool
            .with_payment(&VerifiedPayment {
                nullifiers: [[1; 32], [2; 32]],
                commitments: [[1; 32], [2; 32]],
                public_value_balance: -0x1112_1314_1516_1718,
            })
            .unwrap();
        let data = pool.encode();
        assert_eq!(data.len(), bytes);
        assert_eq!(&data[8..40], &NETWORK);
        assert_eq!(data[40..48], 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(data[48..56], 0x1112_1314_1516_1718u64.to_le_bytes());
        assert_eq!(data[56..64], 2u64.to_le_bytes());
    }
}
