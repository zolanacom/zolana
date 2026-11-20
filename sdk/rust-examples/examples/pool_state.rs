//! Encode and decode the pool account, and see which anchors it accepts.
//!
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example pool_state
//!
//! Offline. No proof is built. On a network, the bytes decoded here are the
//! data of the pool account as returned by getAccountInfo.
use native_payments::{
    anchors::ANCHOR_WINDOW_SLOTS,
    state::{PoolState, SLOT_STATE_BYTES, STATE_BYTES},
};
use zolana_sdk_examples::{hex, NETWORK};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The slot-anchored format: one root per completed slot.
    let mut pool = PoolState::new_slot_anchored(NETWORK, 1_000_000)?;
    pool.complete_slot(0)?; // the empty genesis checkpoint
    pool.complete_slot(7)?; // a later block without payments
    let bytes = pool.encode();
    assert_eq!(bytes.len(), SLOT_STATE_BYTES);
    println!(
        "{} bytes, tag {}",
        bytes.len(),
        std::str::from_utf8(&bytes[..8])?
    );

    let decoded = PoolState::decode(&bytes)?;
    println!("network        {}", hex(&decoded.network));
    println!("rent floor     {}", decoded.rent_floor);
    println!("backing        {}", decoded.backing); // total value of all notes
    println!("notes          {}", decoded.note_count());
    println!("root           {}", hex(&decoded.root()));
    let anchors = decoded.slot_anchors().ok_or("slot anchors expected")?;
    for entry in anchors.entries() {
        println!("  slot {} holds {} notes", entry.slot, entry.note_count);
    }

    // A proof names the root it was built against. A root recorded for slot S
    // is accepted in later slots while its age is below 512 slots.
    let root = decoded.root();
    for slot in [7, 8, 7 + ANCHOR_WINDOW_SLOTS - 1, 7 + ANCHOR_WINDOW_SLOTS] {
        // roots_at refuses a slot earlier than the last recorded one.
        let accepted = decoded.accepted_roots(slot)?.contains(&root);
        println!("root accepted at slot {slot}: {accepted}");
    }

    // The older format keeps the 64 most recent roots instead.
    let legacy = PoolState::new(NETWORK, 1_000_000)?;
    let bytes = legacy.encode();
    assert_eq!(bytes.len(), STATE_BYTES);
    println!(
        "{} bytes, tag {}",
        bytes.len(),
        std::str::from_utf8(&bytes[..8])?
    );
    println!(
        "legacy roots   {}",
        PoolState::decode(&bytes)?.roots().len()
    );

    // Anything else is refused.
    let refused = PoolState::decode(&bytes[..100]).unwrap_err();
    println!("truncated account: {refused:?}");
    Ok(())
}
