//! Bounded stopped-ledger diagnostics; no shred, bank or tower mutation.
use super::*;
use solana_core::consensus::{tower_storage::FileTowerStorage, Tower};
use std::collections::VecDeque;

pub fn inspect(root: &Path, index: usize, name: &str) -> Result<()> {
    if index > 1
        || !name.starts_with("ledger-")
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("invalid local validator or ledger".into());
    }
    let identity = read_keypair_file(root.join(format!("identity-{index}.keypair.json")))?;
    let genesis = solana_genesis_config::GenesisConfig::load(&root.join(name))?;
    let tower = Tower::restore(
        &FileTowerStorage::new(root.join(format!("consensus-{index}"))),
        &identity.pubkey(),
    )?;
    // PRIMARY access fails if a validator owns this blockstore. Never inspect
    // through a secondary view whose state could race an active writer.
    let store = Blockstore::open(&root.join(name))?;
    let highest = store.highest_slot()?.ok_or("empty restart ledger")?;
    let mut recent = VecDeque::new();
    let mut latest_frozen = None;
    let mut count = 0usize;
    for (slot, meta) in store.slot_meta_iterator(0)? {
        let frozen = store.get_bank_hash(slot);
        if frozen.is_some() {
            latest_frozen = Some(slot);
        }
        recent.push_back(
            json!({"slot":slot,"parent":meta.parent_slot,"full":meta.is_full(),
            "received":meta.received,"consumed":meta.consumed,"last_index":meta.last_index,
            "bank_hash":frozen.map(|hash|hash.to_string()),"dead":store.is_dead(slot),
            "duplicate":store.has_duplicate_shreds_in_slot(slot),"root":store.is_root(slot)}),
        );
        if recent.len() > 64 {
            recent.pop_front();
        }
        count += 1;
    }
    let meta = store.meta(highest)?.ok_or("missing highest metadata")?;
    let intermediate = meta
        .parent_slot
        .map(|parent| {
            store
                .slot_meta_iterator(parent.saturating_add(1))
                .map(|mut slots| slots.any(|(slot, _)| slot < highest))
        })
        .transpose()?;
    println!(
        "{}",
        json!({"format":"native-restart-tail-diagnostic-v1","identity":identity.pubkey().to_string(),
        "genesis_hash":genesis.hash().to_string(),"tower_root":tower.root(),"last_vote":tower.last_voted_slot_hash().map(|(slot,hash)|json!({"slot":slot,"hash":hash.to_string()})),
        "highest_slot":highest,"latest_frozen":latest_frozen,"blockstore_root":store.max_root(),
        "intermediate":intermediate,"slots_count":count,"recent":recent})
    );
    Ok(())
}
