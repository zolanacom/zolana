//! Fail-closed startup replay bound, separate from inspection halts/hard forks.
use std::collections::BTreeSet;

/// Immutable pre-TPU ledger inventory. Later producer slots, including gaps
/// below the old highest slot, must never be replayed as historical leaders.
#[derive(Default)]
pub struct StoredReplay {
    slots: BTreeSet<u64>,
}

pub fn durable_vote_ready(enabled: bool, complete_ancestry: impl FnOnce() -> bool) -> bool {
    !enabled || complete_ancestry()
}
impl StoredReplay {
    pub fn capture(slots: impl IntoIterator<Item = u64>) -> Result<Self, String> {
        let slots: BTreeSet<_> = slots.into_iter().take(4097).collect();
        if slots.len() > 4096 {
            return Err("native stored replay inventory exceeds bounds".into());
        }
        Ok(Self { slots })
    }
    pub fn admits(&self, slot: u64, complete: impl FnOnce() -> bool) -> bool {
        self.slots.contains(&slot) && complete()
    }
}
pub struct Inputs {
    pub enabled: bool,
    pub slot: Option<u64>,
    pub require_tower: bool,
    pub genesis_pinned: bool,
    pub hash_pinned: bool,
    pub stored_hash_matches: bool,
    pub root: u64,
    pub override_mode: bool,
}

pub fn checkpoint(input: Inputs) -> Result<Option<u64>, String> {
    if !input.enabled {
        return Ok(None);
    }
    let slot = input
        .slot
        .ok_or("native restart requires the coordinated checkpoint")?;
    if !input.require_tower
        || !input.genesis_pinned
        || !input.hash_pinned
        || !input.stored_hash_matches
        || input.override_mode
        || slot <= input.root
    {
        return Err("native restart requires a frozen hash-pinned checkpoint above root, the original tower and no halt/warp/hard-fork override".into());
    }
    Ok(Some(slot))
}

pub fn check_loaded_root(limit: Option<u64>, root: u64) -> Result<(), String> {
    if limit.is_some_and(|slot| root >= slot) {
        return Err(
            "native restart snapshot/root reaches checkpoint; tower-discard path forbidden".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_complete_child_cannot_be_voted_while_a_required_parent_is_still_missing_data() {
        assert!(!durable_vote_ready(true, || [true, false, true]
            .into_iter()
            .all(|full| full)));
        assert!(durable_vote_ready(true, || [true, true, true]
            .into_iter()
            .all(|full| full)));
        assert!(durable_vote_ready(false, || panic!(
            "upstream mode must not inspect native vote data"
        )));
    }
    #[test]
    fn stored_replay_captures_only_old_slots_including_later_repairs_not_new_producer_gaps() {
        let stored = StoredReplay::capture([6271, 6272, 6311]).unwrap();
        assert!(!stored.admits(6271, || false));
        assert!(stored.admits(6271, || true)); // same retained slot, now repaired
        assert!(stored.admits(6272, || true)); // full old slot need not have a hash yet
        assert!(!stored.admits(6280, || panic!("live producer gap must not inspect ledger")));
        assert!(!stored.admits(6312, || panic!("new producer must not inspect ledger")));
        assert!(!StoredReplay::default().admits(6272, || panic!("normal startup unchanged")));
        assert!(StoredReplay::capture(0..4097).is_err());
    }
    fn valid() -> Inputs {
        Inputs {
            enabled: true,
            slot: Some(6174),
            require_tower: true,
            genesis_pinned: true,
            hash_pinned: true,
            stored_hash_matches: true,
            root: 6122,
            override_mode: false,
        }
    }
    #[test]
    fn native_checkpoint_requires_every_pin_and_cannot_select_root_or_override_tower() {
        assert_eq!(checkpoint(valid()).unwrap(), Some(6174));
        for mode in 0..8 {
            let mut input = valid();
            match mode {
                0 => input.slot = None,
                1 => input.require_tower = false,
                2 => input.genesis_pinned = false,
                3 => input.hash_pinned = false,
                4 => input.stored_hash_matches = false,
                5 => input.root = 6174,
                6 => input.root = 6180,
                _ => input.override_mode = true,
            };
            assert!(checkpoint(input).is_err());
        }
    }
    #[test]
    fn normal_startup_is_unchanged_and_snapshot_bound_never_discards_a_tower() {
        let mut input = valid();
        input.enabled = false;
        input.slot = None;
        assert_eq!(checkpoint(input).unwrap(), None);
        assert!(check_loaded_root(None, 9999).is_ok());
        assert!(check_loaded_root(Some(6174), 6122).is_ok());
        assert!(check_loaded_root(Some(6174), 6174).is_err());
        assert!(check_loaded_root(Some(6174), 6180).is_err());
    }
}
