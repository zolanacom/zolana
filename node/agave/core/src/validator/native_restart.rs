//! Fail-closed startup replay bound, separate from inspection halts/hard forks.
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
