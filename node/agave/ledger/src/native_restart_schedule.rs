//! Bounded operational lookahead from an explicitly pinned restart Bank.
pub fn horizon(
    root_epoch: u64,
    bank_epoch: u64,
    root_max: u64,
    requested: u64,
    frozen: bool,
) -> Result<Option<u64>, String> {
    if !frozen {
        return Err("native restart schedule requires a frozen checkpoint".into());
    }
    if requested <= root_max {
        return Ok(None);
    }
    if bank_epoch > root_epoch.saturating_add(1) || requested != root_max.saturating_add(1) {
        return Err("native restart schedule may extend only one epoch from a checkpoint at most one epoch above root".into());
    }
    Ok(Some(requested))
}
pub fn visible(root_max: u64, horizon: Option<u64>) -> u64 {
    root_max.max(horizon.unwrap_or(root_max))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoint_can_only_open_one_available_epoch_without_advancing_root() {
        assert_eq!(horizon(48, 49, 49, 50, true).unwrap(), Some(50));
        assert_eq!(horizon(49, 49, 50, 50, true).unwrap(), None);
        assert!(horizon(48, 50, 49, 51, true).is_err());
        assert!(horizon(48, 49, 49, 51, true).is_err());
        assert!(horizon(48, 49, 49, 50, false).is_err());
        let root_max = 49;
        assert_eq!(visible(root_max, Some(50)), 50);
        assert_eq!(root_max, 49);
        assert_eq!(visible(50, None), 50);
        assert_eq!(visible(51, None), 51);
    }
}
