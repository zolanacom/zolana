//! Select a frozen descendant of the signed vote, preserving other fork records.
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Meta {
    pub parent: Option<u64>,
    pub full: bool,
    pub frozen: bool,
    pub dead: bool,
    pub duplicate: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub checkpoint: u64,
    pub complete_child: Option<u64>,
    pub complete: Vec<u64>,
    pub partial: Vec<u64>,
    pub competing: Vec<u64>,
    pub rejected: Vec<u64>,
}

fn ancestry(slot: u64, floor: u64, nodes: &BTreeMap<u64, Meta>) -> Result<BTreeSet<u64>, String> {
    let mut path = BTreeSet::new();
    let mut current = slot;
    loop {
        path.insert(current);
        if current <= floor {
            return Ok(path);
        }
        let node = nodes
            .get(&current)
            .ok_or("restart branch has missing ancestry")?;
        let parent = node.parent.ok_or("restart branch has no parent")?;
        if parent >= current {
            return Err("invalid restart ancestry".into());
        }
        current = parent;
    }
}

pub fn plan(nodes: &BTreeMap<u64, Meta>, vote: u64, floor: u64) -> Result<Plan, String> {
    if nodes.len() > 4096 || vote < floor {
        return Err("restart ancestry exceeds bounds or signed vote is behind root".into());
    }
    if nodes.values().any(|n| n.duplicate || (n.dead && n.frozen)) {
        return Err("duplicate or frozen-dead restart record requires explicit repair".into());
    }
    let voted = nodes
        .get(&vote)
        .ok_or("signed vote metadata is unavailable")?;
    let voted_path = ancestry(vote, floor, nodes)?;
    if !voted.frozen || !voted_path.contains(&floor) {
        return Err("signed vote has no frozen rooted ancestry".into());
    }
    // A leader can persist its frozen bank hash and signed vote before the
    // final broadcast shred batch reaches disk. Keep that future tower vote
    // and every partial record; replay its nearest complete frozen ancestor.
    // Agave's ordinary tower restoration retains future lockouts. This never
    // rewinds or rewrites the tower, and cannot choose a competing branch.
    let mut checkpoint = None;
    for (&slot, node) in nodes {
        if node.frozen && node.full {
            let path = ancestry(slot, floor, nodes)?;
            if path.contains(&vote) || voted_path.contains(&slot) {
                if path.iter().any(|s| nodes.get(s).is_some_and(|n| !n.full)) {
                    continue;
                }
                checkpoint = Some(slot);
            }
        } else if node.frozen && !voted_path.contains(&slot) {
            if !node.full {
                return Err("frozen restart bank has incomplete metadata".into());
            }
        }
    }
    let checkpoint = checkpoint.ok_or("signed vote has no complete frozen restart ancestor")?;
    if checkpoint <= floor {
        return Err("restart checkpoint would discard tower restoration".into());
    }
    let selected = ancestry(checkpoint, floor, nodes)?;
    if voted_path
        .union(&selected)
        .any(|slot| nodes.get(slot).is_some_and(|node| node.dead))
    {
        return Err("restart checkpoint has rejected ancestry".into());
    }
    let mut result = Plan {
        checkpoint,
        complete_child: None,
        complete: vec![],
        partial: vec![],
        competing: vec![],
        rejected: vec![],
    };
    for (&slot, node) in nodes {
        if selected.contains(&slot) {
            continue;
        }
        let path = ancestry(slot, floor, nodes)?;
        if path
            .iter()
            .any(|slot| nodes.get(slot).is_some_and(|node| node.dead))
        {
            result.rejected.push(slot);
            continue;
        }
        if slot <= checkpoint
            || !path.contains(&checkpoint)
            || (!path.contains(&vote) && !voted_path.contains(&slot))
        {
            result.competing.push(slot);
            continue;
        }
        if node.full {
            if node.frozen {
                return Err("frozen compatible bank was omitted from checkpoint".into());
            }
            result.complete.push(slot);
        } else {
            result.partial.push(slot);
        }
    }
    if result.complete.len() == 1 && nodes[&result.complete[0]].parent == Some(checkpoint) {
        result.complete_child = Some(result.complete[0]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn meta(parent: u64, full: bool, frozen: bool) -> Meta {
        Meta {
            parent: Some(parent),
            full,
            frozen,
            dead: false,
            duplicate: false,
        }
    }
    fn original() -> BTreeMap<u64, Meta> {
        let mut rejected = meta(6155, true, false);
        rejected.dead = true;
        BTreeMap::from([
            (6155, meta(6122, true, true)),
            (6156, rejected),
            (6171, meta(6155, true, true)),
            (6172, meta(6171, true, true)),
            (6173, meta(6172, true, true)),
            (6174, meta(6173, true, true)),
            (6175, meta(6174, false, false)),
            (6176, meta(6171, true, false)),
            (6179, meta(6174, false, false)),
        ])
    }
    #[test]
    fn actual_service_shape_retains_competing_full_fork_and_multiple_partial_children() {
        let nodes = original();
        let before = format!("{nodes:?}");
        assert_eq!(
            plan(&nodes, 6174, 6122).unwrap(),
            Plan {
                checkpoint: 6174,
                complete_child: None,
                complete: vec![],
                partial: vec![6175, 6179],
                competing: vec![6176],
                rejected: vec![6156]
            }
        );
        assert_eq!(format!("{nodes:?}"), before);
    }
    #[test]
    fn a_higher_frozen_competing_fork_never_replaces_the_signed_vote_branch() {
        let mut nodes = original();
        nodes.get_mut(&6176).unwrap().frozen = true;
        let selected = plan(&nodes, 6174, 6122).unwrap();
        assert_eq!(selected.checkpoint, 6174);
        assert_eq!(selected.competing, vec![6176]);
    }
    #[test]
    fn compatible_full_child_still_requires_the_separate_verified_replay_path() {
        let mut nodes = original();
        nodes.insert(6177, meta(6174, true, false));
        assert_eq!(plan(&nodes, 6174, 6122).unwrap().complete_child, Some(6177));
        nodes.insert(6178, meta(6177, true, false));
        let result = plan(&nodes, 6174, 6122).unwrap();
        assert_eq!(result.complete_child, None);
        assert_eq!(result.complete, vec![6177, 6178]);
        assert_eq!(result.checkpoint, 6174);
    }
    #[test]
    fn a_frozen_descendant_can_extend_but_never_rewind_the_vote_checkpoint() {
        let mut nodes = original();
        nodes.insert(6180, meta(6174, true, true));
        assert_eq!(plan(&nodes, 6174, 6122).unwrap().checkpoint, 6180);
        assert!(plan(&nodes, 6174, 6180).is_err());
    }
    #[test]
    fn dead_duplicate_missing_nonfrozen_voted_and_invalid_ancestry_fail_closed() {
        for mode in 0..7 {
            let mut nodes = original();
            match mode {
                0 => nodes.get_mut(&6174).unwrap().dead = true,
                1 => nodes.get_mut(&6176).unwrap().duplicate = true,
                2 => {
                    nodes.remove(&6173);
                }
                3 => nodes.get_mut(&6174).unwrap().frozen = false,
                4 => nodes.get_mut(&6179).unwrap().parent = Some(6179),
                5 => nodes.get_mut(&6174).unwrap().parent = Some(6121),
                _ => nodes.get_mut(&6179).unwrap().parent = None,
            };
            assert!(plan(&nodes, 6174, 6122).is_err(), "mode {mode}");
        }
    }
    #[test]
    fn rejected_forks_and_their_descendants_are_retained_without_clearing_dead_flags() {
        let mut nodes = original();
        nodes.insert(6160, meta(6156, true, false));
        let result = plan(&nodes, 6174, 6122).unwrap();
        assert_eq!(result.rejected, vec![6156, 6160]);
        assert!(nodes[&6156].dead);
        assert_eq!(result.complete_child, None);
    }

    #[test]
    fn crash_after_vote_before_final_shred_keeps_future_vote_and_its_exact_branch() {
        let mut nodes = original();
        nodes.get_mut(&6174).unwrap().full = false;
        let before = format!("{nodes:?}");
        let result = plan(&nodes, 6174, 6122).unwrap();
        assert_eq!(result.checkpoint, 6173);
        assert!(result.partial.contains(&6174));
        assert_eq!(format!("{nodes:?}"), before);
        // A complete competing fork must never replace the voted branch.
        nodes.get_mut(&6176).unwrap().frozen = true;
        assert_eq!(plan(&nodes, 6174, 6122).unwrap().checkpoint, 6173);
        nodes.insert(6180, meta(6173, true, true));
        let result = plan(&nodes, 6174, 6122).unwrap();
        assert_eq!(result.checkpoint, 6173);
        assert!(result.competing.contains(&6180));
        nodes.get_mut(&6174).unwrap().dead = true;
        assert!(plan(&nodes, 6174, 6122).is_err());
    }
}
