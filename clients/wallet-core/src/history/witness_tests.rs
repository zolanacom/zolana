use super::*;

fn leaf(value: u32) -> MerkleHashOrchard {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&value.to_le_bytes());
    Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap()
}

// Deliberately rebuild the full tree, as the original wallet did, to compare
// incremental paths against a separate construction at subtree boundaries.
fn full_path(
    leaves: &[MerkleHashOrchard],
    position: usize,
) -> (MerkleHashOrchard, [MerkleHashOrchard; 32]) {
    let mut nodes = leaves.to_vec();
    let mut index = position;
    let mut siblings = [MerkleHashOrchard::empty_leaf(); 32];
    for (level, sibling) in siblings.iter_mut().enumerate() {
        let empty = MerkleHashOrchard::empty_root(Level::from(level as u8));
        *sibling = nodes.get(index ^ 1).copied().unwrap_or(empty);
        nodes = nodes
            .chunks(2)
            .map(|pair| {
                MerkleHashOrchard::combine(
                    Level::from(level as u8),
                    &pair[0],
                    pair.get(1).unwrap_or(&empty),
                )
            })
            .collect();
        index /= 2;
    }
    assert_eq!(nodes.len(), 1);
    (nodes[0], siblings)
}

#[test]
fn v4_empty_finish_reuses_authenticated_root_and_still_checks_independent_tree() {
    let wallet =
        crate::test_keys::FixtureKeys::new([43; 32], bs58::encode([44; 32]).into_string(), [7; 32]);
    let key = Arc::new(VerifyingKey::build(bundle_version().circuit_version()));
    let mut state = WalletState::with_key(&wallet, 1000, key.clone()).unwrap();
    state.pool = PoolState::new_slot_anchored(wallet.network_domain(), 1000).unwrap();
    state.finish_slot(0).unwrap();
    // Not leaf(2): the field element 2 is the empty leaf, which the pool
    // refuses as a note.
    let commitments = [leaf(1), leaf(5)];
    state.pool = state
        .pool
        .with_payment(&VerifiedPayment {
            nullifiers: [[3; 32], [4; 32]],
            commitments: commitments.map(|node| node.to_bytes()),
            public_value_balance: 0,
        })
        .unwrap();
    state.tree.append(&commitments).unwrap();
    state.spent.extend([[3; 32], [4; 32]]);
    state.finish_slot(1).unwrap();
    let root = state.pool.root();
    let checked = state.spendable_anchor().unwrap();
    assert_eq!(checked, root);
    assert_eq!(
        state.witness_at_anchor(0, checked).unwrap().auth_path(),
        state.witness(0).unwrap().auth_path()
    );
    assert!(state.witness_at_anchor(0, leaf(99).to_bytes()).is_err());
    for slot in 2..700 {
        state.finish_slot(slot).unwrap();
        let last = state.pool.slot_anchors().unwrap().entries().last().unwrap();
        assert_eq!((last.slot, last.note_count, last.root), (slot, 2, root));
    }
    assert_eq!(state.pool.slot_anchors().unwrap().entries().len(), 512);
    let before_restore = state.pool.encode();
    let mut restored = WalletState::restore_with_key(&wallet, state.snapshot(), Some(key)).unwrap();
    assert_eq!(restored.pool.encode(), before_restore);
    restored.finish_slot(700).unwrap();
    let state = &mut restored;
    let before = state.pool.encode();
    let original = state.tree.parents[31][0];
    state.tree.parents[31][0] = leaf(99);
    assert!(state.witness_at_anchor(0, root).is_err());
    assert!(state.finish_slot(701).is_err());
    assert_eq!(state.pool.encode(), before);
    state.tree.parents[31][0] = original;
    state.tree.leaves.push(leaf(3));
    assert!(state.witness_at_anchor(0, root).is_err());
    assert!(state.finish_slot(701).is_err());
    assert_eq!(state.pool.encode(), before);
    state.tree.leaves.pop();
    state.finish_slot(701).unwrap();
    let before = state.pool.encode();
    assert!(state.finish_slot(700).is_err());
    assert_eq!(state.pool.encode(), before);
    let commitments = [leaf(3), leaf(4)];
    state.pool = state
        .pool
        .with_payment(&VerifiedPayment {
            nullifiers: [[5; 32], [6; 32]],
            commitments: commitments.map(|node| node.to_bytes()),
            public_value_balance: 0,
        })
        .unwrap();
    state.tree.append(&commitments).unwrap();
    assert_ne!(state.pool.root(), root);
    assert!(state.spendable_anchor().is_err());
    assert!(state.witness_at_anchor(0, root).is_err());
    let before = state.pool.encode();
    assert!(state.finish_slot(701).is_err());
    assert_eq!(state.pool.encode(), before);
    state.finish_slot(702).unwrap();
    let last = state.pool.slot_anchors().unwrap().entries().last().unwrap();
    assert_eq!(last.note_count, 4);
    assert_eq!(last.root, state.pool.root());
}

#[test]
fn incremental_paths_match_full_history_across_subtree_boundaries() {
    let mut tree = WitnessTree::default();
    assert_eq!(tree.root(), MerkleHashOrchard::empty_root(Level::from(32)));
    assert!(tree.witness(0, tree.root().to_bytes()).is_err());
    let mut next = 0;
    for batch_size in [1, 2, 4, 8, 16, 32, 64, 128] {
        let batch: Vec<_> = (next..next + batch_size).map(leaf).collect();
        tree.append(&batch).unwrap();
        next += batch_size;
        for position in [0, tree.len() / 2, tree.len() - 1] {
            let (root, expected) = full_path(&tree.leaves, position);
            assert_eq!(tree.root(), root);
            assert_eq!(
                tree.witness(position as u32, root.to_bytes())
                    .unwrap()
                    .auth_path(),
                expected
            );
        }
        assert!(tree
            .witness(tree.len() as u32, tree.root().to_bytes())
            .is_err());
        assert!(tree.parents.iter().map(Vec::len).sum::<usize>() < tree.len() + 32);
    }
    let root = tree.root();
    tree.append(&[]).unwrap();
    assert_eq!(tree.root(), root);
}

#[test]
fn rebuilt_cache_preserves_multiple_paths_and_accepts_later_appends() {
    let leaves: Vec<_> = (0..130).map(leaf).collect();
    let mut original = WitnessTree::default();
    for pair in leaves[..126].chunks(2) {
        original.append(pair).unwrap();
    }
    let mut restored = WitnessTree::from_leaves(original.leaves.clone()).unwrap();
    for tree in [&mut original, &mut restored] {
        tree.append(&leaves[126..]).unwrap();
    }
    assert_eq!(original.root(), restored.root());
    for position in 0..leaves.len() {
        assert_eq!(
            original
                .witness(position as u32, original.root().to_bytes())
                .unwrap()
                .auth_path(),
            restored
                .witness(position as u32, original.root().to_bytes())
                .unwrap()
                .auth_path()
        );
    }
}

#[test]
fn cached_witnesses_reject_wrong_roots_and_corrupt_paths() {
    let mut tree = WitnessTree::from_leaves((0..8).map(leaf).collect()).unwrap();
    let root = tree.root().to_bytes();
    assert!(tree.witness(0, leaf(99).to_bytes()).is_err());
    tree.parents[0][0] = leaf(99);
    assert!(tree.witness(2, root).is_err());
    // A different path still independently authenticates its own leaf.
    assert!(tree.witness(0, root).is_ok());
    tree.parents[31][0] = leaf(99);
    assert!(tree.witness(0, root).is_err());
}

#[test]
fn incremental_cache_matches_native_pool_frontier() {
    let mut pool = PoolState::new([1; 32], 1000).unwrap();
    let mut tree = WitnessTree::default();
    for payment in 0..70 {
        // From 3 on: the field element 2 is the empty leaf, which the pool
        // refuses as a note.
        let commitments = [leaf(payment * 2 + 3), leaf(payment * 2 + 4)];
        pool = pool
            .with_payment(&VerifiedPayment {
                nullifiers: [[3; 32], [4; 32]],
                commitments: commitments.map(|node| node.to_bytes()),
                public_value_balance: 0,
            })
            .unwrap();
        tree.append(&commitments).unwrap();
        assert_eq!(tree.len() as u64, pool.note_count());
        assert_eq!(tree.root().to_bytes(), pool.root());
    }
    tree.witness(0, pool.root()).unwrap();
    tree.witness(139, pool.root()).unwrap();
}
