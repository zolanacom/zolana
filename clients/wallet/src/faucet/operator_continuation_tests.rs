//! Filesystem/authorization guards only; no RPC, proving, grants or finality.
use super::*;

fn fixture() -> (
    tempfile::TempDir,
    Policy,
    Claim,
    Progress,
    WalletOperation,
    String,
) {
    let root = tempfile::tempdir().unwrap();
    let network = Network {
        network: [67; 32],
        genesis_hash: bs58::encode([9; 32]).into_string(),
    };
    let source = WalletKey::generate(network.clone()).unwrap();
    let recipient = WalletKey::generate(network.clone()).unwrap();
    let claim = Claim::signed(&recipient).unwrap();
    let policy = Policy {
        format: NATIVE_FAUCET_FORMAT.into(),
        network,
        source_fee_address: source.fee_keypair().pubkey().to_string(),
        source_private_address: source.address_text(),
        max_claims: 10,
        invite_required: true,
        operator_rpc: false,
        operator_unix: false,
        private_amount: NATIVE_PRIVATE_GRANT,
        gas_amount: 0,
        max_attempts: ATTEMPTS,
        payment_cap: PAYMENT_CAP,
    };
    let progress = Progress {
        gas_done: true,
        private_attempts: ATTEMPTS,
        ..Progress::default()
    };
    let path = root.path().join(format!("{}.json", claim.id()));
    save(&path, &progress).unwrap();
    let hash = operator_continuation::digest(&read_private(&path, 128 * 1024).unwrap());
    let operation = WalletOperation::acquire(&root.path().join("wallet.enc.json")).unwrap();
    (root, policy, claim, progress, operation, hash)
}

#[test]
fn one_durable_authorization_preserves_counter_and_cannot_be_repeated_after_failed_preparation() {
    let (root, policy, claim, progress, operation, hash) = fixture();
    let path = root.path().join(format!("{}.json", claim.id()));
    let original = fs::read(&path).unwrap();
    operator_continuation::begin(root.path(), &policy, &claim, &progress, &operation, &hash)
        .unwrap();
    let intent = root
        .path()
        .join(format!("{}.operator-continuation.json", claim.id()));
    let saved = read_private(&intent, 16 * 1024).unwrap();
    let value: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(value["legacy_private_attempts"], 3);
    assert_eq!(value["additional_preparation_authorizations"], 1);
    assert!(value["proof_sha256"].is_null());
    // A downstream failure/crash cannot erase this consumed authorization.
    assert!(operator_continuation::begin(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &hash
    )
    .is_err());
    assert_eq!(read_private(&intent, 16 * 1024).unwrap(), saved);
    assert_eq!(fs::read(&path).unwrap(), original);
    operator_continuation::check_progress(root.path(), &policy, &claim, &progress).unwrap();
    assert_eq!(progress.private_attempts, ATTEMPTS);
}

#[test]
fn wrong_progress_claim_policy_and_nonterminal_state_are_rejected_before_intent() {
    let (root, mut policy, mut claim, mut progress, operation, hash) = fixture();
    assert!(operator_continuation::begin(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &"0".repeat(64)
    )
    .is_err());
    for attempts in [0, 2, 4] {
        progress.private_attempts = attempts;
        assert!(operator_continuation::begin(
            root.path(),
            &policy,
            &claim,
            &progress,
            &operation,
            &hash
        )
        .is_err());
    }
    progress.private_attempts = ATTEMPTS;
    progress.submission_started = true;
    assert!(operator_continuation::begin(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &hash
    )
    .is_err());
    progress.submission_started = false;
    policy.private_amount += 1;
    assert!(operator_continuation::begin(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &hash
    )
    .is_err());
    policy.private_amount = NATIVE_PRIVATE_GRANT;
    claim.private_address.push('x');
    assert!(operator_continuation::begin(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &hash
    )
    .is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2); // original progress and source lock only
}

#[test]
fn any_original_outcome_or_unresolved_journal_prevents_the_exception() {
    for kind in [
        "pending.json",
        "native.json",
        "shielded.json",
        "staging.json",
        "outcome.json",
    ] {
        let (root, policy, claim, progress, operation, hash) = fixture();
        let path = if kind == "outcome.json" {
            root.path().join(format!("{}.outcome.json", claim.id()))
        } else {
            root.path().join(format!("wallet.enc.json.{kind}"))
        };
        write_private_new(&path, b"preserve original uncertainty").unwrap();
        assert!(
            operator_continuation::begin(
                root.path(),
                &policy,
                &claim,
                &progress,
                &operation,
                &hash
            )
            .is_err(),
            "{kind}"
        );
        assert_eq!(fs::read(path).unwrap(), b"preserve original uncertainty");
    }
}

#[test]
fn proof_seal_precedes_progress_publication_and_only_those_exact_bytes_can_resume() {
    let (root, policy, claim, mut progress, operation, hash) = fixture();
    operator_continuation::begin(root.path(), &policy, &claim, &progress, &operation, &hash)
        .unwrap();
    let proof = vec![9; 9222]; // opaque fixture, not a claimed valid transaction
    operator_continuation::seal_proof(root.path(), &policy, &claim, &progress, &operation, &proof)
        .unwrap();
    assert!(progress.proof.is_none());
    assert!(operator_continuation::seal_proof(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &proof
    )
    .is_err());
    // A crash before publication leaves no proof and grants no new preparation.
    operator_continuation::check_progress(root.path(), &policy, &claim, &progress).unwrap();
    progress.proof = Some(proof);
    save(&root.path().join(format!("{}.json", claim.id())), &progress).unwrap();
    operator_continuation::check_progress(root.path(), &policy, &claim, &progress).unwrap();
    progress.submission_started = true; // normal tick recovery may now own journals
    operator_continuation::check_progress(root.path(), &policy, &claim, &progress).unwrap();
    progress.proof.as_mut().unwrap()[0] ^= 1;
    assert!(
        operator_continuation::check_progress(root.path(), &policy, &claim, &progress).is_err()
    );
}

#[test]
fn unsealed_progress_proof_is_not_adopted_and_cleared_proof_cannot_reauthorize_preparation() {
    let (root, policy, claim, mut progress, operation, hash) = fixture();
    operator_continuation::begin(root.path(), &policy, &claim, &progress, &operation, &hash)
        .unwrap();
    progress.proof = Some(vec![2; 9222]);
    assert!(
        operator_continuation::check_progress(root.path(), &policy, &claim, &progress).is_err()
    );
    progress.proof = None;
    operator_continuation::seal_proof(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &[2; 9222],
    )
    .unwrap();
    // Normal expiry/failure may clear its packet; the consumed authorization and
    // unchanged attempt-three guard remain. No replacement proof is permitted.
    operator_continuation::check_progress(root.path(), &policy, &claim, &progress).unwrap();
    assert!(operator_continuation::begin(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &hash
    )
    .is_err());
    assert!(operator_continuation::seal_proof(
        root.path(),
        &policy,
        &claim,
        &progress,
        &operation,
        &[3; 9222]
    )
    .is_err());
}
