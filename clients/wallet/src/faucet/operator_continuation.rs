//! Explicit, one-shot operator exception for an exhausted native grant.
//! The legacy counter remains three. This separately journaled authorization
//! permits one additional proof preparation, never a new claim or amount.
use super::*;
use sha2::{Digest, Sha256};

const FORMAT: &str = "native-grant-operator-continuation-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: String,
    claim: Claim,
    policy_sha256: String,
    original_progress_sha256: String,
    legacy_private_attempts: u8,
    additional_preparation_authorizations: u8,
    proof_sha256: Option<String>,
}

pub(super) fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

pub(super) fn valid_pin(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn path(root: &Path, claim: &Claim) -> std::path::PathBuf {
    root.join(format!("{}.operator-continuation.json", claim.id()))
}

fn absent(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("operator continuation requires no original outcome or unresolved journal".into()),
    }
}

fn no_journals(root: &Path, claim: &Claim, operation: &WalletOperation) -> Result<()> {
    for journal in [
        &operation.pending,
        &operation.native,
        &operation.shielded,
        &operation.staging,
    ] {
        absent(journal)?;
    }
    absent(&root.join(format!("{}.outcome.json", claim.id())))
}

/// The caller holds the same worker and source-wallet locks as ordinary tick.
/// Exclusive creation is the consumed preparation authorization. Any subsequent
/// failure before a proof is persisted requires operator attention, not retry.
pub(super) fn begin(
    root: &Path,
    policy: &Policy,
    claim: &Claim,
    progress: &Progress,
    operation: &WalletOperation,
    expected_progress_sha256: &str,
) -> Result<()> {
    claim.validate(&policy.network)?;
    if !valid_pin(expected_progress_sha256)
        || !policy.native()
        || policy.private_amount != NATIVE_PRIVATE_GRANT
        || policy.gas_amount != 0
        || policy.max_attempts != ATTEMPTS
        || policy.payment_cap != PAYMENT_CAP
        || progress.private_attempts != ATTEMPTS
        || progress.proof.is_some()
        || progress.submission_started
        || progress.private_done
        || !progress.gas_done
        || progress.gas.is_some()
        || progress.gas_attempts != 0
    {
        return Err("continuation requires the exact exhausted, unsubmitted native grant".into());
    }
    no_journals(root, claim, operation)?;
    let raw = read_private(&root.join(format!("{}.json", claim.id())), 128 * 1024)?;
    let recorded: Progress = serde_json::from_slice(&raw)?;
    if digest(&raw) != expected_progress_sha256
        || serde_json::to_vec(&recorded)? != serde_json::to_vec(progress)?
    {
        return Err("operator continuation progress pin changed".into());
    }
    let intent = Intent {
        format: FORMAT.into(),
        claim: claim.clone(),
        policy_sha256: digest(&serde_json::to_vec(policy)?),
        original_progress_sha256: expected_progress_sha256.into(),
        legacy_private_attempts: ATTEMPTS,
        additional_preparation_authorizations: 1,
        proof_sha256: None,
    };
    write_private_new(&path(root, claim), &serde_json::to_vec_pretty(&intent)?)?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

fn recorded(root: &Path, policy: &Policy, claim: &Claim, progress: &Progress) -> Result<Intent> {
    let intent: Intent = serde_json::from_slice(&read_private(&path(root, claim), 16 * 1024)?)?;
    if intent.format != FORMAT
        || serde_json::to_vec(&intent.claim)? != serde_json::to_vec(claim)?
        || intent.policy_sha256 != digest(&serde_json::to_vec(policy)?)
        || !valid_pin(&intent.original_progress_sha256)
        || intent.legacy_private_attempts != ATTEMPTS
        || intent.additional_preparation_authorizations != 1
        || progress.private_attempts != ATTEMPTS
    {
        return Err("original operator continuation binding changed".into());
    }
    Ok(intent)
}

/// Seal the one newly prepared proof BEFORE publishing it in ordinary progress.
/// If interrupted before progress publication, this authorization stays consumed;
/// no proof bytes or new preparation are recovered from this hash-only intent.
pub(super) fn seal_proof(
    root: &Path,
    policy: &Policy,
    claim: &Claim,
    progress: &Progress,
    operation: &WalletOperation,
    proof: &[u8],
) -> Result<()> {
    let mut intent = recorded(root, policy, claim, progress)?;
    if intent.proof_sha256.is_some()
        || progress.proof.is_some()
        || progress.submission_started
        || progress.private_done
        || proof.len() != 9222
    {
        return Err("operator continuation cannot prepare or seal a second proof".into());
    }
    no_journals(root, claim, operation)?;
    intent.proof_sha256 = Some(digest(proof));
    save(&path(root, claim), &intent)
}

/// Ordinary tick may resume only the already sealed progress proof. Clearing an
/// expired/failed proof leaves counter three and never grants another preparation.
pub(super) fn check_progress(
    root: &Path,
    policy: &Policy,
    claim: &Claim,
    progress: &Progress,
) -> Result<()> {
    match path(root, claim).symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    let intent = recorded(root, policy, claim, progress)?;
    if let Some(proof) = &progress.proof {
        if intent.proof_sha256.as_deref() != Some(digest(proof).as_str()) {
            return Err("operator continuation cannot replace or adopt an unsealed proof".into());
        }
    }
    Ok(())
}
