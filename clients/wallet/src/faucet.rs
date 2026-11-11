//! Finite, address-bound test grants. No tester seed ever reaches the faucet.
use crate::{
    connection::TesterProfile,
    keys::{decode_address, read_private, write_private_new, Network, WalletKey},
    operation::WalletOperation,
    payments::{self, Payment},
    rpc::Chain,
    sponsor::replace,
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_commitment_config::CommitmentConfig;
#[cfg(test)]
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
#[cfg(test)]
use solana_transaction::Transaction;
#[cfg(test)]
use std::time::Duration;
use std::{fs, path::Path};

pub const PRIVATE_GRANT: u64 = 1_000_000;
pub const GAS_GRANT: u64 = 150_000_000;
pub const NATIVE_PRIVATE_GRANT: u64 = 20_000_000;
const NATIVE_FAUCET_FORMAT: &str = "native-test-faucet-native-v1";
const PAYMENT_CAP: u64 = 150_000_000;
const ATTEMPTS: u8 = 3;

mod client;
mod gas_transfer;
mod operator_continuation;

pub use client::request;
use gas_transfer::gas;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub format: String,
    pub network: Network,
    pub private_address: String,
    pub fee_address: String,
    pub signature: String,
}
impl Claim {
    fn message(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "native-test-grant-v1",
            &self.network,
            &self.private_address,
            &self.fee_address,
        ))?)
    }
    pub fn signed(wallet: &WalletKey) -> Result<Self> {
        let mut claim = Self {
            format: "native-test-grant-v1".into(),
            network: wallet.network.clone(),
            private_address: wallet.address_text(),
            fee_address: wallet.fee_keypair().pubkey().to_string(),
            signature: String::new(),
        };
        claim.signature = wallet
            .fee_keypair()
            .sign_message(&claim.message()?)
            .to_string();
        Ok(claim)
    }
    pub fn validate(&self, network: &Network) -> Result<()> {
        if self.format != "native-test-grant-v1" || &self.network != network {
            return Err("claim network/format mismatch".into());
        }
        decode_address(network, &self.private_address)?;
        let payer: Pubkey = self.fee_address.parse()?;
        if !payer.is_on_curve()
            || !self
                .signature
                .parse::<Signature>()?
                .verify(payer.as_ref(), &self.message()?)
        {
            return Err("claim address signature is invalid".into());
        }
        Ok(())
    }
    pub fn id(&self) -> String {
        blake2b_simd::Params::new()
            .hash_length(32)
            .hash(self.fee_address.as_bytes())
            .to_hex()
            .to_string()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    format: String,
    network: Network,
    source_fee_address: String,
    source_private_address: String,
    max_claims: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    invite_required: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    operator_rpc: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    operator_unix: bool,
    private_amount: u64,
    gas_amount: u64,
    max_attempts: u8,
    payment_cap: u64,
}
impl Policy {
    fn native(&self) -> bool {
        self.format == NATIVE_FAUCET_FORMAT
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    policy: Policy,
    claims: Vec<Claim>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    gas_attempts: u8,
    gas: Option<Gas>,
    gas_done: bool,
    private_attempts: u8,
    proof: Option<Vec<u8>>,
    private_done: bool,
    #[serde(default)]
    submission_started: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    signature: String,
    accepted: bool,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    expired_without_execution: bool,
}
fn read_outcome(path: &Path) -> Result<Option<bool>> {
    if !path.exists() {
        return Ok(None);
    }
    let result: Outcome = serde_json::from_slice(&read_private(path, 4096)?)?;
    result.signature.parse::<Signature>()?;
    if u8::from(result.accepted)
        + u8::from(result.failed)
        + u8::from(result.expired_without_execution)
        != 1
    {
        return Err("invalid funding outcome; preserve original claim records".into());
    }
    Ok(Some(result.accepted))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gas {
    transaction: Vec<u8>,
    last_valid_block_height: u64,
}
fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    replace(path, &serde_json::to_vec_pretty(value)?)
}

/// A native source scan is read-only readiness work, not a proof authorization.
/// Reserve the finite attempt only after that scan succeeds, immediately before
/// invoking the proof builder. A failure or crash inside the builder still
/// consumes the persisted attempt. Only an ordinary native grant calls this
/// helper; an exhausted claim can never reach either callback.
fn prepare_native_grant<S>(
    path: &Path,
    progress: &mut Progress,
    sync: impl FnOnce() -> Result<S>,
    build: impl FnOnce(S) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    if progress.private_attempts >= ATTEMPTS {
        return Err("ordinary grant proof preparation limit reached".into());
    }
    let source = sync()?;
    progress.private_attempts += 1;
    save(path, progress)?;
    build(source)
}

fn load(root: &Path) -> Result<(TesterProfile, Ledger)> {
    let profile = TesterProfile::load(&root.join("profile.json"))?;
    let ledger: Ledger =
        serde_json::from_slice(&read_private(&root.join("claims.json"), 1024 * 1024)?)?;
    let p = &ledger.policy;
    let valid_mode = match p.format.as_str() {
        "native-test-faucet-v1" => {
            (1..=100).contains(&p.max_claims)
                && p.private_amount == PRIVATE_GRANT
                && p.gas_amount == GAS_GRANT
        }
        NATIVE_FAUCET_FORMAT => {
            (1..=10).contains(&p.max_claims)
                && p.private_amount == NATIVE_PRIVATE_GRANT
                && p.gas_amount == 0
                && profile.pool_format == "NPOOL004"
                && !profile.invite_required
                && profile.private_send_transport.is_none()
        }
        _ => false,
    };
    if !valid_mode
        || p.network != profile.network()
        || p.max_attempts != ATTEMPTS
        || p.payment_cap != PAYMENT_CAP
        || ledger.claims.len() > p.max_claims
    {
        return Err("invalid faucet policy/ledger; preserve it for recovery".into());
    }
    let mut fees = std::collections::BTreeSet::new();
    for c in &ledger.claims {
        c.validate(&p.network)?;
        if !fees.insert(&c.fee_address) {
            return Err("duplicate faucet identities".into());
        }
    }
    Ok((profile, ledger))
}

pub fn initialize(
    root: &Path,
    profile_path: &Path,
    password: &[u8],
    max_claims: usize,
) -> Result<Value> {
    initialize_with_rpc(root, profile_path, password, max_claims, None)
}
pub fn initialize_with_rpc(
    root: &Path,
    profile_path: &Path,
    password: &[u8],
    max_claims: usize,
    credential: Option<&Path>,
) -> Result<Value> {
    initialize_mode(root, profile_path, password, max_claims, credential, false)
}

/// A separate finite V4 cohort. Grants use operator-paid staged private sends;
/// testers receive no public gas and their later sends use shielded fees.
pub fn initialize_native(
    root: &Path,
    profile_path: &Path,
    password: &[u8],
    max_claims: usize,
    credential: Option<&Path>,
) -> Result<Value> {
    initialize_mode(root, profile_path, password, max_claims, credential, true)
}

fn initialize_mode(
    root: &Path,
    profile_path: &Path,
    password: &[u8],
    max_claims: usize,
    credential: Option<&Path>,
    native: bool,
) -> Result<Value> {
    let material = credential
        .map(native_rpc_access::read_credential)
        .transpose()?;
    let token = credential
        .map(native_rpc_access::read_material)
        .transpose()?;
    if root.exists() || !(1..=if native { 10 } else { 100 }).contains(&max_claims) {
        if native {
            return Err("use a new native faucet directory and 1..10 lifetime claims".into());
        }
        return Err("use a new faucet directory and 1..100 lifetime claims".into());
    }
    let profile = TesterProfile::load(profile_path)?;
    let operator_port = reqwest::Url::parse(&profile.rpc.url)?
        .port()
        .ok_or("operator RPC port required");
    let operator_unix = if let Some(c) = &material {
        c.socket(operator_port?)?.is_some()
    } else {
        false
    };
    if profile.invite_required {
        return Err(
            "faucet source profile must use separate operator RPC without invitation access".into(),
        );
    }
    if native && (profile.pool_format != "NPOOL004" || profile.private_send_transport.is_some()) {
        return Err("native faucet requires an explicit NPOOL004 operator source profile".into());
    }
    fs::create_dir(root)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    if let Some(token) = &token {
        write_private_new(&root.join("rpc-access.key"), token)?;
    }
    let wallet = WalletKey::generate(profile.network())?;
    wallet.save(&root.join("wallet.enc.json"), password)?;
    wallet.save(&root.join("recovery.enc.json"), password)?;
    let policy = Policy {
        format: if native {
            NATIVE_FAUCET_FORMAT
        } else {
            "native-test-faucet-v1"
        }
        .into(),
        network: wallet.network.clone(),
        source_fee_address: wallet.fee_keypair().pubkey().to_string(),
        source_private_address: wallet.address_text(),
        max_claims,
        invite_required: false,
        operator_rpc: token.is_some(),
        operator_unix,
        private_amount: if native {
            NATIVE_PRIVATE_GRANT
        } else {
            PRIVATE_GRANT
        },
        gas_amount: if native { 0 } else { GAS_GRANT },
        max_attempts: ATTEMPTS,
        payment_cap: PAYMENT_CAP,
    };
    write_private_new(
        &root.join("profile.json"),
        &serde_json::to_vec_pretty(&profile)?,
    )?;
    write_private_new(
        &root.join("claims.json"),
        &serde_json::to_vec_pretty(&Ledger {
            policy: policy.clone(),
            claims: Vec::new(),
        })?,
    )?;
    fs::File::open(root)?.sync_all()?;
    let mut result = json!({"private_address":policy.source_private_address,"fee_address":policy.source_fee_address,"private_units_required":max_claims as u64 * policy.private_amount,"public_gas_grants_required":max_claims as u64 * policy.gas_amount,"additional_working_rent_required":PAYMENT_CAP,"max_claims":max_claims,"automatic_refill":false});
    if native {
        result["gas_required"] = false.into();
        result["conservative_public_units"] =
            (max_claims as u64 * u64::from(ATTEMPTS) * PAYMENT_CAP).into();
    }
    Ok(result)
}
fn progress(root: &Path, id: &str, policy: &Policy) -> Result<Progress> {
    read_progress(root, id, policy.native())
}
fn read_progress(root: &Path, id: &str, native: bool) -> Result<Progress> {
    let path = root.join(format!("{id}.json"));
    let p: Progress = serde_json::from_slice(&read_private(&path, 128 * 1024)?)?;
    if p.gas_attempts > ATTEMPTS
        || p.private_attempts > ATTEMPTS
        || p.proof.as_ref().is_some_and(|b| b.len() != 9222)
        || (!native && p.gas_done && p.gas.is_none())
        || (native && (p.gas_attempts != 0 || p.gas.is_some()))
        || (native
            && !p.gas_done
            && (p.private_attempts != 0 || p.proof.is_some() || p.submission_started))
        || (p.private_done && !p.gas_done)
    {
        return Err("invalid faucet progress; operator recovery required".into());
    }
    Ok(p)
}
fn status(root: &Path, claim: &Claim, policy: &Policy) -> Result<Value> {
    let p = progress(root, &claim.id(), policy)?;
    let state = if p.private_done {
        "ready"
    } else if (p.gas_attempts >= ATTEMPTS && !p.gas_done && p.gas.is_none())
        || (p.private_attempts >= ATTEMPTS && p.proof.is_none())
    {
        "needs_attention"
    } else if p.gas_attempts > 0 || (policy.native() && p.private_attempts > 0) {
        "funding"
    } else {
        "queued"
    };
    let mut result = json!({"claim_id":claim.id(),"state":state,"private_amount":policy.private_amount,"gas_amount":policy.gas_amount,"gas_finalized":p.gas_done && !policy.native(),"private_finalized":p.private_done,"one_grant_per_wallet":true});
    if policy.native() {
        result["gas_required"] = false.into();
    }
    Ok(result)
}
/// Atomically reserve a lifetime slot before starting any funding operation.
pub fn accept(root: &Path, claim: Claim) -> Result<Value> {
    let _lock = WalletOperation::acquire(&root.join("claims.json"))?;
    accept_unlocked(root, claim)
}
pub(crate) fn accept_unlocked(root: &Path, claim: Claim) -> Result<Value> {
    let (_, mut ledger) = load(root)?;
    claim.validate(&ledger.policy.network)?;
    if ledger.policy.invite_required {
        crate::access::require_member(root, &claim)?;
    }
    if claim.fee_address == ledger.policy.source_fee_address
        || claim.private_address == ledger.policy.source_private_address
    {
        return Err("faucet cannot grant to itself".into());
    }
    if let Some(existing) = ledger
        .claims
        .iter()
        .find(|c| c.fee_address == claim.fee_address)
    {
        if serde_json::to_vec(existing)? != serde_json::to_vec(&claim)? {
            return Err("this address already belongs to a different claim".into());
        }
        return status(root, existing, &ledger.policy);
    }
    if ledger.claims.len() >= ledger.policy.max_claims {
        return Err("test faucet lifetime capacity exhausted".into());
    }
    let initial = root.join(format!("{}.json", claim.id()));
    if initial.exists() {
        let orphan = progress(root, &claim.id(), &ledger.policy)?;
        if orphan.gas_attempts != 0
            || orphan.private_attempts != 0
            || orphan.gas.is_some()
            || orphan.proof.is_some()
            || orphan.gas_done
            || orphan.private_done
        {
            return Err("unexpected orphan claim; preserve it for recovery".into());
        }
    } else {
        write_private_new(&initial, &serde_json::to_vec(&Progress::default())?)?;
        fs::File::open(root)?.sync_all()?;
    }
    ledger.claims.push(claim.clone());
    save(&root.join("claims.json"), &ledger)?;
    status(root, &claim, &ledger.policy)
}

pub(crate) fn access_context(root: &Path) -> Result<(Network, usize, bool)> {
    let (_, ledger) = load(root)?;
    Ok((
        ledger.policy.network,
        ledger.policy.max_claims,
        ledger.policy.invite_required,
    ))
}
pub(crate) fn enable_invites(root: &Path) -> Result<()> {
    let (_, mut ledger) = load(root)?;
    if !ledger.claims.is_empty() || ledger.policy.invite_required {
        return Err(
            "invite setup requires an unused faucet; never reset existing claims or admission"
                .into(),
        );
    }
    ledger.policy.invite_required = true;
    save(&root.join("claims.json"), &ledger)
}

/// One serialized worker; all RPC uncertainty retains the original identities.
pub fn tick(root: &Path, password: &[u8]) -> Result<Value> {
    tick_with_history(root, password, None)
}

/// Use verified retained history only for grant proof preparation. The original
/// claim, attempt cap, proof identity and pending-operation recovery stay intact.
pub fn tick_with_history(root: &Path, password: &[u8], history: Option<&Path>) -> Result<Value> {
    tick_mode(root, password, history, None, false)
}

/// Explicit operator recovery exception: one extra preparation for this exact
/// exhausted native claim, without resetting its legacy attempt counter. This
/// returns after persisting one proof; ordinary tick owns submission/recovery.
pub fn continue_grant_once(
    root: &Path,
    password: &[u8],
    claim_id: &str,
    progress_sha256: &str,
    history: &Path,
) -> Result<Value> {
    if !operator_continuation::valid_pin(claim_id)
        || !operator_continuation::valid_pin(progress_sha256)
        || history.as_os_str().is_empty()
    {
        return Err("explicit claim ID, progress SHA-256 and retained history required".into());
    }
    tick_mode(
        root,
        password,
        Some(history),
        Some((claim_id, progress_sha256)),
        false,
    )
}

/// Verify/cache the original native source history without touching any claim,
/// intent, attempt, proof or outcome and without submitting a transaction.
pub fn warm_grant_history(root: &Path, password: &[u8], history: &Path) -> Result<Value> {
    if history.as_os_str().is_empty() {
        return Err("explicit retained history required for source warm-up".into());
    }
    tick_mode(root, password, Some(history), None, true)
}

fn tick_mode(
    root: &Path,
    password: &[u8],
    history: Option<&Path>,
    continuation: Option<(&str, &str)>,
    warm_history: bool,
) -> Result<Value> {
    let _worker = WalletOperation::acquire(&root.join("worker"))?;
    let (profile, ledger) = load(root)?;
    if warm_history && !ledger.policy.native() {
        return Err("history warm-up requires the original native source policy".into());
    }
    if let Some((id, _)) = continuation {
        if !ledger.policy.native() || !ledger.claims.iter().any(|claim| claim.id() == id) {
            return Err("continuation requires one existing native claim".into());
        }
    }
    let source = root.join("wallet.enc.json");
    let wallet = WalletKey::open(&source, password, &profile.network())?;
    let payer = wallet.fee_keypair();
    if payer.pubkey().to_string() != ledger.policy.source_fee_address
        || wallet.address_text() != ledger.policy.source_private_address
    {
        return Err("faucet seed differs from original ledger".into());
    }
    let connect = || {
        let chain = if ledger.policy.operator_rpc {
            if ledger.policy.operator_unix
                && native_rpc_access::read_credential(&root.join("rpc-access.key"))?
                    .socket(
                        reqwest::Url::parse(&profile.rpc.url)?
                            .port()
                            .ok_or("operator RPC port required")?,
                    )?
                    .is_none()
            {
                return Err("faucet private RPC transport cannot be downgraded".into());
            }
            Chain::connect_operator(
                &profile.rpc.url,
                profile.network(),
                &root.join("rpc-access.key"),
            )?
            .with_pool_format(&profile.pool_format)?
        } else {
            Chain::connect_profile(&profile)?
        };
        if ledger.policy.native() && history.is_some() {
            chain.with_operator_read_batches()
        } else {
            Ok(chain)
        }
    };
    let chain = connect()?;
    chain.health()?;
    if warm_history {
        let operation = WalletOperation::acquire(&source)?;
        operation.ensure_resolved()?;
        let synced = chain.sync_cached_with_history(
            &wallet,
            &operation,
            history.ok_or("history path missing from warm-up")?,
        )?;
        return Ok(
            json!({"warm_history":true,"balance":synced.state.balance()?,
            "finalized_slot":synced.slot,"scan":synced.scan,"grant_state_changed":false,
            "transactions_submitted":0,"local_verified_cache_may_update":true}),
        );
    }
    for claim in &ledger.claims {
        let id = claim.id();
        if continuation.is_some_and(|(selected, _)| selected != id.as_str()) {
            continue;
        }
        let path = root.join(format!("{id}.json"));
        let mut p = progress(root, &id, &ledger.policy)?;
        // Complete accepted work's rent cleanup before starting another grant.
        let outcome = root.join(format!("{id}.outcome.json"));
        let operation = WalletOperation::acquire(&source)?.with_durable_receipt(&outcome);
        if let Some((_, expected)) = continuation {
            operator_continuation::begin(root, &ledger.policy, claim, &p, &operation, expected)?;
        }
        operator_continuation::check_progress(root, &ledger.policy, claim, &p)?;
        if p.private_done {
            continue;
        }
        if !p.gas_done {
            if ledger.policy.native() {
                // Only this explicit policy may skip public tester funding.
                p.gas_done = true;
                save(&path, &p)?;
            } else {
                gas(&chain.rpc, &payer, claim, &mut p, &path)?;
            }
            if !p.gas_done {
                return status(root, claim, &ledger.policy);
            }
        }
        let mut chain = connect()?.with_user_fees(payer.pubkey(), PAYMENT_CAP, &operation)?;
        if operation.pending.exists() {
            chain.resolve(&wallet, &operation)?;
        }
        let resolution = read_outcome(&outcome)?;
        let accepted = resolution == Some(true);
        if resolution.is_none() && p.submission_started && !operation.staging.exists() {
            return Err("funding outcome and upload record are missing; preserve the original claim for operator recovery".into());
        }
        if operation.staging.exists() {
            let cap = chain
                .recovery_user_limit(&operation, payer.pubkey())?
                .ok_or("faucet stage has no original fee cap")?;
            chain = connect()?.with_user_fees(payer.pubkey(), cap, &operation)?;
            chain.reclaim(&payer, &operation)?;
            if !accepted {
                p.submission_started = false;
                p.proof = None;
                save(&path, &p)?;
            }
        }
        if accepted {
            p.private_done = true;
            save(&path, &p)?;
            return status(root, claim, &ledger.policy);
        }
        if resolution == Some(false) {
            p.submission_started = false;
            p.proof = None;
            save(&path, &p)?;
        }
        if let Some(proof) = &p.proof {
            if native_payments::wire::decode(wallet.network.network, proof)?
                .context
                .expires_at
                < chain
                    .rpc
                    .get_slot_with_commitment(CommitmentConfig::confirmed())?
            {
                p.proof = None;
                save(&path, &p)?;
            }
        }
        if p.proof.is_none() {
            if p.private_attempts >= ATTEMPTS && continuation.is_none() {
                return status(root, claim, &ledger.policy);
            }
            if continuation.is_none() && !ledger.policy.native() {
                p.private_attempts += 1;
                save(&path, &p)?;
            }
            if outcome.exists() {
                fs::remove_file(&outcome)?;
                fs::File::open(root)?.sync_all()?;
            }
            let sync = || {
                let synced = match history {
                    Some(path) => chain.sync_cached_with_history(&wallet, &operation, path)?,
                    None => chain.sync_cached(&wallet, &operation)?,
                };
                Ok((synced, chain.expiry()?))
            };
            let build = |(synced, expiry): (crate::rpc::Synced, u64)| {
                payments::build(
                    &wallet,
                    &synced.state,
                    payer.pubkey().to_bytes(),
                    expiry,
                    Payment::Send {
                        amount: ledger.policy.private_amount,
                        recipient: &claim.private_address,
                    },
                )
            };
            let proof = if ledger.policy.native() && continuation.is_none() {
                prepare_native_grant(&path, &mut p, sync, build)?
            } else {
                build(sync()?)?
            };
            if continuation.is_some() {
                operator_continuation::seal_proof(
                    root,
                    &ledger.policy,
                    claim,
                    &p,
                    &operation,
                    &proof,
                )?;
            }
            p.proof = Some(proof);
            save(&path, &p)?;
            if continuation.is_some() {
                operator_continuation::check_progress(root, &ledger.policy, claim, &p)?;
                let mut result = status(root, claim, &ledger.policy)?;
                result["explicit_operator_exception"] = true.into();
                result["additional_preparations_authorized"] = 1.into();
                result["legacy_private_attempts"] = p.private_attempts.into();
                result["proof_sha256"] =
                    operator_continuation::digest(p.proof.as_ref().unwrap()).into();
                result["transactions_submitted"] = 0.into();
                return Ok(result);
            }
        }
        p.submission_started = true;
        save(&path, &p)?;
        chain.submit(
            &payer,
            p.proof.as_ref().ok_or("missing grant proof")?,
            &operation,
        )?;
        p.private_done = !operation.staging.exists();
        save(&path, &p)?;
        return status(root, claim, &ledger.policy);
    }
    Ok(
        json!({"idle":true,"reserved_claims":ledger.claims.len(),"max_claims":ledger.policy.max_claims}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_gas_waits_for_finality_without_resending_or_resigning() {
        use solana_rpc_client::{mock_sender::Mocks, rpc_client::RpcClient};
        use solana_rpc_client_api::request::RpcRequest;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claim.json");
        let payer = Keypair::new();
        let wallet = WalletKey::generate(Network {
            network: [7; 32],
            genesis_hash: bs58::encode([9; 32]).into_string(),
        })
        .unwrap();
        let claim = Claim::signed(&wallet).unwrap();
        let tx = Transaction::new_signed_with_payer(
            &[solana_system_interface::instruction::transfer(
                &payer.pubkey(),
                &claim.fee_address.parse().unwrap(),
                GAS_GRANT,
            )],
            Some(&payer.pubkey()),
            &[&payer],
            bs58::encode([8; 32]).into_string().parse().unwrap(),
        );
        let mut p = Progress {
            gas_attempts: 1,
            gas: Some(Gas {
                transaction: bincode::serialize(&tx).unwrap(),
                last_valid_block_height: 100,
            }),
            ..Progress::default()
        };
        save(&path, &p).unwrap();
        let original = fs::read(&path).unwrap();
        for commitment in ["processed", "confirmed", "finalized"] {
            let mocks = Mocks::from_iter([(
                RpcRequest::GetSignatureStatuses,
                json!({"context":{"slot":5},"value":[{"slot":4,"confirmations":if commitment=="finalized" {None} else {Some(1)},"err":null,"status":{"Ok":null},"confirmationStatus":commitment}]}),
            )]);
            // Any unconfigured RPC call fails decoding, including block-height or submit.
            let rpc = RpcClient::new_mock_with_mocks("fails", mocks);
            gas(&rpc, &payer, &claim, &mut p, &path).unwrap();
            assert_eq!(p.gas_attempts, 1);
            assert_eq!(
                p.gas.as_ref().unwrap().transaction,
                bincode::serialize(&tx).unwrap()
            );
            assert_eq!(p.gas_done, commitment == "finalized");
            if commitment != "finalized" {
                assert_eq!(fs::read(&path).unwrap(), original);
            }
        }
    }
    #[test]
    fn lifetime_reservations_survive_restart_reject_redirection_and_missing_records() {
        let temp = tempfile::tempdir().unwrap();
        let profile = TesterProfile {
            format: "native-wallet-profile-v1".into(),
            label: "Grant test".into(),
            key_mode: "user-wallet-v1".into(),
            network: [7; 32],
            genesis_hash: bs58::encode([9; 32]).into_string(),
            program: native_payment_program::id().to_string(),
            pool: native_payment_program::pool_address().to_string(),
            pool_format: "NPOOL003".into(),
            private_send_transport: None,
            retained_history_format: None,
            access_audiences: None,
            recipient_withdrawals: true,
            rpc: crate::connection::Endpoint {
                transport: "loopback-http".into(),
                url: "http://127.0.0.1:18899".into(),
            },
            invite_required: false,
            local_tls_ca_pem: None,
            faucet: None,
        };
        let profile_path = temp.path().join("profile.json");
        fs::write(&profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let root = temp.path().join("faucet");
        initialize(&root, &profile_path, b"separate-test-password", 1).unwrap();
        let a = WalletKey::generate(profile.network()).unwrap();
        let b = WalletKey::generate(profile.network()).unwrap();
        let c = Claim::signed(&a).unwrap();
        let first = accept(&root, c.clone()).unwrap();
        let ledger = fs::read(root.join("claims.json")).unwrap();
        for _ in 0..3 {
            assert_eq!(accept(&root, c.clone()).unwrap(), first);
        }
        assert_eq!(fs::read(root.join("claims.json")).unwrap(), ledger);
        let mut redirected = Claim::signed(&b).unwrap();
        redirected.private_address = a.address_text();
        redirected.signature = b
            .fee_keypair()
            .sign_message(&redirected.message().unwrap())
            .to_string();
        assert!(accept(&root, redirected).is_err());
        assert!(accept(&root, Claim::signed(&b).unwrap()).is_err());
        assert!(initialize(&root, &profile_path, b"separate-test-password", 1).is_err());
        let lock = WalletOperation::acquire(&root.join("claims.json")).unwrap();
        assert!(accept(&root, c.clone()).is_err());
        drop(lock);
        fs::remove_file(root.join(format!("{}.json", c.id()))).unwrap();
        assert!(accept(&root, c).is_err());
        assert_eq!(fs::read(root.join("claims.json")).unwrap(), ledger);
    }
    #[test]
    fn knowing_a_private_receiving_address_cannot_reserve_its_owners_fee_claim() {
        let temp = tempfile::tempdir().unwrap();
        let profile = TesterProfile {
            format: "native-wallet-profile-v1".into(),
            label: "Admission test".into(),
            key_mode: "user-wallet-v1".into(),
            network: [7; 32],
            genesis_hash: bs58::encode([9; 32]).into_string(),
            program: native_payment_program::id().to_string(),
            pool: native_payment_program::pool_address().to_string(),
            pool_format: "NPOOL003".into(),
            private_send_transport: None,
            retained_history_format: None,
            access_audiences: None,
            recipient_withdrawals: true,
            rpc: crate::connection::Endpoint {
                transport: "loopback-http".into(),
                url: "http://127.0.0.1:18899".into(),
            },
            invite_required: false,
            local_tls_ca_pem: None,
            faucet: None,
        };
        let path = temp.path().join("profile.json");
        fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let root = temp.path().join("faucet");
        initialize(&root, &path, b"separate-test-password", 2).unwrap();
        let owner = WalletKey::generate(profile.network()).unwrap();
        let other = WalletKey::generate(profile.network()).unwrap();
        let mut gift = Claim::signed(&other).unwrap();
        gift.private_address = owner.address_text();
        gift.signature = other
            .fee_keypair()
            .sign_message(&gift.message().unwrap())
            .to_string();
        accept(&root, gift).unwrap();
        let original = Claim::signed(&owner).unwrap();
        accept(&root, original.clone()).unwrap();
        let mut redirected = original.clone();
        redirected.private_address = other.address_text();
        redirected.signature = owner
            .fee_keypair()
            .sign_message(&redirected.message().unwrap())
            .to_string();
        assert!(accept(&root, redirected).is_err());
        assert_eq!(accept(&root, original).unwrap()["state"], "queued");
        assert_eq!(load(&root).unwrap().1.claims.len(), 2);
    }
    #[test]
    fn proof_progress_roundtrips_within_a_bounded_owner_only_file() {
        let temp = tempfile::tempdir().unwrap();
        let p = Progress {
            private_attempts: 1,
            proof: Some(vec![255; 9222]),
            ..Progress::default()
        };
        save(&temp.path().join("claim.json"), &p).unwrap();
        assert!(fs::metadata(temp.path().join("claim.json")).unwrap().len() > 64 * 1024);
        assert_eq!(
            read_progress(temp.path(), "claim", false)
                .unwrap()
                .proof
                .unwrap()
                .len(),
            9222
        );
        let mut exhausted = p;
        exhausted.private_attempts = ATTEMPTS + 1;
        save(&temp.path().join("claim.json"), &exhausted).unwrap();
        assert!(read_progress(temp.path(), "claim", false).is_err());
    }
    #[test]
    fn incomplete_or_conflicting_outcomes_are_never_treated_as_unpaid() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("outcome");
        for value in [
            json!({}),
            json!({"signature":Signature::default().to_string(),"accepted":false}),
            json!({"signature":Signature::default().to_string(),"accepted":true,"failed":true}),
        ] {
            save(&path, &value).unwrap();
            assert!(read_outcome(&path).is_err());
        }
        save(
            &path,
            &json!({"signature":Signature::default().to_string(),"accepted":true}),
        )
        .unwrap();
        assert_eq!(read_outcome(&path).unwrap(), Some(true));
    }
    #[test]
    fn signatures_bind_network_both_addresses_and_version() {
        let network = Network {
            network: [7; 32],
            genesis_hash: bs58::encode([9; 32]).into_string(),
        };
        let a = WalletKey::generate(network.clone()).unwrap();
        let b = WalletKey::generate(network.clone()).unwrap();
        let c = Claim::signed(&a).unwrap();
        c.validate(&network).unwrap();
        let mut redirected = c.clone();
        redirected.private_address = b.address_text();
        assert!(redirected.validate(&network).is_err());
        redirected = c.clone();
        redirected.fee_address = b.fee_keypair().pubkey().to_string();
        assert!(redirected.validate(&network).is_err());
        redirected = c.clone();
        redirected.format = "other".into();
        assert!(redirected.validate(&network).is_err());
        let mut other = network;
        other.network = [8; 32];
        assert!(c.validate(&other).is_err());
        assert_eq!(
            serde_json::to_vec(&Claim::signed(&a).unwrap()).unwrap(),
            serde_json::to_vec(&c).unwrap()
        );
    }
}

#[cfg(test)]
#[path = "faucet/native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "faucet/operator_continuation_tests.rs"]
mod operator_continuation_tests;

#[cfg(test)]
#[path = "faucet/attempt_tests.rs"]
mod attempt_tests;
