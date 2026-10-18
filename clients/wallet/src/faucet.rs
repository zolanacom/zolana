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
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{fs, path::Path, time::Duration};

pub const PRIVATE_GRANT: u64 = 1_000_000;
pub const GAS_GRANT: u64 = 150_000_000;
const PAYMENT_CAP: u64 = 150_000_000;
const ATTEMPTS: u8 = 3;

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

pub fn request(profile: &TesterProfile, wallet: &WalletKey) -> Result<Value> {
    profile.validate()?;
    if profile.invite_required {
        return crate::access::request_join(profile, wallet, None);
    }
    let endpoint = profile
        .faucet
        .as_ref()
        .ok_or("this profile has no test faucet")?;
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let reply = client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&Claim::signed(wallet)?)?)
        .send()?;
    if reply.status().as_u16() == 409 {
        return Err(
            "the test faucet has no grants left; an existing claim can still be checked".into(),
        );
    }
    if reply.status().as_u16() == 429 {
        return Err("please check the same test claim again in a moment".into());
    }
    if !reply.status().is_success() {
        return Err(format!(
            "test faucet unavailable (HTTP {}); checking again reuses the same claim",
            reply.status()
        )
        .into());
    }
    use std::io::Read;
    let mut body = Vec::new();
    reply.take(4097).read_to_end(&mut body)?;
    if body.len() > 4096 {
        return Err("faucet response exceeds limit".into());
    }
    let response: Value = serde_json::from_slice(&body)?;
    if response["claim_id"] != Claim::signed(wallet)?.id()
        || !matches!(
            response["state"].as_str(),
            Some("queued" | "funding" | "ready" | "needs_attention")
        )
    {
        return Err("invalid faucet receipt".into());
    }
    Ok(response)
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
    private_amount: u64,
    gas_amount: u64,
    max_attempts: u8,
    payment_cap: u64,
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
fn load(root: &Path) -> Result<(TesterProfile, Ledger)> {
    let profile = TesterProfile::load(&root.join("profile.json"))?;
    let ledger: Ledger =
        serde_json::from_slice(&read_private(&root.join("claims.json"), 1024 * 1024)?)?;
    let p = &ledger.policy;
    if p.format != "native-test-faucet-v1"
        || p.network != profile.network()
        || !(1..=100).contains(&p.max_claims)
        || p.private_amount != PRIVATE_GRANT
        || p.gas_amount != GAS_GRANT
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
    if root.exists() || !(1..=100).contains(&max_claims) {
        return Err("use a new faucet directory and 1..100 lifetime claims".into());
    }
    let profile = TesterProfile::load(profile_path)?;
    if profile.invite_required {
        return Err(
            "faucet source profile must use separate operator RPC without invitation access".into(),
        );
    }
    fs::create_dir(root)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let wallet = WalletKey::generate(profile.network())?;
    wallet.save(&root.join("wallet.enc.json"), password)?;
    wallet.save(&root.join("recovery.enc.json"), password)?;
    let policy = Policy {
        format: "native-test-faucet-v1".into(),
        network: wallet.network.clone(),
        source_fee_address: wallet.fee_keypair().pubkey().to_string(),
        source_private_address: wallet.address_text(),
        max_claims,
        invite_required: false,
        private_amount: PRIVATE_GRANT,
        gas_amount: GAS_GRANT,
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
    Ok(
        json!({"private_address":policy.source_private_address,"fee_address":policy.source_fee_address,"private_units_required":max_claims as u64 * PRIVATE_GRANT,"public_gas_grants_required":max_claims as u64 * GAS_GRANT,"additional_working_rent_required":PAYMENT_CAP,"max_claims":max_claims,"automatic_refill":false}),
    )
}
fn progress(root: &Path, id: &str) -> Result<Progress> {
    let path = root.join(format!("{id}.json"));
    let p: Progress = serde_json::from_slice(&read_private(&path, 128 * 1024)?)?;
    if p.gas_attempts > ATTEMPTS
        || p.private_attempts > ATTEMPTS
        || p.proof.as_ref().is_some_and(|b| b.len() != 9222)
        || (p.gas_done && p.gas.is_none())
        || (p.private_done && !p.gas_done)
    {
        return Err("invalid faucet progress; operator recovery required".into());
    }
    Ok(p)
}
fn status(root: &Path, claim: &Claim) -> Result<Value> {
    let p = progress(root, &claim.id())?;
    let state = if p.private_done {
        "ready"
    } else if (p.gas_attempts >= ATTEMPTS && !p.gas_done && p.gas.is_none())
        || (p.private_attempts >= ATTEMPTS && p.proof.is_none())
    {
        "needs_attention"
    } else if p.gas_attempts > 0 {
        "funding"
    } else {
        "queued"
    };
    Ok(
        json!({"claim_id":claim.id(),"state":state,"private_amount":PRIVATE_GRANT,"gas_amount":GAS_GRANT,"gas_finalized":p.gas_done,"private_finalized":p.private_done,"one_grant_per_wallet":true}),
    )
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
        return status(root, existing);
    }
    if ledger.claims.len() >= ledger.policy.max_claims {
        return Err("test faucet lifetime capacity exhausted".into());
    }
    let initial = root.join(format!("{}.json", claim.id()));
    if initial.exists() {
        let orphan = progress(root, &claim.id())?;
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
    status(root, &claim)
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
    let _worker = WalletOperation::acquire(&root.join("worker"))?;
    let (profile, ledger) = load(root)?;
    let source = root.join("wallet.enc.json");
    let wallet = WalletKey::open(&source, password, &profile.network())?;
    let payer = wallet.fee_keypair();
    if payer.pubkey().to_string() != ledger.policy.source_fee_address
        || wallet.address_text() != ledger.policy.source_private_address
    {
        return Err("faucet seed differs from original ledger".into());
    }
    let chain = Chain::connect_profile(&profile)?;
    chain.health()?;
    for claim in &ledger.claims {
        let id = claim.id();
        let path = root.join(format!("{id}.json"));
        let mut p = progress(root, &id)?;
        // Complete accepted work's rent cleanup before starting another grant.
        let outcome = root.join(format!("{id}.outcome.json"));
        let operation = WalletOperation::acquire(&source)?.with_durable_receipt(&outcome);
        if p.private_done {
            continue;
        }
        if !p.gas_done {
            gas(&chain.rpc, &payer, claim, &mut p, &path)?;
            if !p.gas_done {
                return status(root, claim);
            }
        }
        let mut chain = Chain::connect_profile(&profile)?.with_user_fees(
            payer.pubkey(),
            PAYMENT_CAP,
            &operation,
        )?;
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
            chain = Chain::connect_profile(&profile)?.with_user_fees(
                payer.pubkey(),
                cap,
                &operation,
            )?;
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
            return status(root, claim);
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
            if p.private_attempts >= ATTEMPTS {
                return status(root, claim);
            }
            p.private_attempts += 1;
            save(&path, &p)?;
            if outcome.exists() {
                fs::remove_file(&outcome)?;
                fs::File::open(root)?.sync_all()?;
            }
            let synced = chain.sync_cached(&wallet, &operation)?;
            p.proof = Some(payments::build(
                &wallet,
                &synced.state,
                payer.pubkey().to_bytes(),
                chain.expiry()?,
                Payment::Send {
                    amount: PRIVATE_GRANT,
                    recipient: &claim.private_address,
                },
            )?);
            save(&path, &p)?;
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
        return status(root, claim);
    }
    Ok(
        json!({"idle":true,"reserved_claims":ledger.claims.len(),"max_claims":ledger.policy.max_claims}),
    )
}
fn gas(
    rpc: &solana_rpc_client::rpc_client::RpcClient,
    payer: &Keypair,
    claim: &Claim,
    p: &mut Progress,
    path: &Path,
) -> Result<()> {
    let recipient: Pubkey = claim.fee_address.parse()?;
    if p.gas.is_none() {
        if p.gas_attempts >= ATTEMPTS {
            return Ok(());
        }
        let (hash, height) =
            rpc.get_latest_blockhash_with_commitment(CommitmentConfig::finalized())?;
        let tx = Transaction::new_signed_with_payer(
            &[solana_system_interface::instruction::transfer(
                &payer.pubkey(),
                &recipient,
                GAS_GRANT,
            )],
            Some(&payer.pubkey()),
            &[payer],
            hash,
        );
        let fee = rpc.get_fee_for_message(&tx.message)?;
        if fee > 10_000 {
            return Err("faucet gas transfer fee exceeds fixed limit".into());
        }
        p.gas_attempts += 1;
        p.gas = Some(Gas {
            transaction: bincode::serialize(&tx)?,
            last_valid_block_height: height,
        });
        save(path, p)?; // Full signed identity, not just a recipient balance, before broadcast.
    }
    let gas = p.gas.as_ref().ok_or("missing gas identity")?;
    let tx: Transaction = bincode::deserialize(&gas.transaction)?;
    let expected = Transaction::new_signed_with_payer(
        &[solana_system_interface::instruction::transfer(
            &payer.pubkey(),
            &recipient,
            GAS_GRANT,
        )],
        Some(&payer.pubkey()),
        &[payer],
        tx.message.recent_blockhash,
    );
    if tx != expected {
        return Err("saved gas transaction differs from fixed claim".into());
    }
    let signature = tx.signatures[0];
    let statuses = rpc.get_signature_statuses_with_history(&[signature])?;
    if let Some(s) = statuses.value.first().and_then(Option::as_ref) {
        if s.satisfies_commitment(CommitmentConfig::finalized()) {
            if s.err.is_some() {
                return Err("gas transaction failed canonically; original record retained".into());
            }
            p.gas_done = true;
            save(path, p)?;
            return Ok(());
        }
        // The original identity is already observed. Wait for canonical finality
        // or disappearance on a later tick instead of racing preflight with it.
        return Ok(());
    }
    if rpc.get_block_height_with_commitment(CommitmentConfig::finalized())?
        > gas.last_valid_block_height
    {
        // Resolve once more after the finalized expiry checkpoint before re-signing.
        if rpc
            .get_signature_statuses_with_history(&[signature])?
            .value
            .first()
            .and_then(Option::as_ref)
            .is_none()
        {
            p.gas = None;
            save(path, p)?;
            return Ok(());
        }
        return Ok(());
    }
    rpc.send_transaction_with_config(
        &tx,
        RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
            max_retries: Some(0),
            ..Default::default()
        },
    )?;
    Ok(())
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
            recipient_withdrawals: true,
            rpc: crate::connection::Endpoint {
                transport: "loopback-http".into(),
                url: "http://127.0.0.1:18899".into(),
            },
            invite_required: false,
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
            recipient_withdrawals: true,
            rpc: crate::connection::Endpoint {
                transport: "loopback-http".into(),
                url: "http://127.0.0.1:18899".into(),
            },
            invite_required: false,
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
            progress(temp.path(), "claim").unwrap().proof.unwrap().len(),
            9222
        );
        let mut exhausted = p;
        exhausted.private_attempts = ATTEMPTS + 1;
        save(&temp.path().join("claim.json"), &exhausted).unwrap();
        assert!(progress(temp.path(), "claim").is_err());
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
