//! Invite admission and durable gateway quotas. No wallet spending authority is exported.
use crate::{
    connection::TesterProfile,
    faucet::{self, Claim},
    keys::{read_private, write_private_new, Network, WalletKey},
    operation::WalletOperation,
    sponsor::replace,
    Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use std::{
    fs,
    path::Path,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const STATE: &str = "admission.json";
const MEMBERSHIP_SECONDS: u64 = 7 * 86400;
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn digest(bytes: &[u8]) -> String {
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(bytes)
        .to_hex()
        .to_string()
}
fn lock(root: &Path) -> Result<WalletOperation> {
    let start = Instant::now();
    loop {
        match WalletOperation::acquire(&root.join("claims.json")) {
            Ok(l) => return Ok(l),
            Err(e) if start.elapsed() > Duration::from_secs(2) => return Err(e),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    purpose: String,
    network: Network,
    audience: String,
    fee_address: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
    body_digest: String,
    signature: String,
}
impl Proof {
    fn message(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "native-invited-access-v1",
            &self.purpose,
            &self.network,
            &self.audience,
            &self.fee_address,
            self.issued_at,
            self.expires_at,
            &self.nonce,
            &self.body_digest,
        ))?)
    }
    pub fn signed(wallet: &WalletKey, audience: &str, purpose: &str, body: &[u8]) -> Result<Self> {
        Self::signed_at(wallet, audience, purpose, body, now()?)
    }
    fn signed_at(
        wallet: &WalletKey,
        audience: &str,
        purpose: &str,
        body: &[u8],
        time: u64,
    ) -> Result<Self> {
        let mut proof = Self {
            purpose: purpose.into(),
            network: wallet.network.clone(),
            audience: audience.into(),
            fee_address: wallet.fee_keypair().pubkey().to_string(),
            issued_at: time,
            expires_at: time.checked_add(600).ok_or("clock overflow")?,
            nonce: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>()),
            body_digest: digest(body),
            signature: String::new(),
        };
        proof.signature = wallet
            .fee_keypair()
            .sign_message(&proof.message()?)
            .to_string();
        Ok(proof)
    }
    fn verify(&self, policy: &Policy, purpose: &str, body: &[u8], time: u64) -> Result<()> {
        let audience = if purpose == "rpc" {
            &policy.rpc_audience
        } else {
            &policy.faucet_audience
        };
        if self.network != policy.network
            || self.purpose != purpose
            || &self.audience != audience
            || self.nonce.len() != 32
            || self.body_digest != digest(body)
            || self.expires_at != self.issued_at.checked_add(600).ok_or("clock overflow")?
            || self.issued_at > time.saturating_add(30)
            || self.expires_at <= time
        {
            return Err("access proof invalid or expired".into());
        }
        let key: Pubkey = self.fee_address.parse()?;
        if !key.is_on_curve()
            || !self
                .signature
                .parse::<Signature>()?
                .verify(key.as_ref(), &self.message()?)
        {
            return Err("access proof signature invalid".into());
        }
        Ok(())
    }
    pub fn header(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Join {
    pub claim: Claim,
    pub invitation: Option<String>,
    pub proof: Proof,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub proof: Proof,
}
fn join_body(claim: &Claim, invitation: Option<&str>) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(claim, invitation))?)
}
fn post(profile: &TesterProfile, suffix: &str, body: Vec<u8>) -> Result<Value> {
    profile.validate()?;
    let endpoint = profile.faucet.as_ref().ok_or("no admission endpoint")?;
    let mut client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20));
    if let Some(pem) = &profile.local_tls_ca_pem {
        client = client.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?);
    }
    let response = client
        .build()?
        .post(format!("{}{suffix}", endpoint.url.trim_end_matches('/')))
        .header("Content-Type", "application/json")
        .body(body)
        .send()?;
    if !response.status().is_success() {
        return Err(match response.status().as_u16(){403=>"Invitation or access is invalid, expired, revoked or already bound to another wallet.",429=>"Testnet request limit reached. Wait before checking the same wallet again.",409=>"Testnet admission capacity reached. An existing grant is preserved.",_=>"Testnet access service unavailable. Your original wallet and grant remain saved."}.into());
    }
    use std::io::Read;
    let mut data = Vec::new();
    response.take(4097).read_to_end(&mut data)?;
    if data.len() > 4096 {
        return Err("admission response exceeds limit".into());
    }
    Ok(serde_json::from_slice(&data)?)
}
pub fn request_join(
    profile: &TesterProfile,
    wallet: &WalletKey,
    invitation: Option<String>,
) -> Result<Value> {
    let claim = Claim::signed(wallet)?;
    let endpoint = profile.faucet.as_ref().ok_or("no admission endpoint")?;
    let proof = Proof::signed(
        wallet,
        &endpoint.url,
        "join",
        &join_body(&claim, invitation.as_deref())?,
    )?;
    let value = post(
        profile,
        "/join",
        serde_json::to_vec(&Join {
            claim: claim.clone(),
            invitation,
            proof,
        })?,
    )?;
    if value["claim_id"] != claim.id() || value["admitted"] != true {
        return Err("invalid admission receipt".into());
    }
    Ok(value)
}
pub fn request_status(profile: &TesterProfile, wallet: &WalletKey) -> Result<Value> {
    let endpoint = profile.faucet.as_ref().ok_or("no admission endpoint")?;
    let value = post(
        profile,
        "/status",
        serde_json::to_vec(&Status {
            proof: Proof::signed(wallet, &endpoint.url, "status", b"")?,
        })?,
    )?;
    if !value["admitted"].is_boolean()
        || value["fee_address"] != wallet.fee_keypair().pubkey().to_string()
    {
        return Err("invalid membership response".into());
    }
    Ok(value)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    format: String,
    network: Network,
    rpc_audience: String,
    faucet_audience: String,
    max_invites: usize,
    daily_admissions: usize,
    rpc_per_minute: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    id: String,
    redeem_by: u64,
    bound_fee: Option<String>,
    revoked: bool,
    member: Option<Member>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    claim: Claim,
    admitted_at: u64,
    access_until: u64,
    rpc: Bucket,
    faucet: Bucket,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    period: u64,
    count: u64,
}
impl Bucket {
    fn take(&mut self, period: u64, limit: u64) -> Result<()> {
        self.take_units(period, limit, 1)
    }
    fn take_units(&mut self, period: u64, limit: u64, units: u64) -> Result<()> {
        if !(1..=16).contains(&units) {
            return Err("invalid request units".into());
        }
        if period < self.period {
            return Err("clock moved backwards; preserve admission state".into());
        }
        if period > self.period {
            self.period = period;
            self.count = 0;
        }
        if self
            .count
            .checked_add(units)
            .is_none_or(|count| count > limit)
        {
            return Err("request quota exhausted".into());
        }
        self.count += units;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Edge {
    channel: String,
    peer: String,
    bucket: Bucket,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    policy: Policy,
    last_time: u64,
    admissions: Bucket,
    global_rpc: Bucket,
    global_faucet: Bucket,
    edge: Vec<Edge>,
    invitations: Vec<Invitation>,
}
fn load(root: &Path) -> Result<State> {
    let (network, capacity, required) = faucet::access_context(root)?;
    if !required {
        return Err("invite admission is not enabled".into());
    }
    let state: State = serde_json::from_slice(&read_private(&root.join(STATE), 1024 * 1024)?)?;
    let p = &state.policy;
    if p.format != "native-invited-testnet-v1"
        || p.network != network
        || p.max_invites == 0
        || p.max_invites > capacity
        || p.daily_admissions == 0
        || p.daily_admissions > p.max_invites
        || !(1..=10000).contains(&p.rpc_per_minute)
        || state.invitations.len() > p.max_invites
        || state.edge.len() > 512
    {
        return Err("invalid admission policy/state; preserve original files".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut members = std::collections::BTreeSet::new();
    for invitation in &state.invitations {
        if invitation.id.len() != 64 || !ids.insert(&invitation.id) {
            return Err("duplicate/invalid invitation identity".into());
        }
        if let Some(m) = &invitation.member {
            m.claim.validate(&network)?;
            if !members.insert(&m.claim.fee_address)
                || m.access_until
                    != m.admitted_at
                        .checked_add(MEMBERSHIP_SECONDS)
                        .ok_or("membership overflow")?
                || m.admitted_at > state.last_time
                || invitation
                    .bound_fee
                    .as_ref()
                    .is_some_and(|b| b != &m.claim.fee_address)
            {
                return Err("invalid redeemed invitation".into());
            }
        }
    }
    Ok(state)
}
fn save(root: &Path, state: &State) -> Result<()> {
    replace(&root.join(STATE), &serde_json::to_vec_pretty(state)?)
}
fn clock(state: &mut State, time: u64) -> Result<u64> {
    if time.saturating_add(30) < state.last_time {
        return Err("clock moved backwards; preserve admission state".into());
    }
    state.last_time = state.last_time.max(time);
    Ok(state.last_time)
}
fn member_index(state: &State, fee: &str) -> Option<usize> {
    state.invitations.iter().position(|i| {
        i.member
            .as_ref()
            .is_some_and(|m| m.claim.fee_address == fee)
    })
}
fn active(invitation: &Invitation, time: u64) -> Result<&Member> {
    if invitation.revoked {
        return Err("invitation revoked".into());
    }
    let m = invitation.member.as_ref().ok_or("invitation required")?;
    if m.access_until <= time {
        return Err("membership expired".into());
    }
    Ok(m)
}

pub fn initialize(root: &Path, profile_path: &Path, daily: usize, rpc_limit: u64) -> Result<Value> {
    let _lock = lock(root)?;
    let profile = TesterProfile::load(profile_path)?;
    let source = TesterProfile::load(&root.join("profile.json"))?;
    let (network, capacity, required) = faucet::access_context(root)?;
    if required
        || !profile.invite_required
        || profile.rpc.url == source.rpc.url
        || profile.network() != network
        || daily == 0
        || daily > capacity
        || !(1..=10000).contains(&rpc_limit)
        || root.join(STATE).symlink_metadata().is_ok()
    {
        return Err(
            "new admission setup requires an unused compatible faucet and invited profile".into(),
        );
    }
    let state = State {
        policy: Policy {
            format: "native-invited-testnet-v1".into(),
            network,
            rpc_audience: profile.rpc.url,
            faucet_audience: profile.faucet.ok_or("admission endpoint required")?.url,
            max_invites: capacity,
            daily_admissions: daily,
            rpc_per_minute: rpc_limit,
        },
        last_time: now()?,
        admissions: Bucket::default(),
        global_rpc: Bucket::default(),
        global_faucet: Bucket::default(),
        edge: Vec::new(),
        invitations: Vec::new(),
    };
    // Enable the permanent fail-closed marker before creating any admission data.
    faucet::enable_invites(root)?;
    write_private_new(&root.join(STATE), &serde_json::to_vec_pretty(&state)?)?;
    fs::File::open(root)?.sync_all()?;
    Ok(
        json!({"invite_required":true,"max_invites":capacity,"daily_admissions":daily,"rpc_per_minute":rpc_limit}),
    )
}
pub fn info(root: &Path) -> Result<Value> {
    let (_, _, required) = faucet::access_context(root)?;
    if !required {
        return Ok(json!({"invite_required":false}));
    }
    let state = load(root)?;
    Ok(
        json!({"invite_required":true,"rpc_audience":state.policy.rpc_audience,"faucet_audience":state.policy.faucet_audience,"network":state.policy.network,"issued":state.invitations.len(),"max_invites":state.policy.max_invites}),
    )
}
pub fn issue(root: &Path, output: &Path, ttl: u64, bound_fee: Option<String>) -> Result<Value> {
    issue_at(root, output, ttl, bound_fee, now()?)
}
fn issue_at(
    root: &Path,
    output: &Path,
    ttl: u64,
    bound_fee: Option<String>,
    time: u64,
) -> Result<Value> {
    let _lock = lock(root)?;
    let mut state = load(root)?;
    let time = clock(&mut state, time)?;
    if !(1..=7 * 86400).contains(&ttl)
        || output.symlink_metadata().is_ok()
        || state.invitations.len() >= state.policy.max_invites
    {
        return Err("invitation issuance capacity/TTL/output invalid".into());
    }
    if let Some(fee) = &bound_fee {
        if !fee.parse::<Pubkey>()?.is_on_curve() {
            return Err("bound fee authority invalid".into());
        }
    }
    let token = format!(
        "invite1_{}",
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    );
    let id = digest(token.as_bytes());
    let redeem_by = time.checked_add(ttl).ok_or("expiry overflow")?;
    // The raw code is exported once to a new owner-only file, never the server ledger/log.
    write_private_new(
        output,
        &serde_json::to_vec(&json!({"invitation":token,"invite_id":id,"redeem_by":redeem_by}))?,
    )?;
    fs::File::open(output.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    state.invitations.push(Invitation {
        id: id.clone(),
        redeem_by,
        bound_fee,
        revoked: false,
        member: None,
    });
    save(root, &state)?;
    Ok(json!({"invite_id":id,"redeem_by":redeem_by,"code_written":true}))
}
pub fn revoke(root: &Path, id: &str) -> Result<Value> {
    let _lock = lock(root)?;
    let mut state = load(root)?;
    clock(&mut state, now()?)?;
    state
        .invitations
        .iter_mut()
        .find(|i| i.id == id)
        .ok_or("unknown invitation")?
        .revoked = true;
    save(root, &state)?;
    Ok(json!({"revoked":true,"invite_id":id}))
}

pub fn join(root: &Path, request: Join) -> Result<Value> {
    join_at(root, request, now()?)
}
fn join_at(root: &Path, request: Join, time: u64) -> Result<Value> {
    let _lock = lock(root)?;
    let mut state = load(root)?;
    let time = clock(&mut state, time)?;
    request.claim.validate(&state.policy.network)?;
    request.proof.verify(
        &state.policy,
        "join",
        &join_body(&request.claim, request.invitation.as_deref())?,
        time,
    )?;
    if request.proof.fee_address != request.claim.fee_address {
        return Err("claim and access authority mismatch".into());
    }
    let index = if let Some(index) = member_index(&state, &request.claim.fee_address) {
        let m = active(&state.invitations[index], time)?;
        if serde_json::to_vec(&m.claim)? != serde_json::to_vec(&request.claim)? {
            return Err("original invited claim cannot be changed".into());
        }
        index
    } else {
        let token = request.invitation.as_deref().ok_or("invitation required")?;
        if !token.starts_with("invite1_") || token.len() != 51 {
            return Err("invitation invalid".into());
        }
        let id = digest(token.as_bytes());
        let index = state
            .invitations
            .iter()
            .position(|i| i.id == id)
            .ok_or("invitation invalid")?;
        let invitation = &state.invitations[index];
        if invitation.revoked
            || invitation.member.is_some()
            || invitation.redeem_by <= time
            || invitation
                .bound_fee
                .as_ref()
                .is_some_and(|b| b != &request.claim.fee_address)
        {
            return Err("invitation expired, revoked or already bound".into());
        }
        state
            .admissions
            .take(time / 86400, state.policy.daily_admissions as u64)?;
        state.invitations[index].member = Some(Member {
            claim: request.claim.clone(),
            admitted_at: time,
            access_until: time
                .checked_add(MEMBERSHIP_SECONDS)
                .ok_or("expiry overflow")?,
            rpc: Bucket::default(),
            faucet: Bucket::default(),
        });
        index
    };
    state.global_faucet.take(time / 60, 120)?;
    state.invitations[index]
        .member
        .as_mut()
        .ok_or("missing member")?
        .faucet
        .take(time / 60, 30)?;
    save(root, &state)?; // Redemption and budget survive a crash before claim reservation.
    let until = state.invitations[index]
        .member
        .as_ref()
        .ok_or("missing member")?
        .access_until;
    let mut result = faucet::accept_unlocked(root, request.claim)?;
    result["admitted"] = true.into();
    result["access_until"] = until.into();
    Ok(result)
}
pub(crate) fn require_member(root: &Path, claim: &Claim) -> Result<()> {
    let mut state = load(root)?;
    let time = clock(&mut state, now()?)?;
    let i = member_index(&state, &claim.fee_address).ok_or("invitation required")?;
    let m = active(&state.invitations[i], time)?;
    if serde_json::to_vec(&m.claim)? != serde_json::to_vec(claim)? {
        return Err("original membership claim differs".into());
    }
    Ok(())
}
pub fn status(root: &Path, proof: Proof) -> Result<Value> {
    let _lock = lock(root)?;
    let mut state = load(root)?;
    let time = clock(&mut state, now()?)?;
    proof.verify(&state.policy, "status", b"", time)?;
    state.global_faucet.take(time / 60, 120)?;
    let mut name = "not_invited";
    let mut until = None;
    if let Some(i) = member_index(&state, &proof.fee_address) {
        let invitation = &mut state.invitations[i];
        let m = invitation.member.as_mut().ok_or("missing member")?;
        m.faucet.take(time / 60, 30)?;
        name = if invitation.revoked {
            "revoked"
        } else if m.access_until <= time {
            "expired"
        } else {
            "active"
        };
        until = Some(m.access_until);
    }
    save(root, &state)?;
    Ok(
        json!({"admitted":name=="active","state":name,"fee_address":proof.fee_address,"access_until":until}),
    )
}
pub fn authorize(root: &Path, proof: Proof) -> Result<Value> {
    authorize_at(root, proof, now()?)
}
fn authorize_at(root: &Path, proof: Proof, time: u64) -> Result<Value> {
    authorize_units_at(root, proof, time, 1)
}
pub fn authorize_units(root: &Path, proof: Proof, units: u64) -> Result<Value> {
    authorize_units_at(root, proof, now()?, units)
}
fn authorize_units_at(root: &Path, proof: Proof, time: u64, units: u64) -> Result<Value> {
    let _lock = lock(root)?;
    let mut state = load(root)?;
    let time = clock(&mut state, time)?;
    proof.verify(&state.policy, "rpc", b"", time)?;
    let i = member_index(&state, &proof.fee_address).ok_or("invitation required")?;
    active(&state.invitations[i], time)?;
    state.global_rpc.take_units(time / 60, 6000, units)?;
    let limit = state.policy.rpc_per_minute;
    state.invitations[i]
        .member
        .as_mut()
        .ok_or("missing member")?
        .rpc
        .take_units(time / 60, limit, units)?;
    save(root, &state)?;
    Ok(json!({"authorized":true}))
}
pub fn edge(root: &Path, channel: &str, peer: &str) -> Result<Value> {
    let _lock = lock(root)?;
    let mut state = load(root)?;
    let time = clock(&mut state, now()?)?;
    if !matches!(channel, "rpc" | "faucet")
        || peer.len() > 64
        || peer.parse::<std::net::IpAddr>().is_err()
    {
        return Err("invalid ingress identity".into());
    }
    state.edge.retain(|e| e.bucket.period == time / 60);
    let hash = digest(peer.as_bytes());
    let limit = if channel == "rpc" { 3000 } else { 240 };
    for name in ["global", &hash] {
        let index = if let Some(i) = state
            .edge
            .iter()
            .position(|e| e.channel == channel && e.peer == name)
        {
            i
        } else {
            if state.edge.len() >= 512 {
                return Err("request quota exhausted".into());
            }
            state.edge.push(Edge {
                channel: channel.into(),
                peer: name.into(),
                bucket: Bucket::default(),
            });
            state.edge.len() - 1
        };
        state.edge[index]
            .bucket
            .take(time / 60, if name == "global" { limit * 2 } else { limit })?;
    }
    save(root, &state)?;
    Ok(json!({"allowed":true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(
        capacity: usize,
        daily: usize,
        rpc: u64,
    ) -> (tempfile::TempDir, std::path::PathBuf, TesterProfile) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("faucet");
        let mut profile = TesterProfile {
            format: "native-wallet-profile-v1".into(),
            label: "Invited access".into(),
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
            faucet: Some(crate::connection::Endpoint {
                transport: "loopback-http".into(),
                url: "http://127.0.0.1:8780".into(),
            }),
            invite_required: false,
            local_tls_ca_pem: None,
        };
        let file = dir.path().join("profile.json");
        fs::write(&file, serde_json::to_vec(&profile).unwrap()).unwrap();
        faucet::initialize(&root, &file, b"dedicated-faucet-password", capacity).unwrap();
        profile.invite_required = true;
        profile.rpc.url = "http://127.0.0.1:18898".into();
        fs::write(&file, serde_json::to_vec(&profile).unwrap()).unwrap();
        initialize(&root, &file, daily, rpc).unwrap();
        (dir, root, profile)
    }
    fn token(root: &Path, name: &str, ttl: u64, bound: Option<String>) -> String {
        let file = root.join(name);
        issue(root, &file, ttl, bound).unwrap();
        serde_json::from_slice::<Value>(&read_private(&file, 512).unwrap()).unwrap()["invitation"]
            .as_str()
            .unwrap()
            .into()
    }
    fn joined(
        wallet: &WalletKey,
        profile: &TesterProfile,
        token: Option<String>,
        time: u64,
    ) -> Join {
        let claim = Claim::signed(wallet).unwrap();
        let proof = Proof::signed_at(
            wallet,
            &profile.faucet.as_ref().unwrap().url,
            "join",
            &join_body(&claim, token.as_deref()).unwrap(),
            time,
        )
        .unwrap();
        Join {
            claim,
            invitation: token,
            proof,
        }
    }
    #[test]
    fn block_units_are_durable_bounded_and_cannot_bypass_limits_or_revocation() {
        let (_dir, root, profile) = fixture(1, 1, 20);
        let wallet = WalletKey::generate(profile.network()).unwrap();
        let code = token(&root, "invite", 3600, None);
        let time = now().unwrap();
        join(&root, joined(&wallet, &profile, Some(code), time)).unwrap();
        let proof = || Proof::signed_at(&wallet, &profile.rpc.url, "rpc", b"", time).unwrap();
        authorize_units_at(&root, proof(), time, 16).unwrap();
        let original = fs::read(root.join(STATE)).unwrap();
        for units in [0, 5, 17, u64::MAX] {
            assert!(authorize_units_at(&root, proof(), time, units).is_err());
            assert_eq!(fs::read(root.join(STATE)).unwrap(), original);
        }
        authorize_units_at(&root, proof(), time, 4).unwrap();
        assert_eq!(load(&root).unwrap().global_rpc.count, 20);
        assert_eq!(
            load(&root).unwrap().invitations[0]
                .member
                .as_ref()
                .unwrap()
                .rpc
                .count,
            20
        );
        assert!(authorize_units_at(&root, proof(), time, 1).is_err());
        let id = load(&root).unwrap().invitations[0].id.clone();
        revoke(&root, &id).unwrap();
        assert!(authorize_units_at(&root, proof(), time + 60, 16).is_err());
    }

    #[test]
    fn redemption_binds_once_resumes_after_missing_claim_commit_and_never_exports_raw_codes() {
        let (_dir, root, profile) = fixture(2, 2, 5);
        let a = WalletKey::generate(profile.network()).unwrap();
        let b = WalletKey::generate(profile.network()).unwrap();
        let code = token(&root, "invite", 3600, None);
        let time = now().unwrap();
        // Emulate the durable redemption checkpoint before faucet reservation.
        {
            let _lock = lock(&root).unwrap();
            let mut state = load(&root).unwrap();
            let index = state
                .invitations
                .iter()
                .position(|i| i.id == digest(code.as_bytes()))
                .unwrap();
            state.last_time = time;
            state.admissions.take(time / 86400, 2).unwrap();
            state.invitations[index].member = Some(Member {
                claim: Claim::signed(&a).unwrap(),
                admitted_at: time,
                access_until: time + MEMBERSHIP_SECONDS,
                rpc: Bucket::default(),
                faucet: Bucket::default(),
            });
            save(&root, &state).unwrap();
        }
        let result = join(&root, joined(&a, &profile, None, time)).unwrap();
        assert_eq!(result["state"], "queued");
        assert!(join(&root, joined(&b, &profile, Some(code.clone()), time)).is_err());
        for _ in 0..3 {
            assert_eq!(
                join(&root, joined(&a, &profile, None, time)).unwrap()["claim_id"],
                result["claim_id"]
            );
        }
        let state = load(&root).unwrap();
        assert_eq!(state.admissions.count, 1);
        assert_eq!(
            state
                .invitations
                .iter()
                .filter(|i| i.member.is_some())
                .count(),
            1
        );
        assert!(
            !String::from_utf8_lossy(&read_private(&root.join(STATE), 1024 * 1024).unwrap())
                .contains(&code)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(
                &read_private(&root.join("claims.json"), 1024 * 1024).unwrap()
            )
            .unwrap()["claims"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn expiry_binding_revocation_and_gateway_scope_fail_closed() {
        let (_dir, root, profile) = fixture(3, 3, 5);
        let a = WalletKey::generate(profile.network()).unwrap();
        let b = WalletKey::generate(profile.network()).unwrap();
        let time = now().unwrap();
        let short = token(&root, "expired", 1, None);
        assert!(join_at(&root, joined(&a, &profile, Some(short), time + 3), time + 3).is_err());
        let code = token(
            &root,
            "bound",
            3600,
            Some(a.fee_keypair().pubkey().to_string()),
        );
        assert!(join(&root, joined(&b, &profile, Some(code.clone()), time)).is_err());
        let mut altered = joined(&a, &profile, Some(code.clone()), time);
        altered.claim.private_address = b.address_text();
        assert!(join(&root, altered).is_err());
        join(&root, joined(&a, &profile, Some(code.clone()), time)).unwrap();
        let proof = Proof::signed_at(&a, &profile.rpc.url, "rpc", b"", time).unwrap();
        authorize(&root, proof.clone()).unwrap();
        let mut wrong = proof.clone();
        wrong.audience = profile.faucet.as_ref().unwrap().url.clone();
        assert!(authorize(&root, wrong).is_err());
        assert!(authorize_at(&root, proof.clone(), time + 601).is_err());
        revoke(&root, &digest(code.as_bytes())).unwrap();
        assert!(authorize(&root, proof).is_err());
        assert!(join(&root, joined(&a, &profile, None, time)).is_err());
        assert!(faucet::accept(&root, Claim::signed(&b).unwrap()).is_err());
    }
    #[test]
    fn daily_and_rpc_quotas_persist_without_restart_refills_or_clock_rollback() {
        let (_dir, root, profile) = fixture(3, 1, 2);
        let a = WalletKey::generate(profile.network()).unwrap();
        let b = WalletKey::generate(profile.network()).unwrap();
        let time = now().unwrap();
        let first = token(&root, "a", 3600, None);
        let second = token(&root, "b", 3600, None);
        join(&root, joined(&a, &profile, Some(first), time)).unwrap();
        assert!(join(&root, joined(&b, &profile, Some(second), time))
            .unwrap_err()
            .to_string()
            .contains("quota"));
        let proof = Proof::signed_at(&a, &profile.rpc.url, "rpc", b"", time).unwrap();
        authorize_at(&root, proof.clone(), time).unwrap();
        authorize_at(&root, proof.clone(), time).unwrap();
        assert!(authorize_at(&root, proof, time)
            .unwrap_err()
            .to_string()
            .contains("quota"));
        let state = load(&root).unwrap();
        assert_eq!(state.invitations[0].member.as_ref().unwrap().rpc.count, 2);
        assert_eq!(state.admissions.count, 1);
        let mut state = load(&root).unwrap();
        assert!(clock(&mut state, time.saturating_sub(31)).is_err());
        let mut bucket = Bucket {
            period: 5,
            count: 2,
        };
        assert!(bucket.take(5, 2).is_err());
        bucket.take(6, 2).unwrap();
        assert_eq!(bucket.count, 1);
        assert!(bucket.take(5, 2).is_err());
        fs::remove_file(root.join(STATE)).unwrap();
        assert!(authorize(
            &root,
            Proof::signed(&a, &profile.rpc.url, "rpc", b"").unwrap()
        )
        .is_err());
        assert!(faucet::accept(&root, Claim::signed(&a).unwrap()).is_err());
    }
    #[test]
    fn concurrent_redemption_has_one_winner_and_reserves_one_grant() {
        let (_dir, root, profile) = fixture(2, 2, 5);
        let code = token(&root, "race", 3600, None);
        let time = now().unwrap();
        let a = WalletKey::generate(profile.network()).unwrap();
        let b = WalletKey::generate(profile.network()).unwrap();
        let one = joined(&a, &profile, Some(code.clone()), time);
        let two = joined(&b, &profile, Some(code), time);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let roots = [root.clone(), root.clone()];
        let handles = [one, two]
            .into_iter()
            .zip(roots)
            .map(|(request, path)| {
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    join(&path, request).is_ok()
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert_eq!(load(&root).unwrap().admissions.count, 1);
    }
}
