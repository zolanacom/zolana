//! Separate synthetic Mac-to-Linux fixture. Existing wallet paths are never inputs.
//! A complete signed packet is durable before transport; only canonical execution
//! and durable encrypted recipient state permit a successful ready receipt.
use super::{Chain, Synced};
use crate::keys::{read_private, write_private_new, Network, WalletKey};
use crate::operation::WalletOperation;
use crate::payments::{Payment, PaymentProver};
use crate::Result;
use base64::Engine;
use native_payment_program::instructions;
use native_payments::staging::payload_digest;
use native_payments::wire;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fs, thread};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};

const NAMES: [&str; 3] = ["alice", "bob", "charlie"];
const MAX_PACKET: usize = 16_384;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureProfile {
    pub format: String,
    pub network: Network,
    pub pool_format: String,
    pub rpc: String,
    pub ingress: Vec<SocketAddr>,
    pub relay_keypair: PathBuf,
    pub shielded_fee: u64,
}

#[cfg(test)]
mod recovery_policy_tests {
    use super::*;

    #[test]
    fn fixture_rpc_url_cannot_escape_loopback_or_add_credentials_and_routes() {
        for good in ["http://127.0.0.1:18899", "http://127.0.0.1:18899/"] {
            assert!(validate_rpc_url(good).is_ok(), "{good}");
        }
        for bad in [
            "http://127.0.0.1:18899@outside.example/",
            "http://user@127.0.0.1:18899/",
            "http://:password@127.0.0.1:18899/",
            "http://127.0.0.1.example:18899/",
            "https://127.0.0.1:18899/",
            "http://127.0.0.1:0/",
            "http://127.0.0.1/",
            "http://127.0.0.1:18899/rpc",
            "http://127.0.0.1:18899/?url=outside",
            "http://127.0.0.1:18899/#outside",
            "http://[::1]:18899/",
        ] {
            assert!(validate_rpc_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parallel_native_admission_preserves_wire_and_rejects_false_finality() {
        use std::{net::TcpListener, sync::mpsc};
        let fixture = tempfile::tempdir().unwrap();
        let intent = fixture.path().join("alice.native.json");
        let original = b"durable exact-packet reservation";
        write_private_new(&intent, original).unwrap();
        let packet = vec![0x5a; 2048];
        let signature = "original-fixture-signature";
        let (received_tx, received_rx) = mpsc::channel();
        let mut endpoints = Vec::new();
        let mut servers = Vec::new();
        let mut releases = Vec::new();
        for index in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            endpoints.push(listener.local_addr().unwrap());
            let (release_tx, release_rx) = mpsc::channel();
            releases.push(release_tx);
            let received_tx = received_tx.clone();
            servers.push(thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut size = [0; 4];
                stream.read_exact(&mut size).unwrap();
                let size = u32::from_le_bytes(size) as usize;
                assert_eq!(size, 2048);
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).unwrap();
                received_tx.send(bytes).unwrap();
                // All endpoints must receive the packet before any ACK is sent.
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                let ack = match index {
                    0 => json!({"status":"admitted","signature":signature,"finalized":false}),
                    1 => json!({"status":"admitted","signature":"substituted","finalized":false}),
                    _ => json!({"status":"admitted","signature":signature,"finalized":true}),
                };
                let _ = stream.write_all(format!("{ack}\n").as_bytes());
            }));
        }
        drop(received_tx);
        let coordinator = thread::spawn(move || {
            let received: std::result::Result<Vec<_>, _> = (0..3)
                .map(|_| received_rx.recv_timeout(Duration::from_secs(2)))
                .collect();
            for release in releases {
                let _ = release.send(());
            }
            received
        });
        let (_, acknowledgements) = Session::submit_all(&endpoints, &packet, signature).unwrap();
        for server in servers {
            server.join().unwrap();
        }
        for received in coordinator.join().unwrap().unwrap() {
            assert_eq!(received, packet);
        }
        assert_eq!(acknowledgements, vec![true, false, false]);
        assert_eq!(fs::read(&intent).unwrap(), original);
        assert!(Session::submit_all(&[], &packet, signature).is_err());
        assert!(Session::submit_all(&[endpoints[0]; 4], &packet, signature).is_err());
    }

    #[test]
    fn native_recovery_requires_complete_absence_and_both_strict_expiries() {
        let absent = json!({"accepted": false, "expired_without_execution": true});
        for (slot, height, expected) in [
            (100, 201, CanonicalDecision::Reserved),
            (101, 200, CanonicalDecision::Reserved),
            (100, 200, CanonicalDecision::Reserved),
            (101, 201, CanonicalDecision::ExpiredAbsent),
        ] {
            assert_eq!(
                full_canonical_decision(&absent, "original", 100, 200, slot, height).unwrap(),
                expected
            );
        }
        for no_proof in [
            json!({"state": "missing"}),
            json!({"accepted": false}),
            json!({"expired_without_execution": true}),
        ] {
            assert_eq!(
                full_canonical_decision(&no_proof, "original", 100, 200, 1000, 1000).unwrap(),
                CanonicalDecision::Reserved
            );
        }
        assert_eq!(
            full_canonical_decision(
                &json!({"accepted": true, "signature": "original"}),
                "original",
                100,
                200,
                1,
                1
            )
            .unwrap(),
            CanonicalDecision::Accepted
        );
        assert!(full_canonical_decision(
            &json!({"accepted": true, "signature": "substituted"}),
            "original",
            100,
            200,
            1000,
            1000
        )
        .is_err());
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    format: String,
    network: Network,
    pool_format: String,
    relay: String,
    wallets: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: String,
    network: Network,
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    expiry: u64,
    last_valid_block_height: u64,
    payload: String,
    packet: String,
    signature: String,
    packet_sha256: String,
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_rpc_url(raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw)?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none_or(|port| port == 0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("fixture RPC requires http://127.0.0.1:NONZERO_PORT with no credentials, path, query or fragment".into());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum CanonicalDecision {
    Accepted,
    ExpiredAbsent,
    Reserved,
}

// The caller must obtain `outcome` from Chain::shielded_outcome's complete
// canonical scan. Missing RPC status, retained history, ACK or expiry alone
// cannot supply this evidence.
fn full_canonical_decision(
    outcome: &Value,
    signature: &str,
    expiry: u64,
    last_valid_block_height: u64,
    finalized_slot: u64,
    finalized_block_height: u64,
) -> Result<CanonicalDecision> {
    if outcome["accepted"] == true {
        if outcome["signature"] != signature {
            return Err("full canonical recovery returned another signed identity".into());
        }
        return Ok(CanonicalDecision::Accepted);
    }
    if outcome["accepted"] == false
        && outcome["expired_without_execution"] == true
        && finalized_slot > expiry
        && finalized_block_height > last_valid_block_height
    {
        return Ok(CanonicalDecision::ExpiredAbsent);
    }
    Ok(CanonicalDecision::Reserved)
}

pub fn relay_init(path: &Path) -> Result<Value> {
    if !path.is_absolute() {
        return Err("fixture relay output must be absolute".into());
    }
    let key = Keypair::new();
    write_private_new(path, &serde_json::to_vec(&key.to_bytes().as_slice())?)?;
    write_private_new(
        &path.with_extension("fixture.json"),
        &serde_json::to_vec(&json!({
            "format": "native-fast-relay-fixture-v1", "public_key": key.pubkey().to_string(),
        }))?,
    )?;
    Ok(json!({"public_key": key.pubkey().to_string(), "synthetic_fixture_only": true}))
}

#[derive(Default)]
struct ResolveStages {
    status_rpc_ms: u128,
    status_rpc_count: usize,
    admission_ms: u128,
    admission_attempts: usize,
    finalized_observed_ms: u128,
}

pub struct Session {
    profile: FixtureProfile,
    root: PathBuf,
    chain: Chain,
    prover: PaymentProver,
    relay: Keypair,
    wallets: BTreeMap<String, WalletKey>,
    operations: BTreeMap<String, WalletOperation>,
    _relay_lock: WalletOperation,
    setup_ms: u128,
}

impl Session {
    pub fn open(profile_file: &Path, root: &Path, password: &[u8], resume: bool) -> Result<Self> {
        let began = Instant::now();
        let profile: FixtureProfile = serde_json::from_slice(&read_private(profile_file, 16_384)?)?;
        profile.network.validate()?;
        validate_rpc_url(&profile.rpc)?;
        if profile.format != "zolana-fast-fixture-v1"
            || !matches!(profile.pool_format.as_str(), "NPOOL003" | "NPOOL004")
            || profile.ingress.is_empty()
            || profile.ingress.len() > 3
            || profile
                .ingress
                .iter()
                .any(|endpoint| !endpoint.ip().is_loopback() || endpoint.port() == 0)
            || profile.shielded_fee == 0
            || profile.shielded_fee > 1_000_000
        {
            return Err("bounded loopback fixture profile required".into());
        }
        let relay = Keypair::try_from(
            serde_json::from_slice::<Vec<u8>>(&read_private(&profile.relay_keypair, 4096)?)?
                .as_slice(),
        )?;
        let relay_marker: Value = serde_json::from_slice(&read_private(
            &profile.relay_keypair.with_extension("fixture.json"),
            4096,
        )?)?;
        if relay_marker["format"] != "native-fast-relay-fixture-v1"
            || relay_marker["public_key"] != relay.pubkey().to_string()
        {
            return Err("only a separately generated Mac fixture relay is allowed".into());
        }
        if !root.is_absolute()
            || root
                .parent()
                .ok_or("fixture parent missing")?
                .canonicalize()?
                != root.parent().unwrap()
        {
            return Err("fixture directory must be an absolute canonical child".into());
        }
        if resume {
            if root.canonicalize()? != root || fs::metadata(root)?.permissions().mode() & 0o077 != 0
            {
                return Err(
                    "resume requires the original owner-only real fixture directory".into(),
                );
            }
        } else {
            fs::DirBuilder::new().mode(0o700).create(root)?;
        }
        let marker_path = root.join("fixture.json");
        let mut marker = if resume {
            serde_json::from_slice::<Marker>(&read_private(&marker_path, 8192)?)?
        } else {
            let marker = Marker {
                format: "native-fast-mac-fixture-v1".into(),
                network: profile.network.clone(),
                pool_format: profile.pool_format.clone(),
                relay: relay.pubkey().to_string(),
                wallets: BTreeMap::new(),
            };
            write_private_new(&marker_path, &serde_json::to_vec(&marker)?)?;
            marker
        };
        if marker.format != "native-fast-mac-fixture-v1"
            || marker.network != profile.network
            || marker.pool_format != profile.pool_format
            || marker.relay != relay.pubkey().to_string()
        {
            return Err("fixture marker network/relay mismatch; existing files preserved".into());
        }
        let relay_lock = WalletOperation::acquire(&root.join("relay-operation"))?;
        let mut wallets = BTreeMap::new();
        let mut operations = BTreeMap::new();
        for name in NAMES {
            let path = root.join(format!("{name}.wallet"));
            let operation = WalletOperation::acquire(&path)?;
            let wallet = if path.exists() {
                WalletKey::open(&path, password, &profile.network)?
            } else {
                if marker.wallets.contains_key(name) {
                    return Err("a recorded fixture wallet is missing; restore its backup".into());
                }
                let wallet = WalletKey::generate(profile.network.clone())?;
                wallet.save(&path, password)?;
                wallet
            };
            if marker
                .wallets
                .get(name)
                .is_some_and(|address| address != &wallet.address_text())
            {
                return Err("fixture wallet identity changed".into());
            }
            let backup = root.join(format!("{name}.backup"));
            if !backup.exists() {
                wallet.save(&backup, password)?;
            }
            marker.wallets.insert(name.into(), wallet.address_text());
            wallets.insert(name.into(), wallet);
            operations.insert(name.into(), operation);
        }
        crate::sponsor::replace(&marker_path, &serde_json::to_vec(&marker)?)?;
        let prover = PaymentProver::new();
        let chain = Chain::connect(&profile.rpc, profile.network.clone())?
            .with_standard_read_batches()?
            .with_payment_prover(&prover)
            .with_pool_format(&profile.pool_format)?;
        Ok(Self {
            profile,
            root: root.to_owned(),
            chain,
            prover,
            relay,
            wallets,
            operations,
            _relay_lock: relay_lock,
            setup_ms: began.elapsed().as_millis(),
        })
    }

    fn name<'a>(&self, request: &'a Value, field: &str) -> Result<&'a str> {
        let name = request[field]
            .as_str()
            .ok_or("fixture wallet name required")?;
        if !NAMES.contains(&name) {
            return Err("wallet must be alice, bob or charlie".into());
        }
        Ok(name)
    }

    fn sync(&self, name: &str) -> Result<Synced> {
        Self::sync_wallet(&self.chain, &self.wallets[name], &self.operations[name])
    }

    fn sync_wallet(
        chain: &Chain,
        wallet: &WalletKey,
        operation: &WalletOperation,
    ) -> Result<Synced> {
        let synced = chain.sync_cached(wallet, operation)?;
        if !synced.scan.cache_saved {
            return Err("encrypted checkpoint was not durable; wallet is not ready".into());
        }
        for note in synced.state.unspent() {
            synced.state.witness(note.position)?;
        }
        Ok(synced)
    }

    fn packet(&self, intent: &Intent) -> Result<(Vec<u8>, Vec<u8>, Transaction)> {
        if intent.format != "native-fast-packet-v1"
            || intent.network != self.profile.network
            || !NAMES.contains(&intent.from.as_str())
            || !NAMES.contains(&intent.to.as_str())
            || intent.from == intent.to
            || intent.amount == 0
            || intent.fee != self.profile.shielded_fee
        {
            return Err("native journal identity/intent mismatch".into());
        }
        let engine = base64::engine::general_purpose::STANDARD;
        let payload = engine.decode(&intent.payload)?;
        let packet = engine.decode(&intent.packet)?;
        if packet.len() > MAX_PACKET
            || packet.len() <= 1232
            || engine.encode(&packet) != intent.packet
            || engine.encode(&payload) != intent.payload
            || digest(&packet) != intent.packet_sha256
        {
            return Err("native journal packet is malformed".into());
        }
        let payment = wire::decode(self.profile.network.network, &payload)?;
        if payment.context.sponsor != self.relay.pubkey().to_bytes()
            || payment.context.shielded_fee != Some(intent.fee)
            || payment.context.expires_at != intent.expiry
        {
            return Err("native journal signed authorization differs".into());
        }
        let transaction: Transaction = bincode::deserialize(&packet)?;
        transaction.verify()?;
        let expected = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                instructions::inline(self.profile.network.network, &payload)?,
            ],
            Some(&self.relay.pubkey()),
            &[&self.relay],
            transaction.message.recent_blockhash,
        );
        if bincode::serialize(&expected)? != packet
            || bincode::serialize(&transaction)? != packet
            || transaction.signatures[0].to_string() != intent.signature
        {
            return Err("native journal wire/signature/effects mismatch".into());
        }
        Ok((payload, packet, transaction))
    }

    fn prepare(&self, from: &str, to: &str, amount: u64) -> Result<Value> {
        if from == to || amount == 0 || amount > 1_000_000_000 {
            return Err("bounded distinct-recipient fixture send required".into());
        }
        let operation = &self.operations[from];
        operation.ensure_resolved()?;
        let started = Instant::now();
        let synced = self.sync(from)?;
        let sync_ms = started.elapsed().as_millis();
        let expiry_at = Instant::now();
        let expiry = self.chain.expiry()?;
        let expiry_rpc_ms = expiry_at.elapsed().as_millis();
        let proof_at = Instant::now();
        let payload = self.prover.build(
            &self.wallets[from],
            &synced.state,
            self.relay.pubkey().to_bytes(),
            expiry,
            Payment::ShieldedSend {
                amount,
                recipient: &self.wallets[to].address_text(),
                fee: self.profile.shielded_fee,
            },
        )?;
        let proof_ms = proof_at.elapsed().as_millis();
        let proof_complete_ms = started.elapsed().as_millis();
        let blockhash_at = Instant::now();
        let (blockhash, last_valid_block_height) = self
            .chain
            .rpc
            .get_latest_blockhash_with_commitment(CommitmentConfig::finalized())?;
        let blockhash_rpc_ms = blockhash_at.elapsed().as_millis();
        let transaction = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                instructions::inline(self.profile.network.network, &payload)?,
            ],
            Some(&self.relay.pubkey()),
            &[&self.relay],
            blockhash,
        );
        let packet = bincode::serialize(&transaction)?;
        let engine = base64::engine::general_purpose::STANDARD;
        let intent = Intent {
            format: "native-fast-packet-v1".into(),
            network: self.profile.network.clone(),
            from: from.into(),
            to: to.into(),
            amount,
            fee: self.profile.shielded_fee,
            expiry,
            last_valid_block_height,
            payload: engine.encode(payload),
            packet: engine.encode(&packet),
            signature: transaction.signatures[0].to_string(),
            packet_sha256: digest(&packet),
        };
        self.packet(&intent)?;
        let raw_path = self.root.join(format!("{}.packet", intent.signature));
        let journal_at = Instant::now();
        write_private_new(&raw_path, &packet)?;
        write_private_new(&operation.native, &serde_json::to_vec(&intent)?)?;
        let journal_ms = journal_at.elapsed().as_millis();
        crate::progress::report("native_packet_durable");
        Ok(
            json!({"pending": true, "signature": intent.signature, "packet_sha256": intent.packet_sha256,
            "raw_packet_file": raw_path, "packet_bytes": packet.len(), "sync_ms": sync_ms,
            "proof_complete_ms": proof_complete_ms, "prepare_ms": started.elapsed().as_millis(),
            "expiry_rpc_ms": expiry_rpc_ms, "proof_ms": proof_ms,
            "blockhash_rpc_ms": blockhash_rpc_ms, "journal_ms": journal_ms,
            "broadcast": false}),
        )
    }

    fn submit(endpoint: SocketAddr, packet: &[u8], signature: &str) -> Result<()> {
        let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_millis(500))?;
        stream.set_nodelay(true)?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.write_all(&(packet.len() as u32).to_le_bytes())?;
        stream.write_all(packet)?;
        let mut line = String::new();
        BufReader::new(stream.take(2048)).read_line(&mut line)?;
        let value: Value = serde_json::from_str(&line)?;
        if value["finalized"] != false
            || (value["status"] == "admitted" && value["signature"] != signature)
        {
            return Err(
                "native acknowledgement identity/finality claim invalid; intent retained".into(),
            );
        }
        Ok(())
    }

    fn submit_all(
        endpoints: &[SocketAddr],
        packet: &[u8],
        signature: &str,
    ) -> Result<(u128, Vec<bool>)> {
        if endpoints.is_empty()
            || endpoints.len() > 3
            || endpoints
                .iter()
                .any(|endpoint| !endpoint.ip().is_loopback() || endpoint.port() == 0)
        {
            return Err("native admission requires 1..3 pinned loopback endpoints".into());
        }
        let began = Instant::now();
        let acknowledgements = thread::scope(|scope| {
            let handles: Vec<_> = endpoints
                .iter()
                .map(|endpoint| {
                    scope.spawn(move || Self::submit(*endpoint, packet, signature).is_ok())
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap_or(false))
                .collect()
        });
        // ACKs are transport observations only. No outcome or journal changes.
        Ok((began.elapsed().as_millis(), acknowledgements))
    }

    fn resolve(&self, from: &str) -> Result<Value> {
        let operation = &self.operations[from];
        let intent: Intent = serde_json::from_slice(&read_private(&operation.native, 64_000)?)?;
        if intent.from != from {
            return Err("native journal belongs to another wallet".into());
        }
        let (payload, packet, transaction) = self.packet(&intent)?;
        let signature = transaction.signatures[0];
        let began = Instant::now();
        let mut next_send = Instant::now();
        let mut stages = ResolveStages::default();
        while began.elapsed() < Duration::from_secs(60) {
            let status_at = Instant::now();
            stages.status_rpc_count += 1;
            let statuses = self
                .chain
                .rpc
                .get_signature_statuses_with_history(&[signature])?;
            stages.status_rpc_ms += status_at.elapsed().as_millis();
            if let Some(status) = statuses.value.first().and_then(Option::as_ref) {
                if status.satisfies_commitment(CommitmentConfig::finalized()) {
                    if status.err.is_some() {
                        return Err("native transaction failed; signed intent retained; use recover-native for complete canonical recovery".into());
                    }
                    stages.finalized_observed_ms = began.elapsed().as_millis();
                    return self.finish_accepted(
                        &intent,
                        &payload,
                        Some(status.slot),
                        began,
                        Some(stages),
                    );
                }
            }
            if Instant::now() >= next_send {
                let (admission_ms, acknowledgements) =
                    Self::submit_all(&self.profile.ingress, &packet, &intent.signature)?;
                stages.admission_attempts += acknowledgements.len();
                stages.admission_ms += admission_ms;
                crate::progress::report("native_original_packet_submitted");
                next_send = Instant::now() + Duration::from_millis(250);
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(
            "native outcome unresolved; original signed packet retained, no replacement authorized"
                .into(),
        )
    }

    fn commit_outcome(&self, intent: &Intent, receipt: &Value) -> Result<()> {
        crate::sponsor::replace(
            &self
                .root
                .join(format!("{}.native-receipt.json", intent.from)),
            &serde_json::to_vec(receipt)?,
        )?;
        fs::remove_file(&self.operations[&intent.from].native)?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn finish_accepted(
        &self,
        intent: &Intent,
        payload: &[u8],
        execution_slot: Option<u64>,
        began: Instant,
        stages: Option<ResolveStages>,
    ) -> Result<Value> {
        // Independent wallet locks and cache files; each worker owns its RPC
        // runtime/HTTP pool, sharing only immutable pinned endpoint/key material.
        let sender_chain = self.chain.read_only_scan_fork()?;
        let recipient_chain = self.chain.read_only_scan_fork()?;
        let sender_wallet = &self.wallets[&intent.from];
        let recipient_wallet = &self.wallets[&intent.to];
        let sender_operation = &self.operations[&intent.from];
        let recipient_operation = &self.operations[&intent.to];
        let (sender_result, recipient_result) = thread::scope(|scope| {
            let sender = scope.spawn(move || {
                let began = Instant::now();
                Self::sync_wallet(&sender_chain, sender_wallet, sender_operation)
                    .map(|state| (state, began.elapsed().as_millis()))
                    .map_err(|error| error.to_string())
            });
            let recipient = scope.spawn(move || {
                let began = Instant::now();
                Self::sync_wallet(&recipient_chain, recipient_wallet, recipient_operation)
                    .map(|state| (state, began.elapsed().as_millis()))
                    .map_err(|error| error.to_string())
            });
            // Join both even after either fails; the original intent remains.
            (sender.join(), recipient.join())
        });
        let (sender, sender_sync_ms) =
            sender_result.map_err(|_| "sender sync worker panicked; intent retained")??;
        let (recipient, recipient_sync_ms) =
            recipient_result.map_err(|_| "recipient sync worker panicked; intent retained")??;
        if !sender.accepted_finalizations.contains(&intent.signature)
            || sender
                .payment_digests
                .get(&intent.signature)
                .is_some_and(|found| *found != payload_digest(payload))
        {
            return Err(
                "finalized native signature lacks matching canonical successful history".into(),
            );
        }
        if !recipient.accepted_finalizations.contains(&intent.signature) {
            return Err("recipient canonical history does not contain the original payment".into());
        }
        let mut receipt = json!({"accepted": true, "signature": intent.signature,
            "packet_sha256": intent.packet_sha256, "from": intent.from, "to": intent.to,
            "sender_balance": sender.state.balance()?, "recipient_balance": recipient.state.balance()?,
            "execution_slot": execution_slot, "sender_checkpoint": sender.slot,
            "recipient_checkpoint": recipient.slot, "encrypted_checkpoints_durable": true,
            "resolve_to_durable_recipient_ms": began.elapsed().as_millis(),
            "status_rpc_ms": stages.as_ref().map(|stage| stage.status_rpc_ms),
            "status_rpc_count": stages.as_ref().map(|stage| stage.status_rpc_count),
            "admission_ms": stages.as_ref().map(|stage| stage.admission_ms),
            "admission_attempts": stages.as_ref().map(|stage| stage.admission_attempts),
            "finalized_observed_ms": stages.as_ref().map(|stage| stage.finalized_observed_ms),
            "sender_sync_ms": sender_sync_ms, "recipient_sync_ms": recipient_sync_ms,
            "sender_scan": sender.scan, "recipient_scan": recipient.scan,
            "finality_source": "canonical RPC history over operator-pinned SSH; no light-client proof claim"});
        let receipt_at = Instant::now();
        self.commit_outcome(intent, &receipt)?;
        // This observation is returned after the receipt and intent unlink are
        // durable; measuring a commit cannot be included in that same write.
        receipt["receipt_ms"] = json!(receipt_at.elapsed().as_millis());
        Ok(receipt)
    }

    /// Slow explicit recovery proves absence only through complete canonical
    /// replay. It never uses retained/suffix absence, broadcasts, resigns or
    /// constructs a replacement payment.
    fn recover_native(&self, from: &str) -> Result<Value> {
        let intent: Intent =
            serde_json::from_slice(&read_private(&self.operations[from].native, 64_000)?)?;
        if intent.from != from {
            return Err("native journal belongs to another wallet".into());
        }
        let (payload, _, _) = self.packet(&intent)?;
        let began = Instant::now();
        let outcome =
            self.chain
                .shielded_outcome(&self.wallets[from], &payload, Some(&intent.signature))?;
        let finalized_slot = self
            .chain
            .rpc
            .get_slot_with_commitment(CommitmentConfig::finalized())?;
        let finalized_height = self
            .chain
            .rpc
            .get_block_height_with_commitment(CommitmentConfig::finalized())?;
        match full_canonical_decision(&outcome, &intent.signature, intent.expiry,
            intent.last_valid_block_height, finalized_slot, finalized_height)? {
            CanonicalDecision::Accepted => self.finish_accepted(&intent, &payload, None, began, None),
            CanonicalDecision::ExpiredAbsent => {
                let sender = self.sync(from)?;
                if sender.accepted_finalizations.contains(&intent.signature) {
                    return Err("canonical absence conflicts with the sender checkpoint; intent retained".into());
                }
                let receipt = json!({"accepted": false, "expired_without_execution": true,
                    "signature": intent.signature, "packet_sha256": intent.packet_sha256,
                    "sender_balance": sender.state.balance()?, "sender_checkpoint": sender.slot,
                    "encrypted_sender_checkpoint_durable": true,
                    "signed_inner_expiry": intent.expiry, "last_valid_block_height": intent.last_valid_block_height,
                    "observed_finalized_slot": finalized_slot, "observed_finalized_block_height": finalized_height,
                    "absence_source": "complete canonical RPC replay; retained/suffix history and missing statuses are insufficient"});
                self.commit_outcome(&intent, &receipt)?;
                Ok(receipt)
            }
            CanonicalDecision::Reserved => Err("native outcome remains reserved; full canonical absence and both strict expiry bounds are required".into()),
        }
    }

    pub fn request(&mut self, request: &Value) -> Result<Value> {
        let object = request.as_object().ok_or("request must be an object")?;
        if object
            .keys()
            .any(|key| !["op", "wallet", "from", "to", "amount", "id"].contains(&key.as_str()))
        {
            return Err("unknown fixture request field".into());
        }
        match request["op"].as_str().ok_or("op required")? {
            "status" => Ok(
                json!({"setup_ms": self.setup_ms, "relay": self.relay.pubkey().to_string(),
                "wallets": NAMES.iter().map(|name| json!({"name": name, "address": self.wallets[*name].address_text(),
                    "pending_native": self.operations[*name].native.exists(),
                    "pending_staging": self.operations[*name].has_staging(), "pending_legacy": self.operations[*name].has_pending()})).collect::<Vec<_>>() }),
            ),
            "sync" => {
                let name = self.name(request, "wallet")?;
                let state = self.sync(name)?;
                Ok(
                    json!({"wallet": name, "balance": state.state.balance()?, "checkpoint": state.slot,
                    "encrypted_checkpoint_durable": true, "scan": state.scan}),
                )
            }
            "deposit" => {
                let name = self.name(request, "wallet")?;
                self.operations[name].ensure_resolved()?;
                let amount = request["amount"]
                    .as_u64()
                    .filter(|amount| *amount > 0 && *amount <= 1_000_000_000)
                    .ok_or("bounded deposit amount required")?;
                let state = self.sync(name)?;
                let bytes = self.prover.build(
                    &self.wallets[name],
                    &state.state,
                    self.relay.pubkey().to_bytes(),
                    self.chain.expiry()?,
                    Payment::Deposit {
                        amount,
                        recipient: &self.wallets[name].address_text(),
                    },
                )?;
                let receipt = self
                    .chain
                    .submit(&self.relay, &bytes, &self.operations[name])?;
                let state = self.sync(name)?;
                Ok(
                    json!({"receipt": receipt, "balance": state.state.balance()?, "checkpoint": state.slot,
                    "encrypted_checkpoint_durable": true}),
                )
            }
            op @ ("send" | "prepare") => {
                let from = self.name(request, "from")?;
                let to = self.name(request, "to")?;
                let amount = request["amount"].as_u64().ok_or("amount required")?;
                let began = Instant::now();
                let prepared = self.prepare(from, to, amount)?;
                if op == "prepare" {
                    return Ok(prepared);
                }
                let receipt = self.resolve(from)?;
                Ok(json!({"prepared": prepared, "receipt": receipt,
                    "action_to_durable_recipient_ms": began.elapsed().as_millis()}))
            }
            "resolve" => self.resolve(self.name(request, "wallet")?),
            "recover-native" => self.recover_native(self.name(request, "wallet")?),
            "resolve-deposit" => {
                let name = self.name(request, "wallet")?;
                let value = self
                    .chain
                    .resolve(&self.wallets[name], &self.operations[name])?;
                if self.operations[name].has_staging() {
                    self.chain.reclaim(&self.relay, &self.operations[name])?;
                }
                let state = self.sync(name)?;
                Ok(
                    json!({"receipt": value, "balance": state.state.balance()?, "encrypted_checkpoint_durable": true}),
                )
            }
            _ => Err(
                "expected status|sync|deposit|prepare|send|resolve|recover-native|resolve-deposit"
                    .into(),
            ),
        }
    }
}
