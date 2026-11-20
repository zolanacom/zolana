//! Native-cohort policy and durable admission guards. No RPC listeners, chain,
//! grant execution or network finality is simulated by these unit tests.
use super::*;
use crate::{access, connection::Endpoint};

const PASSWORD: &[u8] = b"independent-native-cohort-password";

fn source(pool_format: &str) -> TesterProfile {
    TesterProfile {
        format: "native-wallet-profile-v1".into(),
        label: "Native cohort unit fixture".into(),
        key_mode: "user-wallet-v1".into(),
        network: [67; 32],
        genesis_hash: bs58::encode([9; 32]).into_string(),
        program: native_payment_program::id().to_string(),
        pool: native_payment_program::pool_address().to_string(),
        pool_format: pool_format.into(),
        private_send_transport: None,
        retained_history_format: None,
        access_audiences: None,
        recipient_withdrawals: true,
        rpc: Endpoint {
            transport: "loopback-http".into(),
            url: "http://127.0.0.1:18899".into(),
        },
        faucet: None,
        invite_required: false,
        local_tls_ca_pem: None,
    }
}

fn profile_file(directory: &Path, profile: &TesterProfile) -> std::path::PathBuf {
    let path = directory.join("source.json");
    fs::write(&path, serde_json::to_vec(profile).unwrap()).unwrap();
    path
}

pub(super) fn fixture(capacity: usize) -> (tempfile::TempDir, std::path::PathBuf, TesterProfile) {
    let directory = tempfile::tempdir().unwrap();
    let profile = source("NPOOL004");
    let file = profile_file(directory.path(), &profile);
    let root = directory.path().join("native-cohort");
    initialize_native(&root, &file, PASSWORD, capacity, None).unwrap();
    (directory, root, profile)
}

pub(super) fn signed(profile: &TesterProfile) -> (WalletKey, Claim) {
    let wallet = WalletKey::generate(profile.network()).unwrap();
    let claim = Claim::signed(&wallet).unwrap();
    (wallet, claim)
}

fn invited(root: &Path, profile: &TesterProfile) -> TesterProfile {
    let mut public = profile.clone();
    public.invite_required = true;
    public.rpc.url = "http://127.0.0.1:18898".into();
    public.faucet = Some(Endpoint {
        transport: "loopback-http".into(),
        url: "http://127.0.0.1:8780".into(),
    });
    let path = root.parent().unwrap().join("invited.json");
    fs::write(&path, serde_json::to_vec(&public).unwrap()).unwrap();
    access::initialize(root, &path, 10, 2000).unwrap();
    public
}

fn join_request(wallet: &WalletKey, public: &TesterProfile, token: Option<String>) -> Vec<u8> {
    let claim = Claim::signed(wallet).unwrap();
    let body = serde_json::to_vec(&(&claim, token.as_deref())).unwrap();
    let proof =
        access::Proof::signed(wallet, &public.faucet.as_ref().unwrap().url, "join", &body).unwrap();
    serde_json::to_vec(&access::Join {
        claim,
        invitation: token,
        proof,
    })
    .unwrap()
}

#[test]
fn native_initialization_has_explicit_finite_private_only_budget() {
    let directory = tempfile::tempdir().unwrap();
    let profile = source("NPOOL004");
    let file = profile_file(directory.path(), &profile);
    let root = directory.path().join("native");
    let receipt = initialize_native(&root, &file, PASSWORD, 10, None).unwrap();
    let (saved, ledger) = load(&root).unwrap();
    assert_eq!(saved.pool_format, "NPOOL004");
    assert_eq!(ledger.policy.format, "native-test-faucet-native-v1");
    assert_eq!(ledger.policy.private_amount, 20_000_000);
    assert_eq!(ledger.policy.gas_amount, 0);
    assert_eq!(ledger.policy.max_claims, 10);
    assert_eq!(ledger.policy.max_attempts, 3);
    assert_eq!(ledger.policy.payment_cap, 150_000_000);
    assert!(!ledger.policy.invite_required);
    assert_eq!(receipt["private_units_required"], 200_000_000u64);
    assert_eq!(receipt["public_gas_grants_required"], 0);
    assert_eq!(receipt["conservative_public_units"], 4_500_000_000u64);
    assert_eq!(receipt["automatic_refill"], false);
    assert_eq!(PRIVATE_GRANT, 1_000_000);
    assert_eq!(GAS_GRANT, 150_000_000);
}

#[test]
fn native_init_rejects_non_slot_anchored_or_invited_source_profiles() {
    let directory = tempfile::tempdir().unwrap();
    for (index, mut profile) in [source("NPOOL003"), source("NPOOL004")]
        .into_iter()
        .enumerate()
    {
        if index == 1 {
            profile.invite_required = true;
            profile.faucet = Some(Endpoint {
                transport: "loopback-http".into(),
                url: "http://127.0.0.1:8780".into(),
            });
        }
        let file = profile_file(directory.path(), &profile);
        let root = directory.path().join(format!("invalid-{index}"));
        assert!(initialize_native(&root, &file, PASSWORD, 10, None).is_err());
        assert!(
            !root.exists(),
            "invalid native policy must fail before creating a source wallet"
        );
    }
}

#[test]
fn native_capacity_never_expands_or_reinitializes_a_legacy_root() {
    let directory = tempfile::tempdir().unwrap();
    let profile = source("NPOOL004");
    let file = profile_file(directory.path(), &profile);
    for count in [0, NATIVE_MAX_CLAIMS + 1, 1000, usize::MAX] {
        let root = directory.path().join(format!("invalid-capacity-{count}"));
        assert!(initialize_native(&root, &file, PASSWORD, count, None).is_err());
        assert!(!root.exists());
    }
    let legacy = directory.path().join("existing-legacy");
    initialize(&legacy, &file, PASSWORD, 11).unwrap();
    let original = fs::read(legacy.join("claims.json")).unwrap();
    assert!(initialize_native(&legacy, &file, PASSWORD, 10, None).is_err());
    assert_eq!(fs::read(legacy.join("claims.json")).unwrap(), original);
    let (_, ledger) = load(&legacy).unwrap();
    assert_eq!(ledger.policy.private_amount, 1_000_000);
    assert_eq!(ledger.policy.gas_amount, 150_000_000);
    assert_eq!(ledger.policy.max_claims, 11);
}

#[test]
fn native_capacity_is_bounded_by_the_largest_plannable_cohort() {
    assert_eq!(NATIVE_MAX_CLAIMS, 500);
    let directory = tempfile::tempdir().unwrap();
    let profile = source("NPOOL004");
    let file = profile_file(directory.path(), &profile);
    for (count, private, public) in [
        (1, 20_000_000u64, 450_000_000u64),
        (200, 4_000_000_000, 90_000_000_000),
        (500, 10_000_000_000, 225_000_000_000),
    ] {
        let root = directory.path().join(format!("capacity-{count}"));
        let receipt = initialize_native(&root, &file, PASSWORD, count, None).unwrap();
        assert_eq!(receipt["max_claims"], count);
        assert_eq!(receipt["private_units_required"], private);
        assert_eq!(receipt["conservative_public_units"], public);
        let (_, ledger) = load(&root).unwrap();
        assert_eq!(ledger.policy.max_claims, count);
        assert_eq!(ledger.policy.private_amount, 20_000_000);
        assert_eq!(access_context(&root).unwrap().1, count);
    }
    // A stored policy is re-checked at every load, not only at initialization.
    let root = directory.path().join("capacity-500");
    let original = fs::read(root.join("claims.json")).unwrap();
    for count in [0, 501, 1000] {
        let mut ledger: Value = serde_json::from_slice(&original).unwrap();
        ledger["policy"]["max_claims"] = json!(count);
        save(&root.join("claims.json"), &ledger).unwrap();
        assert!(load(&root).is_err(), "native capacity {count} accepted");
    }
    replace(&root.join("claims.json"), &original).unwrap();
    assert_eq!(load(&root).unwrap().1.policy.max_claims, 500);
    // Invitations and daily admissions take their bound from that capacity alone.
    let mut public = profile.clone();
    public.invite_required = true;
    public.rpc.url = "http://127.0.0.1:18898".into();
    public.faucet = Some(Endpoint {
        transport: "loopback-http".into(),
        url: "http://127.0.0.1:8780".into(),
    });
    let path = directory.path().join("invited.json");
    fs::write(&path, serde_json::to_vec(&public).unwrap()).unwrap();
    for daily in [0, 501] {
        assert!(access::initialize(&root, &path, daily, 2000).is_err());
        assert!(!root.join("admission.json").exists());
    }
    let admission = access::initialize(&root, &path, 500, 2000).unwrap();
    assert_eq!(admission["max_invites"], 500);
    assert_eq!(admission["daily_admissions"], 500);
    assert_eq!(access::info(&root).unwrap()["max_invites"], 500);
}

#[test]
fn ten_wallet_native_state_written_before_the_larger_bound_loads_unchanged() {
    let (_directory, root, _) = fixture(10);
    let (_, ledger) = load(&root).unwrap();
    // Exact bytes a ten-wallet native faucet wrote under the former 1..10 bound.
    let stored = format!(
        concat!(
            "{{\n  \"policy\": {{\n    \"format\": \"native-test-faucet-native-v1\",\n",
            "    \"network\": {},\n    \"source_fee_address\": \"{}\",\n",
            "    \"source_private_address\": \"{}\",\n    \"max_claims\": 10,\n",
            "    \"private_amount\": 20000000,\n    \"gas_amount\": 0,\n",
            "    \"max_attempts\": 3,\n    \"payment_cap\": 150000000\n  }},\n  \"claims\": []\n}}"
        ),
        serde_json::to_string_pretty(&ledger.policy.network)
            .unwrap()
            .replace('\n', "\n    "),
        ledger.policy.source_fee_address,
        ledger.policy.source_private_address,
    );
    assert_eq!(
        fs::read(root.join("claims.json")).unwrap(),
        stored.as_bytes()
    );
    let (_, reloaded) = load(&root).unwrap();
    assert_eq!(reloaded.policy.max_claims, 10);
    assert_eq!(access_context(&root).unwrap().1, 10);
    assert_eq!(
        fs::read(root.join("claims.json")).unwrap(),
        stored.as_bytes()
    );
}

#[test]
fn native_policy_rejects_amount_mode_capacity_and_profile_downgrades() {
    let (_directory, root, _) = fixture(10);
    let original = fs::read(root.join("claims.json")).unwrap();
    for (field, value) in [
        ("private_amount", json!(1_000_000)),
        ("gas_amount", json!(1)),
        ("max_claims", json!(0)),
        ("max_claims", json!(NATIVE_MAX_CLAIMS + 1)),
        ("max_claims", json!(true)),
        ("max_attempts", json!(4)),
        ("payment_cap", json!(150_000_001)),
        ("format", json!("native-test-faucet-v1")),
    ] {
        let mut ledger: Value = serde_json::from_slice(&original).unwrap();
        ledger["policy"][field] = value;
        save(&root.join("claims.json"), &ledger).unwrap();
        assert!(
            load(&root).is_err(),
            "tampered native policy field {field} accepted"
        );
    }
    replace(&root.join("claims.json"), &original).unwrap();
    let mut profile: Value =
        serde_json::from_slice(&fs::read(root.join("profile.json")).unwrap()).unwrap();
    profile["pool_format"] = "NPOOL003".into();
    save(&root.join("profile.json"), &profile).unwrap();
    assert!(load(&root).is_err());
    assert_eq!(fs::read(root.join("claims.json")).unwrap(), original);
}

#[test]
fn native_progress_reports_private_funding_and_never_a_public_gas_grant() {
    let (_directory, root, profile) = fixture(1);
    let (_, claim) = signed(&profile);
    let first = accept(&root, claim.clone()).unwrap();
    assert_eq!(first["state"], "queued");
    let (_, ledger) = load(&root).unwrap();
    let path = root.join(format!("{}.json", claim.id()));
    let mut record = Progress {
        gas_done: true,
        private_attempts: 1,
        proof: Some(vec![3; 9222]),
        ..Progress::default()
    };
    save(&path, &record).unwrap();
    let pending = status(&root, &claim, &ledger.policy).unwrap();
    assert_eq!(pending["state"], "funding");
    for value in [&first, &pending] {
        assert_eq!(value["private_amount"], 20_000_000);
        assert_eq!(value["gas_amount"], 0);
        assert_eq!(value["gas_required"], false);
        assert_eq!(value["gas_finalized"], false);
    }
    record.private_done = true;
    save(&path, &record).unwrap();
    let ready = status(&root, &claim, &ledger.policy).unwrap();
    assert_eq!(ready["state"], "ready");
    assert_eq!(ready["private_finalized"], true);
    assert_eq!(ready["gas_finalized"], false);
    assert!(progress(&root, &claim.id(), &ledger.policy)
        .unwrap()
        .gas
        .is_none());
}

#[test]
fn native_progress_rejects_public_gas_and_inconsistent_or_unbounded_work() {
    let (_directory, root, profile) = fixture(1);
    let (_, claim) = signed(&profile);
    accept(&root, claim.clone()).unwrap();
    let (_, ledger) = load(&root).unwrap();
    let path = root.join(format!("{}.json", claim.id()));
    let malformed = [
        Progress {
            gas_attempts: 1,
            ..Progress::default()
        },
        Progress {
            gas: Some(Gas {
                transaction: vec![1],
                last_valid_block_height: 1,
            }),
            ..Progress::default()
        },
        Progress {
            private_attempts: 1,
            ..Progress::default()
        },
        Progress {
            submission_started: true,
            ..Progress::default()
        },
        Progress {
            private_done: true,
            ..Progress::default()
        },
        Progress {
            gas_done: true,
            private_attempts: 4,
            ..Progress::default()
        },
        Progress {
            gas_done: true,
            private_attempts: 1,
            proof: Some(vec![3; 9221]),
            ..Progress::default()
        },
    ];
    for record in malformed {
        save(&path, &record).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(progress(&root, &claim.id(), &ledger.policy).is_err());
        assert!(accept(&root, claim.clone()).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn repeated_native_claim_preserves_original_proof_pending_staging_and_budget() {
    let (_directory, root, profile) = fixture(1);
    let (wallet, claim) = signed(&profile);
    accept(&root, claim.clone()).unwrap();
    let path = root.join(format!("{}.json", claim.id()));
    let record = Progress {
        gas_done: true,
        private_attempts: 1,
        proof: Some(vec![3; 9222]),
        submission_started: true,
        ..Progress::default()
    };
    save(&path, &record).unwrap();
    let ledger = fs::read(root.join("claims.json")).unwrap();
    let proof = fs::read(&path).unwrap();
    let pending = root.join("wallet.enc.json.pending.json");
    let staging = root.join("wallet.enc.json.staging.json");
    write_private_new(&pending, b"original signed transaction identity").unwrap();
    write_private_new(&staging, b"original upload and gross-cap reservation").unwrap();
    for _ in 0..3 {
        let receipt = accept(&root, Claim::signed(&wallet).unwrap()).unwrap();
        assert_eq!(receipt["claim_id"], claim.id());
        assert_eq!(receipt["state"], "funding");
        assert_eq!(fs::read(&path).unwrap(), proof);
        assert_eq!(fs::read(root.join("claims.json")).unwrap(), ledger);
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"original signed transaction identity"
        );
        assert_eq!(
            fs::read(&staging).unwrap(),
            b"original upload and gross-cap reservation"
        );
    }
    // Missing progress is an incident, not permission to free or refill a slot.
    fs::remove_file(&path).unwrap();
    assert!(accept(&root, claim).is_err());
    assert_eq!(fs::read(root.join("claims.json")).unwrap(), ledger);
}

#[test]
fn native_claims_reject_redirection_forgery_wrong_network_and_worker_overlap() {
    let (_directory, root, profile) = fixture(1);
    let (wallet, claim) = signed(&profile);
    accept(&root, claim.clone()).unwrap();
    let ledger = fs::read(root.join("claims.json")).unwrap();
    let (_, other) = signed(&profile);
    let mut redirected = claim.clone();
    redirected.private_address = other.private_address;
    redirected.signature = wallet
        .fee_keypair()
        .sign_message(&redirected.message().unwrap())
        .to_string();
    assert!(accept(&root, redirected).is_err());
    let mut wrong = claim.clone();
    wrong.network.network[0] ^= 1;
    assert!(accept(&root, wrong).is_err());
    let mut forged = claim;
    forged.signature = Keypair::new()
        .sign_message(&forged.message().unwrap())
        .to_string();
    assert!(accept(&root, forged).is_err());
    assert_eq!(fs::read(root.join("claims.json")).unwrap(), ledger);
    let lock = WalletOperation::acquire(&root.join("worker")).unwrap();
    let error = tick(&root, b"not-a-valid-password")
        .unwrap_err()
        .to_string();
    assert!(error.contains("cannot lock wallet operation"));
    assert_eq!(fs::read(root.join("claims.json")).unwrap(), ledger);
    drop(lock);
}

#[test]
fn ten_invited_native_claims_reserve_once_and_revoked_capacity_is_not_reissued() {
    let (_directory, root, profile) = fixture(10);
    let public = invited(&root, &profile);
    let mut originals = Vec::new();
    let mut invitation_ids = Vec::new();
    for index in 0..10 {
        let (wallet, claim) = signed(&profile);
        let output = root.join(format!("tester-{index}.invite"));
        let issued = access::issue(&root, &output, 3600, Some(claim.fee_address.clone())).unwrap();
        let export: Value = serde_json::from_slice(&read_private(&output, 1024).unwrap()).unwrap();
        let request = join_request(
            &wallet,
            &public,
            Some(export["invitation"].as_str().unwrap().into()),
        );
        let receipt = access::join(&root, serde_json::from_slice(&request).unwrap()).unwrap();
        assert_eq!(receipt["claim_id"], claim.id());
        assert_eq!(receipt["admitted"], true);
        assert_eq!(receipt["private_amount"], 20_000_000);
        assert_eq!(receipt["gas_required"], false);
        assert_eq!(receipt["gas_amount"], 0);
        originals.push((claim.id(), request));
        invitation_ids.push(issued["invite_id"].as_str().unwrap().to_owned());
    }
    let claims = fs::read(root.join("claims.json")).unwrap();
    assert_eq!(load(&root).unwrap().1.claims.len(), 10);
    for (id, request) in originals {
        let receipt = access::join(&root, serde_json::from_slice(&request).unwrap()).unwrap();
        assert_eq!(receipt["claim_id"], id);
        assert_eq!(fs::read(root.join("claims.json")).unwrap(), claims);
    }
    assert!(access::issue(&root, &root.join("eleventh.invite"), 3600, None).is_err());
    let (_, extra) = signed(&profile);
    assert!(accept(&root, extra).is_err());
    access::revoke(&root, &invitation_ids[0]).unwrap();
    assert!(access::issue(&root, &root.join("replacement.invite"), 3600, None).is_err());
    assert_eq!(access::info(&root).unwrap()["issued"], 10);
    assert_eq!(fs::read(root.join("claims.json")).unwrap(), claims);
}

#[test]
fn missing_native_admission_state_fails_closed_without_resetting_claim_capacity() {
    let (_directory, root, profile) = fixture(10);
    invited(&root, &profile);
    let claims = fs::read(root.join("claims.json")).unwrap();
    fs::remove_file(root.join("admission.json")).unwrap();
    let (_, claim) = signed(&profile);
    assert!(access::info(&root).is_err());
    assert!(accept(&root, claim).is_err());
    assert_eq!(fs::read(root.join("claims.json")).unwrap(), claims);
    assert!(initialize_native(&root, &root.join("profile.json"), PASSWORD, 10, None).is_err());
}
