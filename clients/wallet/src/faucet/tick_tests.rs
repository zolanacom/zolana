//! The claims pass of one tick: which claims it visits, when it stops, and what
//! is durable before a grant is submitted. No validator is opened and no
//! payment is built or sent. Every chain handed to the pass fails each RPC
//! call, so a pass that succeeds has read and sent nothing; a grant is
//! completed here only from a canonical accepted outcome already on disk.
use super::native_tests::{fixture, signed, PASSWORD};
use super::*;
use std::cell::Cell;

struct Bench {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    profile: TesterProfile,
    wallet: WalletKey,
}

fn bench(capacity: usize) -> Bench {
    let (directory, root, profile) = fixture(capacity);
    let wallet =
        WalletKey::open(&root.join("wallet.enc.json"), PASSWORD, &profile.network()).unwrap();
    Bench {
        _directory: directory,
        root,
        profile,
        wallet,
    }
}

fn queued() -> Progress {
    Progress::default()
}

/// Three preparations used, nothing in flight: waits for the operator.
fn used_up() -> Progress {
    Progress {
        gas_done: true,
        private_attempts: ATTEMPTS,
        ..Progress::default()
    }
}

/// Submission was started and the tick ended before it recorded the result.
fn submitted() -> Progress {
    Progress {
        gas_done: true,
        private_attempts: 1,
        proof: Some(vec![3; 9222]),
        submission_started: true,
        ..Progress::default()
    }
}

impl Bench {
    fn reserve(&self, progress: Progress) -> Claim {
        let (_, claim) = signed(&self.profile);
        accept(&self.root, claim.clone()).unwrap();
        save(&self.progress_path(&claim), &progress).unwrap();
        claim
    }

    fn progress_path(&self, claim: &Claim) -> std::path::PathBuf {
        self.root.join(format!("{}.json", claim.id()))
    }

    fn outcome_path(&self, claim: &Claim) -> std::path::PathBuf {
        self.root.join(format!("{}.outcome.json", claim.id()))
    }

    fn progress(&self, claim: &Claim) -> Progress {
        let native = load(&self.root).unwrap().1.policy.native();
        read_progress(&self.root, &claim.id(), native).unwrap()
    }

    fn bytes(&self, claim: &Claim) -> Vec<u8> {
        fs::read(self.progress_path(claim)).unwrap()
    }

    /// The durable receipt a resolved, accepted payment leaves for its claim.
    fn record_acceptance(&self, claim: &Claim) {
        let signature = Keypair::new().sign_message(b"accepted grant").to_string();
        write_private_new(
            &self.outcome_path(claim),
            &serde_json::to_vec(&json!({"signature":signature,"accepted":true})).unwrap(),
        )
        .unwrap();
    }

    fn journals(&self) -> Vec<std::path::PathBuf> {
        [
            "pending.json",
            "staging.json",
            "native.json",
            "shielded.json",
        ]
        .iter()
        .map(|kind| self.root.join(format!("wallet.enc.json.{kind}")))
        .filter(|path| path.exists())
        .collect()
    }

    fn pass(
        &self,
        connect: &dyn Fn() -> Result<Chain>,
        continuation: Option<(&str, &str)>,
        begin_until: Instant,
    ) -> Result<Value> {
        let (_, ledger) = load(&self.root)?;
        pay_claims(
            &self.root,
            &ledger,
            &self.wallet,
            &Chain::unreachable(self.profile.network()),
            connect,
            None,
            continuation,
            begin_until,
        )
    }
}

fn open_window() -> Instant {
    Instant::now() + TICK_GRANT_WINDOW
}

fn closed_window() -> Instant {
    Instant::now()
}

#[test]
fn exhausted_claim_no_longer_holds_back_the_claim_queued_behind_it() {
    let bench = bench(3);
    let first = bench.reserve(used_up());
    let second = bench.reserve(submitted());
    bench.record_acceptance(&second);
    let untouched = bench.bytes(&first);
    let network = bench.profile.network();
    let connect = || Ok(Chain::unreachable(network.clone()));

    let result = bench.pass(&connect, None, closed_window()).unwrap();
    assert_eq!(result["claim_id"], second.id());
    assert_eq!(result["state"], "ready");
    assert_eq!(result["grants_completed"], 1);
    assert!(bench.progress(&second).private_done);
    // The exhausted claim keeps its exact record and gains no outcome.
    assert_eq!(bench.bytes(&first), untouched);
    assert!(!bench.outcome_path(&first).exists());
    assert!(bench.journals().is_empty());

    // With nothing left to pay the pass is idle and names what still waits.
    let result = bench.pass(&connect, None, closed_window()).unwrap();
    assert_eq!(
        result,
        json!({"idle":true,"reserved_claims":2,"max_claims":3,"needs_attention":1})
    );
    assert_eq!(bench.bytes(&first), untouched);
    assert_eq!(
        status(&bench.root, &first, &load(&bench.root).unwrap().1.policy).unwrap()["state"],
        "needs_attention"
    );
}

#[test]
fn exhausted_claim_is_passed_over_before_any_chain_or_journal_access() {
    let bench = bench(2);
    let claim = bench.reserve(used_up());
    let untouched = bench.bytes(&claim);
    let network = bench.profile.network();
    let calls = Cell::new(0);
    let connect = || {
        calls.set(calls.get() + 1);
        Ok(Chain::unreachable(network.clone()))
    };
    let result = bench.pass(&connect, None, open_window()).unwrap();
    assert_eq!(
        result,
        json!({"idle":true,"reserved_claims":1,"max_claims":2,"needs_attention":1})
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(bench.bytes(&claim), untouched);
    assert!(bench.journals().is_empty());
    for progress in [
        queued(),
        submitted(),
        Progress {
            proof: Some(vec![3; 9222]),
            ..used_up()
        },
        Progress {
            private_attempts: ATTEMPTS - 1,
            ..used_up()
        },
        Progress {
            private_done: true,
            ..used_up()
        },
    ] {
        assert!(!exhausted(&progress));
    }
    assert!(exhausted(&used_up()));
}

#[test]
fn canonical_acceptance_completes_a_claim_whatever_its_attempt_counter_says() {
    let bench = bench(1);
    let claim = bench.reserve(used_up());
    bench.record_acceptance(&claim);
    let network = bench.profile.network();
    let connect = || Ok(Chain::unreachable(network.clone()));
    let result = bench.pass(&connect, None, open_window()).unwrap();
    assert_eq!(result["state"], "ready");
    let progress = bench.progress(&claim);
    assert!(progress.private_done && progress.proof.is_none());
    assert_eq!(progress.private_attempts, ATTEMPTS);
}

#[test]
fn explicit_continuation_still_reaches_its_exhausted_claim() {
    let bench = bench(2);
    let claim = bench.reserve(used_up());
    let other = bench.reserve(used_up());
    let pin = operator_continuation::digest(&bench.bytes(&claim));
    let calls = Cell::new(0);
    let connect = || {
        calls.set(calls.get() + 1);
        Err("continuation reached the chain".into())
    };
    let id = claim.id();
    let error = bench
        .pass(&connect, Some((id.as_str(), pin.as_str())), open_window())
        .unwrap_err();
    assert_eq!(error.to_string(), "continuation reached the chain");
    assert_eq!(calls.get(), 1);
    assert!(bench
        .root
        .join(format!("{id}.operator-continuation.json"))
        .exists());
    assert!(!bench
        .root
        .join(format!("{}.operator-continuation.json", other.id()))
        .exists());
}

#[test]
fn one_tick_begins_the_next_queued_grant_only_while_its_window_is_open() {
    assert_eq!(TICK_GRANT_WINDOW, Duration::from_secs(60));
    for open in [true, false] {
        let bench = bench(3);
        let first = bench.reserve(submitted());
        bench.record_acceptance(&first);
        let second = bench.reserve(queued());
        let untouched = bench.bytes(&second);
        let network = bench.profile.network();
        let calls = Cell::new(0);
        // The first grant is completed from its recorded outcome. A second
        // grant would have to read the chain, which this test withholds.
        let connect = || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok(Chain::unreachable(network.clone()))
            } else {
                Err("second grant reached the chain".into())
            }
        };
        let window = if open { open_window() } else { closed_window() };
        let result = bench.pass(&connect, None, window);
        assert!(bench.progress(&first).private_done);
        if open {
            assert_eq!(
                result.unwrap_err().to_string(),
                "second grant reached the chain"
            );
            assert_eq!(calls.get(), 2);
            let begun = bench.progress(&second);
            assert!(begun.gas_done && !begun.submission_started && begun.proof.is_none());
            assert_eq!(begun.private_attempts, 0);
        } else {
            let result = result.unwrap();
            assert_eq!(result["claim_id"], first.id());
            assert_eq!(result["state"], "ready");
            assert_eq!(result["grants_completed"], 1);
            assert_eq!(calls.get(), 1);
            assert_eq!(bench.bytes(&second), untouched);
        }
        assert!(bench.journals().is_empty());
    }
}

#[test]
fn one_native_tick_completes_several_grants_in_ledger_order_and_reports_the_last() {
    // Paying needs a chain. Two recorded acceptances stand in for two grants
    // that complete in one tick; the pass itself is the production code.
    let bench = bench(3);
    let first = bench.reserve(submitted());
    let second = bench.reserve(submitted());
    bench.record_acceptance(&first);
    bench.record_acceptance(&second);
    let network = bench.profile.network();
    let connect = || Ok(Chain::unreachable(network.clone()));
    let result = bench.pass(&connect, None, open_window()).unwrap();
    assert_eq!(result["claim_id"], second.id());
    assert_eq!(result["grants_completed"], 2);
    for claim in [&first, &second] {
        let progress = bench.progress(claim);
        assert!(progress.private_done);
        // Nothing was prepared again for a grant that was already submitted.
        assert_eq!(progress.private_attempts, 1);
        assert_eq!(progress.proof, Some(vec![3; 9222]));
    }
    // A completed grant is never visited again.
    let settled = [bench.bytes(&first), bench.bytes(&second)];
    let result = bench.pass(&connect, None, open_window()).unwrap();
    assert_eq!(
        result,
        json!({"idle":true,"reserved_claims":2,"max_claims":3})
    );
    assert_eq!([bench.bytes(&first), bench.bytes(&second)], settled);
}

#[test]
fn policies_other_than_the_native_cohort_still_complete_one_grant_a_tick() {
    let directory = tempfile::tempdir().unwrap();
    let (_native, _, profile) = fixture(1);
    let file = directory.path().join("source.json");
    fs::write(&file, serde_json::to_vec(&profile).unwrap()).unwrap();
    let root = directory.path().join("faucet");
    initialize(&root, &file, PASSWORD, 2).unwrap();
    let bench = Bench {
        wallet: WalletKey::open(&root.join("wallet.enc.json"), PASSWORD, &profile.network())
            .unwrap(),
        _directory: directory,
        root,
        profile,
    };
    let funded = || Progress {
        gas_attempts: 1,
        gas: Some(Gas {
            transaction: vec![1],
            last_valid_block_height: 1,
        }),
        ..submitted()
    };
    let first = bench.reserve(funded());
    let second = bench.reserve(funded());
    bench.record_acceptance(&first);
    bench.record_acceptance(&second);
    let waiting = bench.bytes(&second);
    let network = bench.profile.network();
    let connect = || Ok(Chain::unreachable(network.clone()));
    let result = bench.pass(&connect, None, open_window()).unwrap();
    assert_eq!(result["claim_id"], first.id());
    assert!(result.get("grants_completed").is_none());
    assert!(bench.progress(&first).private_done);
    assert_eq!(bench.bytes(&second), waiting);
}

#[test]
fn submission_mark_and_proof_are_durable_before_every_submit() {
    let bench = bench(1);
    let claim = bench.reserve(Progress {
        submission_started: false,
        ..submitted()
    });
    let path = bench.progress_path(&claim);
    for cleanup_recorded in [true, false] {
        let mut progress = bench.progress(&claim);
        progress.submission_started = false;
        progress.private_done = false;
        save(&path, &progress).unwrap();
        submit_grant(&path, &mut progress, |proof| {
            let durable = bench.progress(&claim);
            assert!(durable.submission_started && !durable.private_done);
            assert_eq!(durable.proof.as_deref(), Some(proof));
            assert_eq!(proof, vec![3u8; 9222].as_slice());
            Ok(cleanup_recorded)
        })
        .unwrap();
        assert_eq!(progress.private_done, !cleanup_recorded);
        assert_eq!(bench.progress(&claim).private_done, !cleanup_recorded);
    }
    // A failed submission keeps the mark and the exact proof for recovery.
    let mut progress = bench.progress(&claim);
    progress.submission_started = false;
    progress.private_done = false;
    save(&path, &progress).unwrap();
    let error = submit_grant(&path, &mut progress, |_| Err("broadcast lost".into())).unwrap_err();
    assert_eq!(error.to_string(), "broadcast lost");
    let durable = bench.progress(&claim);
    assert!(durable.submission_started && !durable.private_done);
    assert_eq!(durable.proof, Some(vec![3; 9222]));
    // Without a proof nothing is submitted.
    let mut empty = used_up();
    assert!(submit_grant(&path, &mut empty, |_| panic!("submitted without a proof")).is_err());
}

#[test]
fn submission_crash_child() {
    let Some(root) = std::env::var_os("ZOLANA_GRANT_SUBMIT_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let (_, ledger) = load(&root).unwrap();
    let claim = ledger.claims.last().unwrap();
    let _worker = WalletOperation::acquire(&root.join("worker")).unwrap();
    let _source = WalletOperation::acquire(&root.join("wallet.enc.json")).unwrap();
    let mut progress = read_progress(&root, &claim.id(), true).unwrap();
    let result = submit_grant(
        &root.join(format!("{}.json", claim.id())),
        &mut progress,
        |_| {
            write_private_new(&root.join("crash-boundary"), b"submit")?;
            // Finite even if the parent is unexpectedly lost.
            std::thread::sleep(Duration::from_secs(30));
            Err("test parent did not kill its child".into())
        },
    );
    panic!("crash child continued unexpectedly: {}", result.is_ok());
}

#[test]
fn tick_killed_inside_a_later_submission_pays_nothing_twice() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    let bench = bench(3);
    // The tick had completed one grant and was submitting the next.
    let completed = bench.reserve(Progress {
        private_done: true,
        ..submitted()
    });
    let interrupted = bench.reserve(Progress {
        submission_started: false,
        ..submitted()
    });
    let settled = bench.bytes(&completed);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "faucet::tick_tests::submission_crash_child",
            "--test-threads=1",
        ])
        .env("ZOLANA_GRANT_SUBMIT_TEST_ROOT", &bench.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !bench.root.join("crash-boundary").exists() && Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let reached = bench.root.join("crash-boundary").exists();
    let killed = child.kill();
    let exit = child.wait().unwrap();
    assert!(reached, "child did not reach the submit boundary");
    killed.unwrap();
    assert_eq!(exit.signal(), Some(9));

    let durable = bench.progress(&interrupted);
    assert!(durable.submission_started && !durable.private_done);
    assert_eq!(durable.proof, Some(vec![3; 9222]));
    let interrupted_record = bench.bytes(&interrupted);

    // No journal and no canonical outcome survive in this fixture, so the next
    // tick has no evidence either way. It must stop, not prepare or send again.
    let network = bench.profile.network();
    let connect = || Ok(Chain::unreachable(network.clone()));
    for _ in 0..2 {
        let error = bench.pass(&connect, None, open_window()).unwrap_err();
        assert!(error
            .to_string()
            .contains("funding outcome and upload record are missing"));
        assert_eq!(bench.bytes(&interrupted), interrupted_record);
        assert_eq!(bench.bytes(&completed), settled);
        assert!(bench.journals().is_empty());
    }

    // Once canonical history has recorded the original payment as accepted the
    // grant is completed from that record alone; the failing chain proves that
    // nothing was read, prepared or sent for it.
    bench.record_acceptance(&interrupted);
    let result = bench.pass(&connect, None, open_window()).unwrap();
    assert_eq!(result["claim_id"], interrupted.id());
    assert_eq!(result["grants_completed"], 1);
    let recovered = bench.progress(&interrupted);
    assert!(recovered.private_done);
    assert_eq!(recovered.private_attempts, 1);
    assert_eq!(recovered.proof, Some(vec![3; 9222]));
    assert_eq!(bench.bytes(&completed), settled);
}
