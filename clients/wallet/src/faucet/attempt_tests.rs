//! Durable preparation boundaries. The subprocess test actually SIGKILLs a
//! disposable test child; it neither opens a validator nor submits a payment.
use super::native_tests::{fixture, signed};
use super::*;
use std::cell::Cell;

fn reserved() -> (tempfile::TempDir, std::path::PathBuf, Claim, Progress) {
    let (directory, root, profile) = fixture(1);
    let (_, claim) = signed(&profile);
    accept(&root, claim.clone()).unwrap();
    let path = root.join(format!("{}.json", claim.id()));
    let progress = Progress {
        gas_done: true,
        ..Progress::default()
    };
    save(&path, &progress).unwrap();
    (directory, root, claim, progress)
}

#[test]
fn native_readiness_failures_preserve_proof_budget_and_original_claim() {
    let (_directory, root, claim, mut progress) = reserved();
    let path = root.join(format!("{}.json", claim.id()));
    let ledger_before = fs::read(root.join("claims.json")).unwrap();
    let progress_before = fs::read(&path).unwrap();
    let built = Cell::new(false);
    // Both transport and fail-closed validation errors are propagated. No
    // replacement/fallback state or proof authorization is published.
    for message in [
        "history transport disconnected",
        "retained history checksum mismatch",
        "finalized pool checkpoint mismatch",
        "RPC behind retained history",
    ] {
        let result = prepare_native_grant::<()>(
            &path,
            &mut progress,
            || Err(message.into()),
            |_| {
                built.set(true);
                Ok(vec![7; 9222])
            },
        );
        assert_eq!(result.unwrap_err().to_string(), message);
        assert!(!built.get());
        assert_eq!(progress.private_attempts, 0);
        assert_eq!(fs::read(&path).unwrap(), progress_before);
        assert_eq!(fs::read(root.join("claims.json")).unwrap(), ledger_before);
        progress = read_progress(&root, &claim.id(), true).unwrap();
        assert_eq!(accept(&root, claim.clone()).unwrap()["state"], "queued");
    }
    assert_eq!(load(&root).unwrap().1.claims.len(), 1);
}

#[test]
fn native_proof_errors_consume_durable_finite_attempts_after_verified_readiness() {
    let (_directory, root, claim, mut progress) = reserved();
    let path = root.join(format!("{}.json", claim.id()));
    let synced = Cell::new(0);
    for expected in 1..=ATTEMPTS {
        let result = prepare_native_grant(
            &path,
            &mut progress,
            || {
                // Readiness must see the old durable counter.
                assert_eq!(
                    read_progress(&root, &claim.id(), true)?.private_attempts,
                    expected - 1
                );
                synced.set(synced.get() + 1);
                Ok(91u64)
            },
            |verified| {
                assert_eq!(verified, 91);
                assert_eq!(
                    read_progress(&root, &claim.id(), true)?.private_attempts,
                    expected
                );
                Err("proof builder failed".into())
            },
        );
        assert_eq!(result.unwrap_err().to_string(), "proof builder failed");
        progress = read_progress(&root, &claim.id(), true).unwrap();
        assert_eq!(progress.private_attempts, expected);
        assert!(progress.proof.is_none() && !progress.submission_started);
    }
    let result = prepare_native_grant(
        &path,
        &mut progress,
        || {
            synced.set(synced.get() + 1);
            Ok(())
        },
        |_| panic!("exhausted ordinary claim reached proof builder"),
    );
    assert!(result.is_err());
    assert_eq!(synced.get(), u32::from(ATTEMPTS));
    assert_eq!(
        status(&root, &claim, &load(&root).unwrap().1.policy).unwrap()["state"],
        "needs_attention"
    );
}

#[test]
fn native_preparation_crash_child() {
    let Some(root) = std::env::var_os("ZOLANA_GRANT_ATTEMPT_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let phase = std::env::var("ZOLANA_GRANT_ATTEMPT_TEST_PHASE").unwrap();
    assert!(matches!(phase.as_str(), "sync" | "build"));
    let (_, ledger) = load(&root).unwrap();
    assert_eq!(ledger.claims.len(), 1);
    let claim = &ledger.claims[0];
    let _worker = WalletOperation::acquire(&root.join("worker")).unwrap();
    let _source = WalletOperation::acquire(&root.join("wallet.enc.json")).unwrap();
    let mut progress = read_progress(&root, &claim.id(), true).unwrap();
    let pause = || -> Result<()> {
        write_private_new(&root.join("crash-boundary"), phase.as_bytes())?;
        // Finite even if the parent is unexpectedly lost.
        std::thread::sleep(Duration::from_secs(30));
        Err("test parent did not kill its child".into())
    };
    let result = prepare_native_grant(
        &root.join(format!("{}.json", claim.id())),
        &mut progress,
        || if phase == "sync" { pause() } else { Ok(()) },
        |_| {
            pause()?;
            Err("test proof never produced".into())
        },
    );
    panic!("crash child continued unexpectedly: {}", result.is_ok());
}

#[test]
fn native_actual_process_crash_preserves_readiness_and_proof_boundaries() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    for (phase, expected) in [("sync", 0), ("build", 1)] {
        let (_directory, root, claim, _) = reserved();
        let policy_before = fs::read(root.join("claims.json")).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "faucet::attempt_tests::native_preparation_crash_child",
                "--test-threads=1",
            ])
            .env("ZOLANA_GRANT_ATTEMPT_TEST_ROOT", &root)
            .env("ZOLANA_GRANT_ATTEMPT_TEST_PHASE", phase)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.join("crash-boundary").exists() && Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let reached = root.join("crash-boundary").exists();
        let killed = child.kill();
        let exit = child.wait().unwrap();
        assert!(reached, "child did not reach {phase} boundary");
        killed.unwrap();
        assert_eq!(exit.signal(), Some(9));
        let _worker = WalletOperation::acquire(&root.join("worker")).unwrap();
        let _source = WalletOperation::acquire(&root.join("wallet.enc.json")).unwrap();
        let restored = read_progress(&root, &claim.id(), true).unwrap();
        assert_eq!(restored.private_attempts, expected);
        assert!(restored.proof.is_none() && !restored.submission_started && !restored.private_done);
        assert_eq!(fs::read(root.join("claims.json")).unwrap(), policy_before);
    }
}
