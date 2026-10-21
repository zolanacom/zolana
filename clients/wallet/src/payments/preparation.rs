//! Prepare only public circuit material while the caller unlocks/connects.
//! Neither a wallet nor payment state can be passed to this worker API.
use super::PaymentProver;
use crate::Result;
use std::{
    sync::{Arc, OnceLock},
    thread,
    time::Instant,
};

// Only the deterministic public circuit key survives between commands. Wallet
// keys, notes, witnesses, randomness and submitted proofs never enter this cache.
static PUBLIC_PROVER: OnceLock<Arc<PaymentProver>> = OnceLock::new();

/// Reuse public verification material only if a command already prepared it.
/// This never generates a key and does not change any history verification.
pub fn cached_prover() -> Option<Arc<PaymentProver>> {
    PUBLIC_PROVER.get().cloned()
}

/// Actual construction time and the remaining wait on the caller's path.
/// These overlap other startup work and must not be added to it as sequential
/// durations. No wallet, witness, seed or proof enters these measurements.
#[derive(Debug, serde::Serialize)]
pub struct PreparationTimings {
    pub proof_key_ms: u128,
    pub proof_key_wait_ms: u128,
    pub proof_key_cached: bool,
}

/// One owned public-key worker. Dropping it joins before returning, including
/// when wallet unlock, connection or fee validation exits early with an error.
#[must_use = "finish preparation before proving; dropping it waits for cleanup"]
pub struct ProverPreparation {
    state: PreparationState,
}

enum PreparationState {
    Ready(Arc<PaymentProver>),
    Pending(PreparationWorker<CachedProver>),
}

struct CachedProver {
    prover: Arc<PaymentProver>,
    proof_key_ms: u128,
    constructed: bool,
}

impl ProverPreparation {
    /// Begin the fixed public circuit-key computation. No secret or payment
    /// input is accepted; this neither constructs nor submits a payment.
    pub fn start() -> Result<Self> {
        if let Some(prover) = PUBLIC_PROVER.get() {
            return Ok(Self {
                state: PreparationState::Ready(prover.clone()),
            });
        }
        Ok(Self {
            state: PreparationState::Pending(PreparationWorker::start(|| {
                let mut proof_key_ms = 0;
                let mut constructed = false;
                let prover = PUBLIC_PROVER
                    .get_or_init(|| {
                        let began = Instant::now();
                        let prover = Arc::new(PaymentProver::new());
                        proof_key_ms = began.elapsed().as_millis();
                        constructed = true;
                        prover
                    })
                    .clone();
                CachedProver {
                    prover,
                    proof_key_ms,
                    constructed,
                }
            })?),
        })
    }

    /// Obtain the sole key or fail closed if its worker panicked. This never
    /// starts a second key computation or falls back to replacement work.
    pub fn finish(self) -> Result<(Arc<PaymentProver>, PreparationTimings)> {
        match self.state {
            PreparationState::Ready(prover) => Ok((
                prover,
                PreparationTimings {
                    proof_key_ms: 0,
                    proof_key_wait_ms: 0,
                    proof_key_cached: true,
                },
            )),
            PreparationState::Pending(worker) => {
                let (cached, mut timing) = worker.finish()?;
                timing.proof_key_ms = cached.proof_key_ms;
                timing.proof_key_cached = !cached.constructed;
                Ok((cached.prover, timing))
            }
        }
    }
}

// Generic only inside this private module so scheduling/error paths can be
// tested without repeatedly computing expensive cryptographic keys.
struct PreparationWorker<T> {
    handle: Option<thread::JoinHandle<(T, u128)>>,
}

impl<T: Send + 'static> PreparationWorker<T> {
    fn start(work: impl FnOnce() -> T + Send + 'static) -> std::io::Result<Self> {
        let handle = thread::Builder::new()
            .name("payment-proving-key".into())
            .spawn(move || {
                let began = Instant::now();
                let result = work();
                (result, began.elapsed().as_millis())
            })?;
        Ok(Self {
            handle: Some(handle),
        })
    }
}

impl<T> PreparationWorker<T> {
    fn finish(mut self) -> Result<(T, PreparationTimings)> {
        let began = Instant::now();
        let handle = self.handle.take().ok_or("public key worker is missing")?;
        let (result, proof_key_ms) = handle
            .join()
            .map_err(|_| "public proving-key preparation worker panicked")?;
        Ok((
            result,
            PreparationTimings {
                proof_key_ms,
                proof_key_wait_ms: began.elapsed().as_millis(),
                proof_key_cached: false,
            },
        ))
    }
}

impl<T> Drop for PreparationWorker<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // Cleanup must not detach a worker or double-panic while the caller
            // unwinds. The only success path obtains the key through finish().
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    };
    use std::time::Duration;

    const LIMIT: Duration = Duration::from_secs(3);

    #[test]
    fn ready_public_prover_is_shared_without_another_worker_or_wait() {
        let (first, _) = ProverPreparation::start().unwrap().finish().unwrap();
        let (second, timing) = ProverPreparation::start().unwrap().finish().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(timing.proof_key_cached);
        assert_eq!(timing.proof_key_ms, 0);
        assert_eq!(timing.proof_key_wait_ms, 0);
    }

    #[test]
    fn public_preparation_starts_before_finish_and_runs_once() {
        let (started, observed_start) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = calls.clone();
        let worker = PreparationWorker::start(move || {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            started.send(()).unwrap();
            released.recv_timeout(LIMIT).unwrap();
            42
        })
        .unwrap();
        observed_start.recv_timeout(LIMIT).unwrap();
        // Caller work can proceed before it needs the public key.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        let (value, _) = worker.finish().unwrap();
        assert_eq!(value, 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn finish_waits_until_the_owned_worker_completes() {
        let (started, observed_start) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let worker = PreparationWorker::start(move || {
            started.send(()).unwrap();
            released.recv_timeout(LIMIT).unwrap();
            42
        })
        .unwrap();
        observed_start.recv_timeout(LIMIT).unwrap();
        let (finishing, observed_finish) = mpsc::sync_channel(1);
        let (finished, observed_finished) = mpsc::sync_channel(1);
        let caller = thread::spawn(move || {
            finishing.send(()).unwrap();
            let result = worker.finish().map(|(value, _)| value);
            finished
                .send(result.map_err(|error| error.to_string()))
                .unwrap();
        });
        observed_finish.recv_timeout(LIMIT).unwrap();
        assert!(observed_finished.try_recv().is_err());
        release.send(()).unwrap();
        assert_eq!(observed_finished.recv_timeout(LIMIT).unwrap(), Ok(42));
        caller.join().unwrap();
    }

    #[test]
    fn early_error_joins_public_preparation_before_returning() {
        let (started, observed_start) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let complete = Arc::new(AtomicBool::new(false));
        let worker_complete = complete.clone();
        let worker = PreparationWorker::start(move || {
            started.send(()).unwrap();
            released.recv_timeout(LIMIT).unwrap();
            worker_complete.store(true, Ordering::SeqCst);
        })
        .unwrap();
        observed_start.recv_timeout(LIMIT).unwrap();
        let (exiting, observed_exit) = mpsc::sync_channel(1);
        let (exited, observed_exited) = mpsc::sync_channel(1);
        let caller = thread::spawn(move || {
            let fail = || -> Result<()> {
                let _owned_worker = worker;
                exiting.send(()).unwrap();
                Err("wallet unlock failed".into())
            };
            exited.send(fail().unwrap_err().to_string()).unwrap();
        });
        observed_exit.recv_timeout(LIMIT).unwrap();
        assert!(!complete.load(Ordering::SeqCst));
        assert!(observed_exited.try_recv().is_err());
        release.send(()).unwrap();
        assert_eq!(
            observed_exited.recv_timeout(LIMIT).unwrap(),
            "wallet unlock failed"
        );
        assert!(complete.load(Ordering::SeqCst));
        caller.join().unwrap();
    }

    #[test]
    fn worker_panic_cannot_produce_a_prepared_key() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = calls.clone();
        let worker = PreparationWorker::start(move || -> () {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            panic!("simulated public key construction failure");
        })
        .unwrap();
        let error = worker.finish().unwrap_err().to_string();
        assert_eq!(error, "public proving-key preparation worker panicked");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cleanup_during_an_error_does_not_double_panic() {
        let worker = PreparationWorker::start(|| -> () {
            panic!("simulated public key construction failure");
        })
        .unwrap();
        let caller = thread::spawn(move || {
            let _owned_worker = worker;
            panic!("original caller failure");
        });
        let payload = caller.join().unwrap_err();
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"original caller failure")
        );
    }
}
