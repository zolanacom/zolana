//! Bounded read-only invited history fetching. Replay stays on the caller thread.
use crate::archive::HistoryBlock;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::{
    client_error::{Error as RpcClientError, ErrorKind},
    request::{RpcError, RpcRequest},
};
use solana_transaction_status_client_types::UiConfirmedBlock;

pub(super) const PAGE: usize = 256;
pub(super) const LEGACY_PAGE: usize = 16;
// Leave two of the shared gateway's four slots for other wallets/control reads.
pub(super) const WORKERS: usize = 2;
pub(super) const WINDOW: usize = PAGE * WORKERS;
const SIZE_ERROR_CODE: i64 = -32062;
const SIZE_ERROR_MESSAGE: &str = "Wallet history response exceeds byte limit";

fn retryable_transport(error: &RpcClientError) -> bool {
    let ErrorKind::Reqwest(error) = error.kind() else {
        return false;
    };
    // HTTP denials/rate limits and invalid JSON are authoritative failures,
    // never a reason to repeat admission or relax any page verification.
    if error.status().is_some() || error.is_builder() || error.is_redirect() || error.is_decode() {
        return false;
    }
    if error.is_connect() || error.is_timeout() || error.is_body() {
        return true;
    }
    if !error.is_request() {
        return false;
    }
    // A request error may wrap an actual reset/closed socket. Do not infer
    // retry eligibility from its displayed message or arbitrary RPC strings.
    let mut cause = std::error::Error::source(error);
    while let Some(current) = cause {
        if current
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::TimedOut
                )
            })
        {
            return true;
        }
        cause = current.source();
    }
    false
}

/// Repeat at most once after a typed transport failure, for these immutable
/// history reads only. The same client retains its TLS endpoint/access proof;
/// parameters retain the exact finalized target, slots and pinned page token.
pub(super) fn history_read<T: DeserializeOwned>(
    rpc: &RpcClient,
    method: &'static str,
    params: serde_json::Value,
) -> Result<T, RpcClientError> {
    if !matches!(
        method,
        "getWalletHistoryBlocks" | "getWalletRetainedHistoryV2"
    ) {
        return Err(
            RpcError::RpcRequestError("bounded history read method required".into()).into(),
        );
    }
    match rpc.send(RpcRequest::Custom { method }, params.clone()) {
        Err(error) if retryable_transport(&error) => {
            rpc.send(RpcRequest::Custom { method }, params)
        }
        result => result,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FetchError {
    ResponseTooLarge,
    Invalid(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResponseTooLarge => out.write_str(SIZE_ERROR_MESSAGE),
            Self::Invalid(message) => out.write_str(message),
        }
    }
}

impl std::error::Error for FetchError {}

fn rpc_error(error: RpcClientError) -> FetchError {
    match error.kind() {
        ErrorKind::RpcError(RpcError::RpcResponseError { code, message, .. })
            if *code == SIZE_ERROR_CODE && message == SIZE_ERROR_MESSAGE =>
        {
            FetchError::ResponseTooLarge
        }
        _ => FetchError::Invalid(format!(
            "cannot read complete finalized history batch; an updated invited gateway is required: {error}"
        )),
    }
}

fn remember_error(saved: &mut Option<FetchError>, error: FetchError) {
    if saved.is_none()
        || (matches!(saved, Some(FetchError::ResponseTooLarge))
            && !matches!(error, FetchError::ResponseTooLarge))
    {
        *saved = Some(error);
    }
}

pub(super) fn invited_history_blocks(
    rpc: &RpcClient,
    slots: &[u64],
) -> Result<Vec<HistoryBlock>, FetchError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Block {
        slot: u64,
        block: UiConfirmedBlock,
    }
    if slots.is_empty()
        || slots.len() > PAGE
        || slots[0] == 0
        || slots.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(FetchError::Invalid(
            "invalid history request size or order".into(),
        ));
    }
    let blocks: Vec<Block> =
        history_read(rpc, "getWalletHistoryBlocks", serde_json::json!([slots]))
            .map_err(rpc_error)?;
    if blocks.len() != slots.len()
        || blocks
            .iter()
            .zip(slots)
            .any(|(block, slot)| block.slot != *slot)
    {
        return Err(FetchError::Invalid(
            "history batch omitted, reordered or substituted a requested block".into(),
        ));
    }
    blocks
        .into_iter()
        .map(|block| {
            HistoryBlock::from_rpc(block.slot, block.block)
                .map_err(|error| FetchError::Invalid(error.to_string()))
        })
        .collect()
}

/// Fetch at most two 256-block pages. All workers are joined before any
/// result or error escapes; no partial window is available for replay/cache writes.
/// Only the thread-safe RPC client belongs in `fetch`, never wallet authorization.
pub(super) fn ordered_window<T, F>(slots: &[u64], fetch: F) -> Result<Vec<T>, FetchError>
where
    T: Send,
    F: Fn(&[u64]) -> Result<Vec<T>, FetchError> + Sync,
{
    if slots.is_empty()
        || slots.len() > WINDOW
        || slots[0] == 0
        || slots.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(FetchError::Invalid(
            "expected 1..512 strictly ordered finalized history slots".into(),
        ));
    }
    std::thread::scope(|scope| {
        let fetch = &fetch;
        let workers: Vec<_> = slots
            .chunks(PAGE)
            .map(|page| (page.len(), scope.spawn(move || fetch(page))))
            .collect();
        let mut pages = Vec::with_capacity(workers.len());
        let mut first_error = None;
        for (length, worker) in workers {
            match worker.join() {
                Ok(Ok(page)) if page.len() == length => pages.push(page),
                Ok(Ok(_)) => {
                    remember_error(
                        &mut first_error,
                        FetchError::Invalid(
                            "history fetch page omitted or added blocks".to_string(),
                        ),
                    );
                }
                Ok(Err(error)) => {
                    remember_error(&mut first_error, error);
                }
                Err(_) => {
                    remember_error(
                        &mut first_error,
                        FetchError::Invalid("finalized history fetch worker panicked".to_string()),
                    );
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(pages.into_iter().flatten().collect())
    })
}

#[derive(Default, Debug)]
pub(super) struct FallbackStats {
    pub requests: usize,
    pub splits: usize,
    pub fetch_ms: u128,
}

/// Dense history is replayed and dropped one bounded page at a time. Never
/// concatenate recursive children: their combined bytes may exceed a reply cap.
/// Only the exact typed size error authorizes a smaller request; all other
/// failures stop immediately, leaving durable cache publication to the caller.
pub(super) fn replay_legacy_pages<T, F, A>(
    slots: &[u64],
    mut fetch: F,
    mut apply: A,
) -> Result<FallbackStats, FetchError>
where
    F: FnMut(&[u64]) -> Result<Vec<T>, FetchError>,
    A: FnMut(T) -> Result<(), FetchError>,
{
    if slots.is_empty()
        || slots.len() > WINDOW
        || slots[0] == 0
        || slots.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(FetchError::Invalid(
            "invalid bounded fallback window".into(),
        ));
    }
    fn page<T, F, A>(
        slots: &[u64],
        fetch: &mut F,
        apply: &mut A,
        stats: &mut FallbackStats,
    ) -> Result<(), FetchError>
    where
        F: FnMut(&[u64]) -> Result<Vec<T>, FetchError>,
        A: FnMut(T) -> Result<(), FetchError>,
    {
        let began = std::time::Instant::now();
        stats.requests += 1;
        let result = fetch(slots);
        stats.fetch_ms += began.elapsed().as_millis();
        match result {
            Ok(items) => {
                if items.len() != slots.len() {
                    return Err(FetchError::Invalid(
                        "history fallback omitted or added blocks".into(),
                    ));
                }
                for item in items {
                    apply(item)?;
                }
                Ok(())
            }
            Err(FetchError::ResponseTooLarge) if slots.len() > 1 => {
                stats.splits += 1;
                let middle = slots.len() / 2;
                page(&slots[..middle], fetch, apply, stats)?;
                page(&slots[middle..], fetch, apply, stats)
            }
            Err(error) => Err(error),
        }
    }
    let mut stats = FallbackStats::default();
    for slots in slots.chunks(LEGACY_PAGE) {
        page(slots, &mut fetch, &mut apply, &mut stats)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier, Condvar, Mutex,
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::{Duration, Instant},
    };

    #[derive(Clone)]
    enum Reply {
        Reset,
        Http(u16, &'static str),
    }

    fn read_fixture(
        replies: Vec<Reply>,
    ) -> (RpcClient, std::thread::JoinHandle<Vec<serde_json::Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let mut received = Vec::new();
            let mut deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("history fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut wire = Vec::new();
                let header_end = loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    wire.push(byte[0]);
                    assert!(wire.len() < 8192);
                    if wire.ends_with(b"\r\n\r\n") {
                        break wire.len();
                    }
                };
                let headers = String::from_utf8(wire.clone()).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                assert!(length <= 32768);
                wire.resize(header_end + length, 0);
                let reply = replies
                    .get(received.len())
                    .unwrap_or_else(|| replies.last().unwrap());
                if matches!(reply, Reply::Reset) {
                    // Observe the complete request but leave its final byte
                    // unread. Closing a TCP socket with unread input causes a
                    // real peer reset without unsafe socket-option calls.
                    let end = wire.len();
                    stream.read_exact(&mut wire[header_end..end - 1]).unwrap();
                    assert_eq!(stream.peek(&mut wire[end - 1..]).unwrap(), 1);
                } else {
                    stream.read_exact(&mut wire[header_end..]).unwrap();
                }
                let request: serde_json::Value =
                    serde_json::from_slice(&wire[header_end..]).unwrap();
                let routing: Vec<_> = headers
                    .lines()
                    .filter_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        (name.eq_ignore_ascii_case("host")
                            || name.eq_ignore_ascii_case("x-testnet-access"))
                        .then(|| (name.to_ascii_lowercase(), value.trim().to_string()))
                    })
                    .collect();
                received.push(serde_json::json!({"method":request["method"],"params":request["params"],"routing":routing}));
                match reply {
                    Reply::Reset => drop(stream),
                    Reply::Http(status, body) => {
                        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nRetry-After: 0\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    }
                }
                if received.len() >= replies.len() {
                    deadline = Instant::now() + Duration::from_millis(100);
                }
                assert!(received.len() <= 8, "unbounded history retry");
            }
            received
        });
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("X-Testnet-Access", "fixture-access".parse().unwrap());
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let rpc = RpcClient::new_sender(
            solana_rpc_client::http_sender::HttpSender::new_with_client(url, http),
            solana_rpc_client::rpc_client::RpcClientConfig::default(),
        );
        (rpc, worker)
    }

    #[test]
    fn history_transport_reset_retries_exact_inputs_for_both_read_methods() {
        for (method, params) in [
            ("getWalletHistoryBlocks", serde_json::json!([[11, 13, 17]])),
            (
                "getWalletRetainedHistoryV2",
                serde_json::json!([17, 99, {"segments":4,"sha256":"a".repeat(64)}, 32768]),
            ),
        ] {
            let (rpc, worker) = read_fixture(vec![
                Reply::Reset,
                Reply::Http(200, r#"{"jsonrpc":"2.0","id":1,"result":7}"#),
            ]);
            assert_eq!(
                history_read::<u64>(&rpc, method, params.clone()).unwrap(),
                7
            );
            let calls = worker.join().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0], calls[1]);
            assert_eq!(calls[0]["method"], method);
            assert_eq!(calls[0]["params"], params);
        }
    }

    #[test]
    fn history_transport_retry_is_finite_and_refuses_status_rpc_json_and_other_methods() {
        let (rpc, worker) = read_fixture(vec![Reply::Reset, Reply::Reset]);
        assert!(
            history_read::<u64>(&rpc, "getWalletHistoryBlocks", serde_json::json!([[1]])).is_err()
        );
        assert_eq!(worker.join().unwrap().len(), 2);
        for (replies, count) in [
            (vec![Reply::Http(403, r#"{"error":"access_denied"}"#)], 1),
            // The existing Agave sender performs five429 retries. This wrapper
            // adds none, and never changes the durable admission policy.
            (vec![Reply::Http(429, r#"{"error":"request_limit"}"#); 6], 6),
            (
                vec![Reply::Http(
                    200,
                    r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32000,"message":"connection reset"}}"#,
                )],
                1,
            ),
            (vec![Reply::Http(200, "invalid JSON")], 1),
            (
                vec![Reply::Http(
                    200,
                    r#"{"jsonrpc":"2.0","id":0,"result":"wrong type"}"#,
                )],
                1,
            ),
        ] {
            let (rpc, worker) = read_fixture(replies);
            assert!(history_read::<u64>(
                &rpc,
                "getWalletRetainedHistoryV2",
                serde_json::json!([0, 99, null, 32768])
            )
            .is_err());
            assert_eq!(worker.join().unwrap().len(), count);
        }
        let rpc = RpcClient::new_mock("fails");
        for method in [
            "submitShieldedPayment",
            "sendTransaction",
            "getWalletRetainedHistory",
        ] {
            let error = history_read::<u64>(&rpc, method, serde_json::json!([])).unwrap_err();
            assert!(
                matches!(error.kind(), ErrorKind::RpcError(RpcError::RpcRequestError(message))
                if message == "bounded history read method required")
            );
        }
    }

    #[test]
    fn invited_history_invalid_page_is_not_retried() {
        let (rpc, worker) = read_fixture(vec![Reply::Http(
            200,
            r#"{"jsonrpc":"2.0","id":0,"result":[]}"#,
        )]);
        assert!(invited_history_blocks(&rpc, &[11, 13])
            .err()
            .unwrap()
            .to_string()
            .contains("omitted"));
        assert_eq!(worker.join().unwrap().len(), 1);
    }

    #[test]
    fn bounded_out_of_order_pages_return_only_in_canonical_order() {
        let slots: Vec<u64> = (1..=WINDOW as u64).collect();
        let barrier = Barrier::new(WORKERS);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let turn = (Mutex::new(WORKERS - 1), Condvar::new());
        let finished = Mutex::new(Vec::new());
        let fetched = ordered_window(&slots, |page| {
            let index = (page[0] as usize - 1) / PAGE;
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            barrier.wait();
            let (lock, ready) = &turn;
            let mut current = ready
                .wait_while(lock.lock().unwrap(), |current| *current != index)
                .unwrap();
            finished.lock().unwrap().push(index);
            *current = current.saturating_sub(1);
            ready.notify_all();
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(page.to_vec())
        })
        .unwrap();
        assert_eq!(fetched, slots);
        assert_eq!(
            *finished.lock().unwrap(),
            (0..WORKERS).rev().collect::<Vec<_>>()
        );
        assert_eq!(peak.load(Ordering::SeqCst), WORKERS);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_error_joins_every_other_page_without_returning_partial_output() {
        let slots: Vec<u64> = (1..=WINDOW as u64).collect();
        let barrier = Barrier::new(WORKERS);
        let completed = AtomicUsize::new(0);
        let result = ordered_window(&slots, |page| {
            barrier.wait();
            if page[0] == 1 {
                return Err(FetchError::Invalid("original page unavailable".to_string()));
            }
            completed.fetch_add(1, Ordering::SeqCst);
            Ok(page.to_vec())
        });
        assert_eq!(
            result.unwrap_err(),
            FetchError::Invalid("original page unavailable".into())
        );
        assert_eq!(completed.load(Ordering::SeqCst), WORKERS - 1);
    }

    #[test]
    fn a_panicking_page_is_joined_and_other_workers_finish_before_error() {
        let slots: Vec<u64> = (1..=WINDOW as u64).collect();
        let barrier = Barrier::new(WORKERS);
        let completed = AtomicUsize::new(0);
        let result = ordered_window(&slots, |page| {
            barrier.wait();
            assert_ne!(page[0], 1, "simulated history worker panic");
            completed.fetch_add(1, Ordering::SeqCst);
            Ok(page.to_vec())
        });
        assert!(result.unwrap_err().to_string().contains("worker panicked"));
        assert_eq!(completed.load(Ordering::SeqCst), WORKERS - 1);
    }

    #[test]
    fn empty_oversized_zero_duplicate_or_unordered_windows_never_start_fetches() {
        let calls = AtomicUsize::new(0);
        for slots in [
            vec![],
            (1..=WINDOW as u64 + 1).collect(),
            vec![0],
            vec![1, 1],
            vec![2, 1],
        ] {
            assert!(ordered_window(&slots, |page| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(page.to_vec())
            })
            .is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn incomplete_page_fails_the_complete_window_after_joining_all_workers() {
        let slots: Vec<u64> = (1..=WINDOW as u64).collect();
        let completed = AtomicUsize::new(0);
        let result = ordered_window(&slots, |page| {
            completed.fetch_add(1, Ordering::SeqCst);
            Ok(if page[0] == 1 { vec![] } else { page.to_vec() })
        });
        assert!(result.unwrap_err().to_string().contains("omitted or added"));
        assert_eq!(completed.load(Ordering::SeqCst), WORKERS);
    }

    #[test]
    fn a_partial_final_page_stays_bounded_and_preserves_requested_order() {
        let sizes = Mutex::new(Vec::new());
        let slots: Vec<u64> = (1..=PAGE as u64 + 1).collect();
        let fetched = ordered_window(&slots, |page| {
            sizes.lock().unwrap().push(page.len());
            Ok(page.to_vec())
        })
        .unwrap();
        let mut actual = sizes.into_inner().unwrap();
        actual.sort_unstable();
        assert_eq!(actual, vec![1, PAGE]);
        assert_eq!(fetched, slots);
    }

    #[test]
    fn only_exact_typed_history_size_errors_allow_fallback() {
        use solana_rpc_client_api::request::RpcResponseErrorData;
        let response = |code, message: &str| {
            RpcClientError::from(RpcError::RpcResponseError {
                code,
                message: message.into(),
                data: RpcResponseErrorData::Empty,
            })
        };
        assert_eq!(
            rpc_error(response(SIZE_ERROR_CODE, SIZE_ERROR_MESSAGE)),
            FetchError::ResponseTooLarge
        );
        for error in [
            response(-403, SIZE_ERROR_MESSAGE),
            response(-429, SIZE_ERROR_MESSAGE),
            response(SIZE_ERROR_CODE, "different message"),
            RpcClientError::from(RpcError::RpcRequestError(SIZE_ERROR_MESSAGE.into())),
            RpcClientError::from(ErrorKind::Custom(format!(
                "{SIZE_ERROR_CODE}: {SIZE_ERROR_MESSAGE}"
            ))),
        ] {
            assert!(matches!(rpc_error(error), FetchError::Invalid(_)));
        }
    }

    #[test]
    fn size_failure_discards_all_joined_window_output() {
        let slots: Vec<_> = (1..=WINDOW as u64).collect();
        let completed = AtomicUsize::new(0);
        let result = ordered_window(&slots, |page| {
            completed.fetch_add(1, Ordering::SeqCst);
            if page[0] == 1 {
                Err(FetchError::ResponseTooLarge)
            } else {
                Ok(page.to_vec())
            }
        });
        assert_eq!(result.unwrap_err(), FetchError::ResponseTooLarge);
        assert_eq!(completed.load(Ordering::SeqCst), WORKERS);
    }

    #[test]
    fn an_unexpected_worker_error_overrides_size_failure_in_either_order() {
        let slots: Vec<_> = (1..=WINDOW as u64).collect();
        for first_size in [false, true] {
            let result: Result<Vec<u64>, _> = ordered_window(&slots, |page| {
                if (page[0] == 1) == first_size {
                    Err(FetchError::ResponseTooLarge)
                } else {
                    Err(FetchError::Invalid("authorization refused".into()))
                }
            });
            assert_eq!(
                result.unwrap_err(),
                FetchError::Invalid("authorization refused".into())
            );
        }
    }

    #[test]
    fn dense_pages_bisect_sequentially_and_drop_payloads_before_the_next_fetch() {
        struct Payload<'a> {
            slot: u64,
            live: &'a AtomicUsize,
        }
        impl Drop for Payload<'_> {
            fn drop(&mut self) {
                self.live.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let live = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let mut replayed = Vec::new();
        let slots: Vec<_> = (1..=LEGACY_PAGE as u64 * 2).collect();
        let stats = replay_legacy_pages(
            &slots,
            |page| {
                assert_eq!(
                    live.load(Ordering::SeqCst),
                    0,
                    "previous page must be dropped before another fetch"
                );
                if page.len() > 4 {
                    return Err(FetchError::ResponseTooLarge);
                }
                live.fetch_add(page.len(), Ordering::SeqCst);
                peak.fetch_max(live.load(Ordering::SeqCst), Ordering::SeqCst);
                Ok(page
                    .iter()
                    .map(|slot| Payload {
                        slot: *slot,
                        live: &live,
                    })
                    .collect())
            },
            |item| {
                replayed.push(item.slot);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(replayed, slots);
        assert_eq!(stats.requests, 14);
        assert_eq!(stats.splits, 6);
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fallback_stops_after_partial_in_memory_replay_on_unexpected_error() {
        let slots: Vec<_> = (1..=LEGACY_PAGE as u64 * 2).collect();
        let mut calls = Vec::new();
        let mut replayed = Vec::new();
        let result = replay_legacy_pages(
            &slots,
            |page| {
                calls.push(page.to_vec());
                if page[0] > LEGACY_PAGE as u64 {
                    return Err(FetchError::Invalid("connection dropped".into()));
                }
                Ok(page.to_vec())
            },
            |slot| {
                replayed.push(slot);
                Ok(())
            },
        );
        assert_eq!(
            result.unwrap_err(),
            FetchError::Invalid("connection dropped".into())
        );
        assert_eq!(calls.len(), 2);
        assert_eq!(replayed, slots[..LEGACY_PAGE]);
    }

    #[test]
    fn a_single_oversized_block_or_incomplete_small_page_fails_closed() {
        let mut calls = 0;
        let result: Result<FallbackStats, _> = replay_legacy_pages(
            &[7],
            |_| {
                calls += 1;
                Err::<Vec<u64>, _>(FetchError::ResponseTooLarge)
            },
            |_| Ok(()),
        );
        assert_eq!(result.unwrap_err(), FetchError::ResponseTooLarge);
        assert_eq!(calls, 1);
        let result = replay_legacy_pages(
            &[7, 8],
            |_| Ok(vec![7]),
            |_: u64| panic!("incomplete page must never reach replay"),
        );
        assert!(result.unwrap_err().to_string().contains("omitted or added"));
    }
}
