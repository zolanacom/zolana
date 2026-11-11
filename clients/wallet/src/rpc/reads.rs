//! Bounded read-only WAN aggregation. Never batches transaction broadcasts.
use super::Chain;
use crate::Result;
use base64::Engine;
use native_payment_program::pool_address;
use native_payment_program::staging::ACCOUNT_BYTES;
use serde_json::{json, Value};
use solana_account::Account;
use solana_account_decoder_client_types::UiAccount;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_rpc_client::http_sender::HttpSender;
use solana_rpc_client::rpc_client::{RpcClient, RpcClientConfig};
use solana_rpc_client_api::config::RpcBlockConfig;
use solana_rpc_client_api::{request::RpcRequest, response::Response};
use solana_transaction::Transaction;
use solana_transaction_status_client_types::TransactionDetails;
use std::thread;
use std::time::{Duration, Instant};

const METHODS: &[&str] = &[
    "getAccountInfo",
    "getBalance",
    "getLatestBlockhash",
    "getSlot",
    "getMinimumBalanceForRentExemption",
    "getFeeForMessage",
];

// Explicit native-fast fixtures and native faucet history preparation may use
// ordinary JSON-RPC arrays. Invited clients keep their custom batch methods.
const MAX_STANDARD_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct ScanControls {
    pub pool: Response<Option<Account>>,
    pub cached_blockhash: Option<String>,
    pub pool_rpc_ms: u128,
    pub checkpoint_rpc_ms: u128,
    pub elapsed_ms: u128,
}

struct Timed<T> {
    value: T,
    elapsed_ms: u128,
}

fn timed<T>(read: impl FnOnce() -> T) -> Timed<T> {
    let began = Instant::now();
    Timed {
        value: read(),
        elapsed_ms: began.elapsed().as_millis(),
    }
}

/// Join both independent reads before exposing either result. In particular,
/// errors and panics must never leave a control worker running during history.
fn joined_control_pair<P: Send, H: Send>(
    pool: impl FnOnce() -> P + Send,
    header: impl FnOnce() -> H + Send,
) -> Result<(Timed<P>, Timed<H>, u128)> {
    let began = Instant::now();
    let (pool, header) = thread::scope(|scope| {
        let pool = scope.spawn(move || timed(pool));
        let header = scope.spawn(move || timed(header));
        let pool = pool.join();
        let header = header.join();
        (pool, header)
    });
    let elapsed_ms = began.elapsed().as_millis();
    let pool = pool.map_err(|_| "finalized pool control worker panicked")?;
    let header = header.map_err(|_| "cached finalized header control worker panicked")?;
    Ok((pool, header, elapsed_ms))
}

/// Existing independently authenticated RPC calls, not a new batch or snapshot.
/// The pool response alone chooses the scan target. A missing cached header
/// retains the existing full-rescan behavior; a worker panic fails closed.
/// Only RpcClient is shared, never Chain or its sponsor authorization.
pub(super) fn scan_controls(rpc: &RpcClient, cached_slot: Option<u64>) -> Result<ScanControls> {
    let pool_read =
        || rpc.get_account_with_commitment(&pool_address(), CommitmentConfig::finalized());
    let Some(cached_slot) = cached_slot.filter(|slot| *slot > 0) else {
        let pool = timed(pool_read);
        return Ok(ScanControls {
            pool: pool.value?,
            cached_blockhash: None,
            pool_rpc_ms: pool.elapsed_ms,
            checkpoint_rpc_ms: 0,
            elapsed_ms: pool.elapsed_ms,
        });
    };
    let (pool, header, elapsed_ms) = joined_control_pair(pool_read, || {
        rpc.get_block_with_config(
            cached_slot,
            RpcBlockConfig {
                transaction_details: Some(TransactionDetails::None),
                rewards: Some(false),
                commitment: Some(CommitmentConfig::finalized()),
                ..Default::default()
            },
        )
    })?;
    Ok(ScanControls {
        pool: pool.value?,
        cached_blockhash: header.value.ok().map(|block| block.blockhash),
        pool_rpc_ms: pool.elapsed_ms,
        checkpoint_rpc_ms: header.elapsed_ms,
        elapsed_ms,
    })
}

pub(super) struct StandardReads {
    client: reqwest::Client,
    url: String,
    enabled: bool,
    operator_zero_based_ids: bool,
}

impl StandardReads {
    pub(super) fn new(url: &str, client: reqwest::Client) -> Self {
        Self {
            client,
            url: url.into(),
            enabled: false,
            operator_zero_based_ids: false,
        }
    }
}

fn standard_request(calls: &[(&str, Value)]) -> Result<Value> {
    standard_request_from(calls, 1)
}

fn standard_request_from(calls: &[(&str, Value)], first_id: u64) -> Result<Value> {
    if first_id > 1
        || calls.is_empty()
        || calls.len() > 16
        || calls
            .iter()
            .any(|(method, _)| *method != "getBlock" && !METHODS.contains(method))
    {
        return Err("only 1..16 standard read-only RPC calls may be batched".into());
    }
    Ok(Value::Array(calls.iter().enumerate().map(|(index, (method, params))| {
        json!({"jsonrpc":"2.0", "id":index as u64 + first_id, "method":method, "params":params})
    }).collect()))
}

fn decode_standard_batch(count: usize, response: Value) -> Result<Vec<Value>> {
    decode_standard_batch_from(count, response, 1)
}

fn decode_standard_batch_from(count: usize, response: Value, first_id: u64) -> Result<Vec<Value>> {
    let items = response
        .as_array()
        .ok_or("standard RPC batch response must be an array")?;
    if first_id > 1 || !(1..=16).contains(&count) || items.len() != count {
        return Err("standard RPC batch omitted or added a response".into());
    }
    let mut ordered = vec![None; count];
    for item in items {
        let object = item.as_object().ok_or("invalid standard RPC batch item")?;
        let id = item
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| id.checked_sub(first_id))
            .filter(|id| *id < count as u64)
            .ok_or("standard RPC batch returned an unknown response ID")? as usize;
        if object.len() != 3
            || item.get("jsonrpc") != Some(&json!("2.0"))
            || !object.contains_key("result")
            || ordered[id].is_some()
        {
            return Err(
                "standard RPC batch returned an error, duplicate ID or invalid response".into(),
            );
        }
        ordered[id] = Some(item["result"].clone());
    }
    ordered
        .into_iter()
        .map(|value| value.ok_or_else(|| "standard RPC batch omitted a response ID".into()))
        .collect()
}

pub(super) struct QuoteInputs {
    pub rent: u64,
    pub markers: u64,
    pub remaining: u64,
    pub balance: u64,
    pub hash: String,
}

pub struct BalanceInputs {
    pub public_balance: u64,
    pub fee_balance: u64,
    pub minimum_withdrawal: u64,
}

impl Chain {
    /// Preserve the ordinary balance/account/rent reads and their commitments,
    /// while using one bounded, independently authorized gateway read batch.
    pub fn balance_inputs(&self, public: Pubkey, fee: Pubkey) -> Result<BalanceInputs> {
        if !public.is_on_curve() {
            return Err("withdrawal recipient must be a public signing address".into());
        }
        let mut results = self
            .read_batch(vec![
                (
                    "getBalance",
                    json!([public.to_string(), {"commitment":"finalized"}]),
                ),
                (
                    "getAccountInfo",
                    json!([public.to_string(), {"encoding":"base64","commitment":"confirmed"}]),
                ),
                ("getMinimumBalanceForRentExemption", json!([0])),
                (
                    "getBalance",
                    json!([fee.to_string(), {"commitment":"finalized"}]),
                ),
            ])?
            .into_iter();
        let public_balance: Response<u64> = serde_json::from_value(results.next().unwrap())?;
        let account: Response<Option<UiAccount>> = serde_json::from_value(results.next().unwrap())?;
        let confirmed_balance = if let Some(account) = account.value {
            let account: Account = account.decode().ok_or("invalid public account encoding")?;
            if account.owner != solana_sdk_ids::system_program::id()
                || !account.data.is_empty()
                || account.executable
            {
                return Err("withdrawal recipient must be an ordinary public account".into());
            }
            account.lamports
        } else {
            0
        };
        let rent: u64 = serde_json::from_value(results.next().unwrap())?;
        let fee_balance: Response<u64> = serde_json::from_value(results.next().unwrap())?;
        Ok(BalanceInputs {
            public_balance: public_balance.value,
            fee_balance: fee_balance.value,
            minimum_withdrawal: rent.saturating_sub(confirmed_balance).max(1),
        })
    }

    /// Only the native faucet's explicit retained-history source path opts in.
    /// Enable the already authenticated client; rebuilding it would lose a
    /// structured operator credential's Unix socket route or its HTTP headers.
    pub(crate) fn with_operator_read_batches(mut self) -> Result<Self> {
        if self.pool_format != "NPOOL004" || self.history_batches || self.retained_history_v2 {
            return Err("operator read batches require a non-invited native source".into());
        }
        let transport = self
            .standard_reads
            .as_ref()
            .ok_or("standard RPC transport unavailable")?;
        crate::connection::Endpoint {
            transport: "loopback-http".into(),
            url: transport.url.clone(),
        }
        .validate()?;
        // The existing sealed grant proxy requires exact positional IDs0..n-1.
        // Fixture clients retain their original IDs1..n contract.
        self.standard_reads
            .as_mut()
            .unwrap()
            .operator_zero_based_ids = true;
        self.with_standard_read_batches()
    }

    pub(super) fn with_standard_read_batches(mut self) -> Result<Self> {
        if self.history_batches {
            return Err("standard fixture batches cannot replace invited gateway batches".into());
        }
        self.standard_reads
            .as_mut()
            .ok_or("standard RPC transport unavailable")?
            .enabled = true;
        Ok(self)
    }

    /// Own a read-only RPC runtime for the already pinned endpoint/network/key.
    /// A worker-local HTTP pool avoids tasks tied to a parked parent runtime.
    /// Never copies fee authority or repeats network/genesis selection.
    pub(super) fn read_only_scan_fork(&self) -> Result<Self> {
        let transport = self
            .standard_reads
            .as_ref()
            .filter(|transport| transport.enabled)
            .ok_or("read-only scan forks require the explicit native fixture transport")?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            rpc: RpcClient::new_sender(
                HttpSender::new_with_client(&transport.url, client.clone()),
                RpcClientConfig::with_commitment(CommitmentConfig::finalized()),
            ),
            network: self.network.clone(),
            sponsor_budget: None,
            user_fees: None,
            history_batches: self.history_batches,
            retained_history_v2: self.retained_history_v2,
            standard_reads: Some(StandardReads {
                client,
                url: transport.url.clone(),
                enabled: transport.enabled,
                operator_zero_based_ids: transport.operator_zero_based_ids,
            }),
            verification_key: self.verification_key.clone(),
            pool_format: self.pool_format,
        })
    }

    pub(super) fn standard_reads_enabled(&self) -> bool {
        self.standard_reads
            .as_ref()
            .is_some_and(|transport| transport.enabled)
    }

    pub(super) fn standard_read_batch(
        &self,
        calls: Vec<(&'static str, Value)>,
    ) -> Result<Vec<Value>> {
        let transport = self
            .standard_reads
            .as_ref()
            .filter(|transport| transport.enabled)
            .ok_or("standard fixture batching is not enabled")?;
        let request = if transport.operator_zero_based_ids {
            standard_request_from(&calls, 0)?
        } else {
            standard_request(&calls)?
        };
        let bytes = self.rpc.runtime().block_on(async {
            let mut response = transport
                .client
                .post(&transport.url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&request)?)
                .send()
                .await?;
            // error_for_status does not reject redirects, which are disabled.
            if !response.status().is_success() {
                return Err(format!("standard RPC batch HTTP status {}", response.status()).into());
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_STANDARD_RESPONSE_BYTES as u64)
            {
                return Err("standard RPC batch response exceeds the size bound".into());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if chunk.len() > MAX_STANDARD_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                    return Err("standard RPC batch response exceeds the size bound".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, Box<dyn std::error::Error>>(bytes)
        })?;
        let response = serde_json::from_slice(&bytes)?;
        if transport.operator_zero_based_ids {
            decode_standard_batch_from(calls.len(), response, 0)
        } else {
            decode_standard_batch(calls.len(), response)
        }
    }

    fn read_batch(&self, calls: Vec<(&'static str, Value)>) -> Result<Vec<Value>> {
        if calls.is_empty()
            || calls.len() > 16
            || calls.iter().any(|(name, _)| !METHODS.contains(name))
        {
            return Err("only bounded wallet reads may be aggregated".into());
        }
        if self.standard_reads_enabled() {
            return self.standard_read_batch(calls);
        }
        if !self.history_batches {
            return calls
                .into_iter()
                .map(|(method, params)| {
                    let request = match method {
                        "getAccountInfo" => RpcRequest::GetAccountInfo,
                        "getBalance" => RpcRequest::GetBalance,
                        "getLatestBlockhash" => RpcRequest::GetLatestBlockhash,
                        "getSlot" => RpcRequest::GetSlot,
                        "getMinimumBalanceForRentExemption" => {
                            RpcRequest::GetMinimumBalanceForRentExemption
                        }
                        "getFeeForMessage" => RpcRequest::GetFeeForMessage,
                        _ => unreachable!(),
                    };
                    self.rpc.send(request, params).map_err(Into::into)
                })
                .collect();
        }
        let expected: Vec<Value> = calls
            .iter()
            .map(|(method, params)| json!({"method":method,"params":params}))
            .collect();
        let result: Vec<Value> = self.rpc.send(
            RpcRequest::Custom {
                method: "getWalletReadBatch",
            },
            json!([expected]),
        )?;
        decode_batch(&expected, result)
    }

    pub(super) fn quote_inputs(&self, payer: Pubkey) -> Result<QuoteInputs> {
        if !payer.is_on_curve() {
            return Err("fee payer must be a public signing address".into());
        }
        let mut results = self
            .read_batch(vec![
                (
                    "getAccountInfo",
                    json!([payer.to_string(), {"encoding":"base64","commitment":"confirmed"}]),
                ),
                ("getMinimumBalanceForRentExemption", json!([ACCOUNT_BYTES])),
                (
                    "getMinimumBalanceForRentExemption",
                    json!([native_payment_program::nullifiers::MARKER_BYTES]),
                ),
                ("getMinimumBalanceForRentExemption", json!([0])),
                ("getLatestBlockhash", json!([{"commitment":"confirmed"}])),
                (
                    "getBalance",
                    json!([payer.to_string(), {"commitment":"finalized"}]),
                ),
            ])?
            .into_iter();
        let account: Response<Option<UiAccount>> = serde_json::from_value(results.next().unwrap())?;
        if let Some(account) = account.value {
            let account: Account = account.decode().ok_or("invalid fee account encoding")?;
            if account.owner != solana_sdk_ids::system_program::id()
                || !account.data.is_empty()
                || account.executable
            {
                return Err("fee payer must be an ordinary public account".into());
            }
        }
        let rent = serde_json::from_value::<u64>(results.next().unwrap())?;
        let markers = serde_json::from_value::<u64>(results.next().unwrap())?
            .max(1)
            .checked_mul(2)
            .ok_or("rent overflow")?;
        let remaining = serde_json::from_value::<u64>(results.next().unwrap())?;
        let hash: Response<solana_rpc_client_api::response::RpcBlockhash> =
            serde_json::from_value(results.next().unwrap())?;
        let hash = hash.value.blockhash;
        let balance: Response<u64> = serde_json::from_value(results.next().unwrap())?;
        Ok(QuoteInputs {
            rent,
            markers,
            remaining,
            hash,
            balance: balance.value,
        })
    }

    pub(super) fn transaction_fees(&self, transactions: &[Transaction]) -> Result<Vec<u64>> {
        if transactions.is_empty() || transactions.len() > 16 {
            return Err("invalid bounded fee request".into());
        }
        let calls = transactions
            .iter()
            .map(|tx| {
                (
                    "getFeeForMessage",
                    json!([
                        base64::engine::general_purpose::STANDARD.encode(tx.message.serialize()),
                        {"commitment":"confirmed"}
                    ]),
                )
            })
            .collect();
        self.read_batch(calls)?
            .into_iter()
            .map(|result| {
                let response: Response<Option<u64>> = serde_json::from_value(result)?;
                response
                    .value
                    .ok_or_else(|| "fee unavailable for this exact message/blockhash".into())
            })
            .collect()
    }
}

fn decode_batch(expected: &[Value], result: Vec<Value>) -> Result<Vec<Value>> {
    if result.len() != expected.len() {
        return Err("wallet read result omitted a requested value".into());
    }
    result
        .into_iter()
        .zip(expected)
        .map(|(mut item, request)| {
            if item
                .as_object()
                .is_none_or(|v| v.len() != 2 || !v.contains_key("result"))
                || item.get("request") != Some(request)
            {
                return Err("wallet read result reordered or substituted a request".into());
            }
            Ok(item.get_mut("result").unwrap().take())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Network;
    use solana_keypair::Keypair;
    use solana_rpc_client::mock_sender::MocksMap;
    use solana_signer::Signer;
    use std::fs;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    fn balance_response(public: Pubkey, fee: Pubkey, account: Value) -> Value {
        let context = json!({"slot":37});
        json!([
            {"request":{"method":"getBalance","params":[public.to_string(),{"commitment":"finalized"}]},
             "result":{"context":context,"value":20}},
            {"request":{"method":"getAccountInfo","params":[public.to_string(),{"encoding":"base64","commitment":"confirmed"}]},
             "result":{"context":context,"value":account}},
            {"request":{"method":"getMinimumBalanceForRentExemption","params":[0]},"result":100},
            {"request":{"method":"getBalance","params":[fee.to_string(),{"commitment":"finalized"}]},
             "result":{"context":context,"value":5}}
        ])
    }

    fn public_account(balance: u64) -> Value {
        json!({"lamports":balance,"owner":solana_sdk_ids::system_program::id().to_string(),
            "data":["","base64"],"executable":false,"rentEpoch":0,"space":0})
    }

    fn balance_chain(responses: Vec<Value>) -> Chain {
        Chain {
            rpc: RpcClient::new_mock_with_mocks_map(
                "fails",
                responses
                    .into_iter()
                    .map(|response| {
                        (
                            RpcRequest::Custom {
                                method: "getWalletReadBatch",
                            },
                            response,
                        )
                    })
                    .collect(),
            ),
            network: Network {
                network: [7; 32],
                genesis_hash: bs58::encode([8; 32]).into_string(),
            },
            sponsor_budget: None,
            user_fees: None,
            history_batches: true,
            retained_history_v2: false,
            standard_reads: None,
            verification_key: None,
            pool_format: "NPOOL004",
        }
    }

    #[test]
    fn balance_inputs_keep_exact_commitments_and_fetch_fresh_values() {
        let public = Keypair::new().pubkey();
        let fee = Keypair::new().pubkey();
        let first = balance_response(public, fee, public_account(40));
        let mut next = first.clone();
        next[0]["result"]["value"] = json!(21);
        next[1]["result"]["value"]["lamports"] = json!(45);
        next[3]["result"]["value"] = json!(6);
        let chain = balance_chain(vec![first, next]);
        let first = chain.balance_inputs(public, fee).unwrap();
        assert_eq!(
            (
                first.public_balance,
                first.fee_balance,
                first.minimum_withdrawal
            ),
            (20, 5, 60)
        );
        let next = chain.balance_inputs(public, fee).unwrap();
        assert_eq!(
            (
                next.public_balance,
                next.fee_balance,
                next.minimum_withdrawal
            ),
            (21, 6, 55)
        );
        // There is no cached-value or sequential-RPC fallback after a failed batch.
        assert!(chain.balance_inputs(public, fee).is_err());
    }

    #[test]
    fn balance_inputs_preserve_missing_account_and_minimum_one_semantics() {
        let public = Keypair::new().pubkey();
        let fee = Keypair::new().pubkey();
        for (account, minimum) in [
            (Value::Null, 100),
            (public_account(100), 1),
            (public_account(200), 1),
        ] {
            let value = balance_chain(vec![balance_response(public, fee, account)])
                .balance_inputs(public, fee)
                .unwrap();
            assert_eq!(value.minimum_withdrawal, minimum);
        }
        let mut zero_rent = balance_response(public, fee, Value::Null);
        zero_rent[2]["result"] = json!(0);
        assert_eq!(
            balance_chain(vec![zero_rent])
                .balance_inputs(public, fee)
                .unwrap()
                .minimum_withdrawal,
            1
        );
    }

    #[test]
    fn balance_inputs_reject_nonordinary_or_invalid_public_accounts() {
        let public = Keypair::new().pubkey();
        let fee = Keypair::new().pubkey();
        for (key, invalid) in [
            ("owner", json!(Pubkey::new_unique().to_string())),
            ("data", json!(["AQ==", "base64"])),
            ("data", json!(["?", "base64"])),
            ("executable", json!(true)),
        ] {
            let mut account = public_account(40);
            account[key] = invalid;
            assert!(balance_chain(vec![balance_response(public, fee, account)])
                .balance_inputs(public, fee)
                .is_err());
        }
        let off_curve =
            Pubkey::find_program_address(&[b"balance-test"], &native_payment_program::id()).0;
        assert!(balance_chain(vec![])
            .balance_inputs(off_curve, fee)
            .is_err());
    }

    #[test]
    fn balance_inputs_reject_partial_substituted_or_malformed_batch_results() {
        let public = Keypair::new().pubkey();
        let fee = Keypair::new().pubkey();
        let good = balance_response(public, fee, Value::Null);
        let mut partial = good.clone();
        partial.as_array_mut().unwrap().pop();
        let mut reordered = good.clone();
        reordered.as_array_mut().unwrap().swap(0, 3);
        let mut commitment = good.clone();
        commitment[0]["request"]["params"][1]["commitment"] = json!("confirmed");
        let mut rpc_error = good.clone();
        rpc_error[0]["error"] = json!({"code":-32000});
        let mut missing = good.clone();
        missing[0].as_object_mut().unwrap().remove("result");
        let mut invalid_balance = good.clone();
        invalid_balance[0]["result"]["value"] = json!("20");
        let mut invalid_rent = good.clone();
        invalid_rent[2]["result"] = json!(-1);
        let mut invalid_fee = good.clone();
        invalid_fee[3]["result"]["value"] = Value::Null;
        for invalid in [
            partial,
            reordered,
            commitment,
            rpc_error,
            missing,
            invalid_balance,
            invalid_rent,
            invalid_fee,
            Value::Null,
        ] {
            assert!(balance_chain(vec![invalid])
                .balance_inputs(public, fee)
                .is_err());
        }
    }

    #[test]
    fn control_reads_start_together_before_either_can_finish() {
        // A bounded rendezvous fails instead of hanging if either read stops
        // being concurrent. No elapsed-time threshold is used as evidence.
        let (pool_started, pool_wait) = mpsc::channel();
        let (header_started, header_wait) = mpsc::channel();
        let (pool, header, _) = joined_control_pair(
            move || {
                pool_started.send(()).unwrap();
                header_wait.recv_timeout(Duration::from_secs(2)).unwrap();
                "pool"
            },
            move || {
                header_started.send(()).unwrap();
                pool_wait.recv_timeout(Duration::from_secs(2)).unwrap();
                "header"
            },
        )
        .unwrap();
        assert_eq!((pool.value, header.value), ("pool", "header"));
    }

    #[test]
    fn control_results_keep_their_role_in_either_completion_order() {
        for pool_first in [true, false] {
            let (release_pool, pool_wait) = mpsc::channel();
            let (release_header, header_wait) = mpsc::channel();
            let (pool, header, _) = joined_control_pair(
                move || {
                    if pool_first {
                        release_header.send(()).unwrap();
                    } else {
                        pool_wait.recv_timeout(Duration::from_secs(2)).unwrap();
                    }
                    17
                },
                move || {
                    if pool_first {
                        header_wait.recv_timeout(Duration::from_secs(2)).unwrap();
                    } else {
                        release_pool.send(()).unwrap();
                    }
                    31
                },
            )
            .unwrap();
            assert_eq!((pool.value, header.value), (17, 31));
        }
    }

    #[test]
    fn control_errors_are_returned_only_after_both_reads_finish() {
        for pool_fails in [true, false] {
            let other_finished = AtomicBool::new(false);
            let (pool, header, _) = joined_control_pair(
                || {
                    if pool_fails {
                        Err("pool unavailable")
                    } else {
                        thread::sleep(Duration::from_millis(5));
                        other_finished.store(true, Ordering::SeqCst);
                        Ok(17)
                    }
                },
                || {
                    if pool_fails {
                        thread::sleep(Duration::from_millis(5));
                        other_finished.store(true, Ordering::SeqCst);
                        Ok(31)
                    } else {
                        Err("header unavailable")
                    }
                },
            )
            .unwrap();
            assert!(other_finished.load(Ordering::SeqCst));
            if pool_fails {
                assert_eq!(pool.value, Err("pool unavailable"));
                assert_eq!(header.value, Ok(31));
            } else {
                assert_eq!(pool.value, Ok(17));
                assert_eq!(header.value, Err("header unavailable"));
            }
        }
    }

    #[test]
    fn either_control_panic_fails_closed_after_joining_the_other_read() {
        for pool_panics in [true, false] {
            let other_finished = AtomicBool::new(false);
            let result = joined_control_pair(
                || {
                    assert!(!pool_panics, "intentional pool worker panic");
                    thread::sleep(Duration::from_millis(5));
                    other_finished.store(true, Ordering::SeqCst);
                    17
                },
                || {
                    assert!(pool_panics, "intentional header worker panic");
                    thread::sleep(Duration::from_millis(5));
                    other_finished.store(true, Ordering::SeqCst);
                    31
                },
            );
            assert!(other_finished.load(Ordering::SeqCst));
            let error = result.err().unwrap().to_string();
            assert!(error.contains(if pool_panics {
                "pool control worker panicked"
            } else {
                "header control worker panicked"
            }));
        }
    }

    fn control_fixture(header: Value) -> RpcClient {
        RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter([
                (
                    RpcRequest::GetAccountInfo,
                    json!({"context":{"slot":37},"value":null}),
                ),
                (RpcRequest::GetBlock, header),
            ]),
        )
    }

    fn control_header() -> Value {
        json!({"blockhash":bs58::encode([23;32]).into_string(),
            "previousBlockhash":bs58::encode([22;32]).into_string(),
            "parentSlot":22,"blockHeight":999,"blockTime":null,"transactions":[],"rewards":[]})
    }

    #[test]
    fn joined_scan_controls_keep_the_pool_context_as_the_only_target() {
        let controls = scan_controls(&control_fixture(control_header()), Some(23)).unwrap();
        assert_eq!(controls.pool.context.slot, 37);
        assert_eq!(
            controls.cached_blockhash,
            Some(bs58::encode([23; 32]).into_string())
        );
    }

    #[test]
    fn unavailable_cached_header_keeps_the_full_rescan_signal() {
        let controls = scan_controls(&control_fixture(Value::Null), Some(23)).unwrap();
        assert_eq!(controls.pool.context.slot, 37);
        assert!(controls.cached_blockhash.is_none());
    }

    #[test]
    fn failed_pool_read_cannot_be_replaced_by_a_valid_cached_header() {
        let rpc = RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter([
                (RpcRequest::GetAccountInfo, Value::Null),
                (RpcRequest::GetBlock, control_header()),
            ]),
        );
        assert!(scan_controls(&rpc, Some(23)).is_err());
    }

    #[test]
    fn fresh_or_genesis_cache_never_reads_a_cached_header() {
        for cached_slot in [None, Some(0)] {
            let header = control_header();
            let rpc = control_fixture(header.clone());
            let controls = scan_controls(&rpc, cached_slot).unwrap();
            assert_eq!(controls.pool.context.slot, 37);
            assert!(controls.cached_blockhash.is_none());
            assert_eq!(controls.checkpoint_rpc_ms, 0);
            // The one saved response remains unconsumed by the control phase.
            let unread = rpc
                .get_block_with_config(23, RpcBlockConfig::default())
                .unwrap();
            assert_eq!(unread.blockhash, header["blockhash"].as_str().unwrap());
        }
    }

    fn operator_fixture(url: &str) -> Chain {
        let mut chain = balance_chain(vec![]);
        chain.history_batches = false;
        chain.standard_reads = Some(StandardReads::new(url, reqwest::Client::new()));
        chain
    }

    #[test]
    fn operator_batches_require_native_noninvited_loopback_source() {
        let chain = operator_fixture("http://127.0.0.1:35339");
        assert!(!chain.standard_reads_enabled());
        assert!(chain
            .with_operator_read_batches()
            .unwrap()
            .standard_reads_enabled());
        let mut legacy = operator_fixture("http://127.0.0.1:35339");
        legacy.pool_format = "NPOOL003";
        assert!(legacy.with_operator_read_batches().is_err());
        let mut invited = operator_fixture("http://127.0.0.1:35339");
        invited.history_batches = true;
        assert!(invited.with_operator_read_batches().is_err());
        let mut retained = operator_fixture("http://127.0.0.1:35339");
        retained.retained_history_v2 = true;
        assert!(retained.with_operator_read_batches().is_err());
        let mut missing = operator_fixture("http://127.0.0.1:35339");
        missing.standard_reads = None;
        assert!(missing.with_operator_read_batches().is_err());
        for url in [
            "https://example.invalid",
            "http://localhost:35339",
            "http://127.0.0.1:35339/path",
        ] {
            assert!(operator_fixture(url).with_operator_read_batches().is_err());
        }
    }

    fn operator_history_params(slot: u64) -> Value {
        json!([slot, {"encoding":"base64", "transactionDetails":"full", "rewards":false,
            "commitment":"finalized", "maxSupportedTransactionVersion":0}])
    }

    // Exercise the production authenticated client, rather than a replacement
    // scan client. Every accept/read is bounded and only synthetic credentials
    // are used; neither transport contacts a running validator or gateway.
    fn serve_operator_reads<T: std::io::Read + std::io::Write>(
        mut accept: impl FnMut() -> std::io::Result<T>,
        token: Option<&str>,
    ) {
        for index in 0..2 {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match accept() {
                    Ok(stream) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "operator test client did not connect"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("operator test accept failed: {error}"),
                }
            };
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
                assert!(bytes.len() <= 16 * 1024);
                if bytes.ends_with(b"\r\n\r\n") {
                    break bytes.len();
                }
            };
            let header = String::from_utf8(bytes.clone())
                .unwrap()
                .to_ascii_lowercase();
            assert!(!header.contains("x-testnet-access:"));
            match token {
                Some(token) => {
                    assert!(header.contains(&format!("{}: {token}\r\n", native_rpc_access::HEADER)))
                }
                None => assert!(!header.contains(native_rpc_access::HEADER)),
            }
            let length: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(length <= 16 * 1024);
            bytes.resize(header_end + length, 0);
            stream.read_exact(&mut bytes[header_end..]).unwrap();
            let request: Value = serde_json::from_slice(&bytes[header_end..]).unwrap();
            let response = if index == 0 {
                assert_eq!(request["method"], "getGenesisHash");
                json!({"jsonrpc":"2.0", "id":request["id"],
                    "result":bs58::encode([8;32]).into_string()})
            } else {
                assert_eq!(
                    request,
                    json!([
                        {"jsonrpc":"2.0","id":0,"method":"getBlock","params":operator_history_params(7)},
                        {"jsonrpc":"2.0","id":1,"method":"getBlock","params":operator_history_params(9)}
                    ])
                );
                json!([
                    {"jsonrpc":"2.0","id":1,"result":9},
                    {"jsonrpc":"2.0","id":0,"result":{"slot":7}}
                ])
            };
            let body = serde_json::to_vec(&response).unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
    }

    fn assert_operator_reads(chain: Chain) {
        assert!(!chain.standard_reads_enabled());
        let chain = chain
            .with_pool_format("NPOOL004")
            .unwrap()
            .with_operator_read_batches()
            .unwrap();
        assert!(chain
            .standard_read_batch(vec![("sendTransaction", json!([]))])
            .is_err());
        assert!(chain
            .standard_read_batch(vec![("getSlot", json!([])); 17])
            .is_err());
        assert_eq!(
            chain
                .standard_read_batch(vec![
                    ("getBlock", operator_history_params(7)),
                    ("getBlock", operator_history_params(9)),
                ])
                .unwrap(),
            vec![json!({"slot":7}), json!(9)]
        );
    }

    #[test]
    fn operator_batches_preserve_internal_http_proxy_transport() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = thread::spawn(move || {
            serve_operator_reads(
                || {
                    let (stream, _) = listener.accept()?;
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    Ok(stream)
                },
                None,
            )
        });
        assert_operator_reads(
            Chain::connect_authenticated(
                &url,
                Network {
                    network: [7; 32],
                    genesis_hash: bs58::encode([8; 32]).into_string(),
                },
                None,
                None,
                None,
            )
            .unwrap(),
        );
        server.join().unwrap();
    }

    #[test]
    fn operator_batches_preserve_credentialed_unix_transport_without_tcp_fallback() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .prefix("op-batch-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fs::canonicalize(dir.path()).unwrap().join("rpc.sock");
        let (listener, _guard) = native_rpc_access::bind_socket(&socket).unwrap();
        // A live TCP listener makes any unintended transport downgrade observable.
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        tcp.set_nonblocking(true).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let credential = dir.path().join("rpc-access.key");
        let token = "ab".repeat(32);
        crate::keys::write_private_new(
            &credential,
            &serde_json::to_vec(&json!({
                "format":"native-rpc-unix-v1", "token":token,
                "sockets":{(port.to_string()):socket}
            }))
            .unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || {
            serve_operator_reads(
                || {
                    let (stream, _) = listener.accept()?;
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    Ok(stream)
                },
                Some(&token),
            )
        });
        assert_operator_reads(
            Chain::connect_operator(
                &format!("http://127.0.0.1:{port}"),
                Network {
                    network: [7; 32],
                    genesis_hash: bs58::encode([8; 32]).into_string(),
                },
                &credential,
            )
            .unwrap(),
        );
        server.join().unwrap();
        assert!(
            matches!(tcp.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn operator_ids_accept_only_the_exact_zero_based_response_set() {
        let first = json!({"jsonrpc":"2.0","id":0,"result":7});
        let second = json!({"jsonrpc":"2.0","id":1,"result":9});
        assert_eq!(
            decode_standard_batch_from(2, json!([second, first]), 0).unwrap(),
            vec![json!(7), json!(9)]
        );
        for invalid in [
            json!([{ "jsonrpc":"2.0","id":1,"result":7 }, { "jsonrpc":"2.0","id":2,"result":9 }]),
            json!([first, first]),
            json!([first]),
            json!([first, {"jsonrpc":"2.0","id":-1,"result":9}]),
            json!([first, {"jsonrpc":"2.0","id":"1","result":9}]),
            json!([first, {"jsonrpc":"2.0","id":1,"error":{"code":-32000}}]),
        ] {
            assert!(decode_standard_batch_from(2, invalid, 0).is_err());
        }
        // Existing fixture requests and responses still use IDs1..n.
        assert_eq!(
            standard_request(&[("getSlot", json!([]))]).unwrap()[0]["id"],
            1
        );
        assert!(decode_standard_batch(2, json!([first, second])).is_err());
    }

    #[test]
    fn standard_batches_restore_request_order_and_fail_closed_on_malformed_ids() {
        let first = json!({"jsonrpc":"2.0","id":1,"result":{"slot":7}});
        let second = json!({"jsonrpc":"2.0","id":2,"result":{"slot":9}});
        assert_eq!(
            decode_standard_batch(2, json!([second, first])).unwrap(),
            vec![json!({"slot":7}), json!({"slot":9})]
        );
        let mut duplicate = json!([first, second]);
        duplicate[1]["id"] = json!(1);
        let mut unknown = json!([first, second]);
        unknown[1]["id"] = json!(3);
        let mut string_id = json!([first, second]);
        string_id[1]["id"] = json!("2");
        let mut zero = json!([first, second]);
        zero[1]["id"] = json!(0);
        let mut fraction = json!([first, second]);
        fraction[1]["id"] = json!(1.5);
        let mut version = json!([first, second]);
        version[1]["jsonrpc"] = json!("1.0");
        let mut error = json!([first, second]);
        error[1].as_object_mut().unwrap().remove("result");
        error[1]["error"] = json!({"code":-32000,"message":"block unavailable"});
        let mut both = json!([first, second]);
        both[1]["error"] = json!({"code":-32000,"message":"ambiguous"});
        let mut missing = json!([first, second]);
        missing[1].as_object_mut().unwrap().remove("result");
        for invalid in [
            duplicate,
            unknown,
            string_id,
            zero,
            fraction,
            version,
            error,
            both,
            missing,
            json!([]),
            json!([first]),
            json!([first, second, first]),
            json!({"jsonrpc":"2.0","id":1,"result":7}),
            json!([first, null]),
        ] {
            assert!(decode_standard_batch(2, invalid).is_err());
        }
        assert!(decode_standard_batch(0, json!([])).is_err());
        assert!(decode_standard_batch(17, Value::Array(vec![first; 17])).is_err());
    }

    #[test]
    fn standard_batches_are_bounded_and_exclusively_read_only() {
        assert!(standard_request(&[]).is_err());
        assert!(standard_request(&vec![("getSlot", json!([])); 17]).is_err());
        for forbidden in [
            "sendTransaction",
            "requestAirdrop",
            "submitShieldedPayment",
            "getWalletHistoryBlocks",
            "getWalletReadBatch",
        ] {
            assert!(standard_request(&[(forbidden, json!([]))]).is_err());
        }
        let request =
            standard_request(&[("getBlock", json!([7])), ("getSlot", json!([]))]).unwrap();
        assert_eq!(
            request[0],
            json!({"jsonrpc":"2.0","id":1,"method":"getBlock","params":[7]})
        );
        assert_eq!(
            request[1],
            json!({"jsonrpc":"2.0","id":2,"method":"getSlot","params":[]})
        );
    }

    #[test]
    fn exact_read_binding_refuses_partial_reordered_substituted_and_error_results() {
        let expected = vec![
            json!({"method":"getFeeForMessage","params":["AAAA",{"commitment":"confirmed"}]}),
            json!({"method":"getBalance","params":["payer",{"commitment":"finalized"}]}),
        ];
        let good = vec![
            json!({"request":expected[0],"result":{"value":5000}}),
            json!({"request":expected[1],"result":{"value":10}}),
        ];
        assert_eq!(
            decode_batch(&expected, good.clone()).unwrap(),
            vec![json!({"value":5000}), json!({"value":10})]
        );
        let mut reversed = good.clone();
        reversed.reverse();
        let mut substitute = good.clone();
        substitute[0]["request"]["params"][0] = json!("BBBB");
        let mut commitment = good.clone();
        commitment[1]["request"]["params"][1]["commitment"] = json!("processed");
        let mut error = good.clone();
        error[0]["error"] = json!("unavailable");
        let mut missing = good.clone();
        missing[0].as_object_mut().unwrap().remove("result");
        for invalid in [
            vec![],
            vec![good[0].clone()],
            reversed,
            substitute,
            commitment,
            error,
            missing,
        ] {
            assert!(decode_batch(&expected, invalid).is_err());
        }
    }
}
