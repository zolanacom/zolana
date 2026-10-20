//! Bounded read-only WAN aggregation. Never batches transaction broadcasts.
use super::*;
use serde_json::{json, Value};
use solana_account_decoder_client_types::UiAccount;
use solana_rpc_client_api::{request::RpcRequest, response::Response};

const METHODS: &[&str] = &[
    "getAccountInfo",
    "getBalance",
    "getLatestBlockhash",
    "getSlot",
    "getMinimumBalanceForRentExemption",
    "getFeeForMessage",
];

pub(super) struct QuoteInputs {
    pub rent: u64,
    pub markers: u64,
    pub remaining: u64,
    pub balance: u64,
    pub hash: String,
}

impl Chain {
    fn read_batch(&self, calls: Vec<(&'static str, Value)>) -> Result<Vec<Value>> {
        if calls.is_empty()
            || calls.len() > 16
            || calls.iter().any(|(name, _)| !METHODS.contains(name))
        {
            return Err("only bounded wallet reads may be aggregated".into());
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
