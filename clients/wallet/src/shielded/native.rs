//! Real-wallet opt-in. This journal contains the original authorized proof;
//! only the shared relay's private job contains its outer signing key/packet.
use super::*;

const FORMAT: &str = "native-inline-client-pending-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    format: String,
    transport: String,
    pool_format: String,
    packet: Packet,
    payer: String,
    fee: u64,
    maximum_fee: u64,
    expires_at: u64,
}

pub fn quote(chain: &Chain, network: &Network) -> Result<Value> {
    chain.require_native_inline()?;
    let mut quote = chain.relay_rpc("getShieldedFeeQuote", json!([]))?;
    validate_quote(&quote, network)?;
    quote["fee_mode"] = json!("shielded");
    quote["shielded_fee"] = quote["fee"].clone();
    quote["maximum_shielded_fee"] = quote["fee"].clone();
    quote["public_gas_required"] = json!(false);
    Ok(quote)
}

fn validate_quote(quote: &Value, network: &Network) -> Result<()> {
    if quote["format"] != "native-shielded-fee-quote-v1"
        || quote["network"] != serde_json::to_value(network)?
        || quote["transport"] != "native-inline-v1"
        || quote["pool_format"] != "NPOOL004"
        || quote["fee"]
            .as_u64()
            .is_none_or(|fee| fee == 0 || fee > 100_000_000)
    {
        return Err("native fee quote network, transport, pool format or fee mismatch".into());
    }
    let payer: solana_pubkey::Pubkey = quote["payer"]
        .as_str()
        .ok_or("native relay payee missing")?
        .parse()?;
    if !payer.is_on_curve() {
        return Err("native relay payee must be a signing address".into());
    }
    Ok(())
}

fn validate_pending(pending: &Pending, wallet: &WalletKey) -> Result<Vec<u8>> {
    let bytes = pending.packet.bytes()?;
    let payment = wire::decode(wallet.network.network, &bytes)?;
    let payer: solana_pubkey::Pubkey = pending.payer.parse()?;
    if pending.format != FORMAT
        || pending.transport != "native-inline-v1"
        || pending.pool_format != "NPOOL004"
        || pending.packet.network != wallet.network
        || !payer.is_on_curve()
        || payment.context.sponsor != payer.to_bytes()
        || payment.context.shielded_fee != Some(pending.fee)
        || pending.fee == 0
        || pending.fee > pending.maximum_fee
        || pending.maximum_fee > 100_000_000
        || payment.context.expires_at != pending.expires_at
    {
        return Err(
            "native pending proof differs from its original network/payee/fee/expiry authorization"
                .into(),
        );
    }
    Ok(bytes)
}

pub fn send(
    chain: Chain,
    wallet: &WalletKey,
    operation: &WalletOperation,
    amount: u64,
    recipient: &str,
    maximum_fee: u64,
) -> Result<Value> {
    send_with_preparation(
        chain,
        wallet,
        operation,
        amount,
        recipient,
        maximum_fee,
        None,
    )
}

/// The CLI can overlap fixed public key construction with unlock/connection.
/// Completion still precedes history verification and proof construction.
pub fn send_with_preparation(
    chain: Chain,
    wallet: &WalletKey,
    operation: &WalletOperation,
    amount: u64,
    recipient: &str,
    maximum_fee: u64,
    preparation: Option<crate::payments::ProverPreparation>,
) -> Result<Value> {
    operation.ensure_resolved()?;
    if maximum_fee == 0 || maximum_fee > 100_000_000 {
        return Err("native shielded fee requires an explicit bounded maximum".into());
    }
    let began = Instant::now();
    let quote = quote(&chain, &wallet.network)?;
    let fee = quote["fee"]
        .as_u64()
        .filter(|fee| *fee <= maximum_fee)
        .ok_or("native shielded fee exceeds the authorized maximum")?;
    let payer: solana_pubkey::Pubkey = quote["payer"].as_str().unwrap().parse()?;
    let preparation = match preparation {
        Some(preparation) => preparation,
        None => {
            crate::progress::report("key");
            crate::payments::ProverPreparation::start()?
        }
    };
    let (prover, timing) = preparation.finish()?;
    let chain = chain.with_payment_prover(&prover);
    crate::progress::report("sync");
    let sync_at = Instant::now();
    let state = chain.sync_cached(wallet, operation)?;
    if !state.scan.cache_saved {
        return Err("native sender checkpoint is not durable; no proof was submitted".into());
    }
    let sync_ms = sync_at.elapsed().as_millis();
    let pre_send_scan = serde_json::to_value(&state.scan)?;
    let payment = Payment::ShieldedSend {
        amount,
        recipient,
        fee,
    };
    crate::payments::validate(wallet, &state.state, &payment)?;
    let expires_at = chain.expiry()?;
    crate::progress::report("prove");
    let proof_at = Instant::now();
    let bytes = prover.build(wallet, &state.state, payer.to_bytes(), expires_at, payment)?;
    let proof_ms = proof_at.elapsed().as_millis();
    let pending = Pending {
        format: FORMAT.into(),
        transport: "native-inline-v1".into(),
        pool_format: "NPOOL004".into(),
        packet: Packet {
            network: wallet.network.clone(),
            payload: STANDARD.encode(bytes),
        },
        payer: payer.to_string(),
        fee,
        maximum_fee,
        expires_at,
    };
    validate_pending(&pending, wallet)?;
    write_private_new(&operation.shielded, &serde_json::to_vec(&pending)?)?;
    crate::progress::report("native_packet_durable");
    let mut outcome = recover(&chain, wallet, operation, true)?;
    outcome["pre_send_sync"] = pre_send_scan;
    outcome["timings"] = json!({"proof_key_ms":timing.proof_key_ms,"proof_key_wait_ms":timing.proof_key_wait_ms,"proof_key_cached":timing.proof_key_cached,"sync_ms":sync_ms,"proof_build_ms":proof_ms,
        "total_ms":began.elapsed().as_millis()});
    Ok(outcome)
}

pub(super) fn is_pending(value: &Value) -> bool {
    value["format"] == FORMAT
}

pub fn recover(
    chain: &Chain,
    wallet: &WalletKey,
    operation: &WalletOperation,
    wait: bool,
) -> Result<Value> {
    chain.require_native_inline()?;
    let pending: Pending = serde_json::from_slice(&read_private(&operation.shielded, 24_576)?)?;
    let bytes = validate_pending(&pending, wallet)?;
    let id = pending.packet.id()?;
    // Every retry sends the same proof. The owner-bound relay job durably keeps
    // its original signature/blockhash, even if this first response is lost.
    let submitted = chain.relay_rpc("submitShieldedPayment", json!([pending.packet]));
    if let Ok(value) = submitted {
        if value["id"] != id {
            return Err("native relay ACK substituted the original proof; intent retained".into());
        }
    }
    let began = Instant::now();
    loop {
        let status = chain.relay_rpc("getShieldedPaymentStatus", json!([id]))?;
        if status["id"] != id {
            return Err(
                "native relay status substituted the proof identity; intent retained".into(),
            );
        }
        let complete = status["state"] == "accepted"
            || status["state"] == "aborted"
            || !wait
            || began.elapsed() > Duration::from_secs(150);
        if complete {
            crate::progress::report("sync");
            if let Some(mut outcome) = chain.native_client_outcome(
                wallet,
                operation,
                &bytes,
                status["signature"].as_str(),
                true,
            )? {
                outcome["id"] = json!(id);
                outcome["fee_mode"] = json!("shielded");
                outcome["transport"] = json!("native-inline-v1");
                outcome["shielded_fee"] = json!(pending.fee);
                crate::rpc::native::persist_outcome(operation, &operation.shielded, &outcome)?;
                return Ok(outcome);
            }
            return Err("native outcome remains unresolved; original proof retained, no replacement authorized".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_quote_cannot_silently_downgrade_network_pool_transport_or_fee() {
        let network = Network {
            network: [7; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let payer = solana_keypair::Keypair::new();
        use solana_signer::Signer;
        let good = json!({"format":"native-shielded-fee-quote-v1","network":network,
            "transport":"native-inline-v1","pool_format":"NPOOL004","payer":payer.pubkey().to_string(),"fee":3_000_000});
        validate_quote(&good, &network).unwrap();
        for (field, value) in [
            ("transport", json!("staged")),
            ("pool_format", json!("NPOOL003")),
            ("fee", json!(0)),
            ("fee", json!(100_000_001)),
            ("network", json!({})),
            ("payer", json!("invalid")),
        ] {
            let mut changed = good.clone();
            changed[field] = value;
            assert!(validate_quote(&changed, &network).is_err(), "{field}");
        }
    }
}
