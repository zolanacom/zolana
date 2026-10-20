//! Shielded fee client and relay packet. No user gas key or plaintext recipient
//! is transmitted to the relay. Admission identity is still visible to ingress.
use crate::{
    keys::{read_private, write_private_new, Network, WalletKey},
    operation::WalletOperation,
    payments::{Payment, PaymentProver},
    rpc::Chain,
    Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use native_payments::{staging::payload_digest, wire};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs, thread,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub network: Network,
    pub payload: String,
}
impl Packet {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if self.payload.len() != 12308 {
            return Err("invalid shielded payload size".into());
        }
        let bytes = STANDARD.decode(&self.payload)?;
        if STANDARD.encode(&bytes) != self.payload {
            return Err("noncanonical payload".into());
        }
        let payment = wire::decode(self.network.network, &bytes)?;
        if payment.context.shielded_fee.is_none() {
            return Err("V3 shielded fee required".into());
        }
        Ok(bytes)
    }
    pub fn id(&self) -> Result<String> {
        Ok(payload_digest(&self.bytes()?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }
}

pub fn send(
    chain: &Chain,
    wallet: &WalletKey,
    operation: &WalletOperation,
    amount: u64,
    recipient: &str,
    maximum_fee: u64,
) -> Result<Value> {
    operation.ensure_resolved()?;
    let quote = chain.relay_rpc("getShieldedFeeQuote", json!([]))?;
    if quote["format"] != "native-shielded-fee-quote-v1"
        || quote["network"] != serde_json::to_value(&wallet.network)?
    {
        return Err("shielded fee quote network/format mismatch".into());
    }
    let fee = quote["fee"]
        .as_u64()
        .filter(|f| *f > 0 && *f <= maximum_fee)
        .ok_or("shielded fee exceeds the explicitly authorized maximum")?;
    let payer: solana_pubkey::Pubkey = quote["payer"]
        .as_str()
        .ok_or("missing relay payee")?
        .parse()?;
    if !payer.is_on_curve() {
        return Err("invalid relay payee".into());
    }
    crate::progress::report("sync");
    let prover = PaymentProver::new();
    let state = chain.sync_cached(wallet, operation)?;
    let payment = Payment::ShieldedSend {
        amount,
        recipient,
        fee,
    };
    crate::payments::validate(wallet, &state.state, &payment)?;
    let bytes = prover.build(
        wallet,
        &state.state,
        payer.to_bytes(),
        chain.expiry()?,
        payment,
    )?;
    let packet = Packet {
        network: wallet.network.clone(),
        payload: STANDARD.encode(bytes),
    };
    // Durable intent precedes even the first possible ingress acknowledgement.
    write_private_new(&operation.shielded, &serde_json::to_vec(&packet)?)?;
    recover(chain, wallet, operation, true)
}

pub fn recover(
    chain: &Chain,
    wallet: &WalletKey,
    operation: &WalletOperation,
    wait: bool,
) -> Result<Value> {
    let packet: Packet = serde_json::from_slice(&read_private(&operation.shielded, 20000)?)?;
    if packet.network != wallet.network {
        return Err("shielded journal network mismatch".into());
    }
    let bytes = packet.bytes()?;
    let id = packet.id()?;
    // Resending the exact proof is idempotent at ingress; never build another
    // proof or silently raise the original signed fee during recovery.
    let submitted = chain.relay_rpc("submitShieldedPayment", json!([packet]));
    if let Ok(value) = &submitted {
        if value["id"] != id {
            return Err("relay acknowledgement identity mismatch; journal retained".into());
        }
    }
    let started = Instant::now();
    loop {
        let status = chain.relay_rpc("getShieldedPaymentStatus", json!([id]))?;
        if status["id"] != id {
            return Err("relay status identity mismatch; journal retained".into());
        }
        if status["state"] == "accepted"
            || status["state"] == "aborted"
            || !wait
            || started.elapsed() > Duration::from_secs(150)
        {
            // Even an authenticated relay cannot assert a debit or prove absence.
            let outcome = chain.shielded_outcome(wallet, &bytes, status["signature"].as_str())?;
            operation.record_outcome(&outcome)?;
            fs::remove_file(&operation.shielded)?;
            return Ok(outcome);
        }
        thread::sleep(Duration::from_millis(500));
    }
}
