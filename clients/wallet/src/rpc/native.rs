//! Explicit native-inline relay transport. The shared relay signs only a fixed
//! private proof; users retain their own keys and a durable proof reservation.
use super::Chain;
use crate::keys::{read_private, write_private_new, Network, WalletKey};
use crate::operation::WalletOperation;
use crate::Result;
use base64::Engine;
use native_payment_program::{id, instructions};
use native_payments::staging::payload_digest;
use native_payments::wire;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_rpc_client_api::config::RpcBlockConfig;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{EncodedTransaction, TransactionBinaryEncoding};
use solana_transaction_status_client_types::{TransactionDetails, UiTransactionEncoding};
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fs, thread};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
};

const MAX_PACKET: usize = 16_384;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayIntent {
    format: String,
    network: Network,
    payer: String,
    payload_digest: [u8; 32],
    packet: String,
    packet_sha256: String,
    signature: String,
    expires_at: u64,
    last_valid_block_height: u64,
    gross_cap: u64,
    transaction_fee: u64,
    marker_rent: u64,
    reserved_debit: u64,
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn persist_outcome(
    operation: &WalletOperation,
    pending: &Path,
    outcome: &Value,
) -> Result<()> {
    crate::sponsor::replace(
        &pending.with_extension("receipt.json"),
        &serde_json::to_vec(outcome)?,
    )?;
    operation.record_outcome(outcome)?;
    fs::remove_file(pending)?;
    fs::File::open(pending.parent().ok_or("pending parent missing")?)?.sync_all()?;
    Ok(())
}

impl Chain {
    pub(crate) fn require_native_inline(&self) -> Result<()> {
        if self.pool_format != "NPOOL004" {
            return Err(
                "native-inline requires the explicit NPOOL004 profile; no migration was performed"
                    .into(),
            );
        }
        Ok(())
    }

    /// A successful suffix must contain the exact proof digest. Cached receipt
    /// identity alone is insufficient when an untrusted relay supplies a sig.
    pub(crate) fn native_client_outcome(
        &self,
        wallet: &WalletKey,
        operation: &WalletOperation,
        bytes: &[u8],
        signature: Option<&str>,
        complete: bool,
    ) -> Result<Option<Value>> {
        self.require_native_inline()?;
        let mut synced = self.sync_cached(wallet, operation)?;
        if !synced.scan.cache_saved {
            return Err("encrypted native checkpoint is not durable; intent retained".into());
        }
        let digest = payload_digest(bytes);
        let mut accepted = signature
            .filter(|sig| {
                synced.accepted_finalizations.contains(*sig)
                    && synced.payment_digests.get(*sig) == Some(&digest)
            })
            .map(str::to_owned);
        if accepted.is_none() && complete {
            let outcome = self.shielded_outcome(wallet, bytes, signature)?;
            if outcome["accepted"] == true {
                let original = outcome["signature"]
                    .as_str()
                    .ok_or("canonical native signature missing")?;
                synced = self.sync_cached(wallet, operation)?;
                if !synced.scan.cache_saved || !synced.accepted_finalizations.contains(original) {
                    return Err("canonical native outcome lacks a durable wallet checkpoint".into());
                }
                accepted = Some(original.to_owned());
            } else if outcome["expired_without_execution"] == true {
                return Ok(Some(
                    json!({"accepted":false,"expired_without_execution":true,
                    "balance":synced.state.balance()?,"encrypted_checkpoint_durable":true,
                    "checkpoint":synced.slot,"absence_source":"complete canonical proof replay"}),
                ));
            }
        }
        let Some(signature) = accepted else {
            return Ok(None);
        };
        for note in synced.state.unspent() {
            synced.state.witness(note.position)?;
        }
        Ok(Some(
            json!({"accepted":true,"signature":signature,"balance":synced.state.balance()?,
            "checkpoint":synced.slot,"encrypted_checkpoint_durable":true,"sync":synced.scan,
            "finality_source":"verified canonical finalized RPC history; RPC consensus is trusted"}),
        ))
    }
}

fn strict_expiries(slot: u64, expiry: u64, height: u64, last_valid_height: u64) -> bool {
    slot > expiry && height > last_valid_height
}

fn check_reservation(
    transaction_fee: u64,
    marker_rent: u64,
    shielded_fee: Option<u64>,
    gross_cap: u64,
) -> Result<u64> {
    let debit = transaction_fee
        .checked_add(marker_rent)
        .ok_or("native budget overflow")?;
    if transaction_fee == 0
        || marker_rent == 0
        || gross_cap == 0
        || gross_cap > 250_000_000
        || debit > gross_cap
        || shielded_fee.is_none_or(|fee| fee < debit)
    {
        return Err("native gross cap and shielded fee must each cover exact transaction fee and permanent marker rent".into());
    }
    Ok(debit)
}

fn validate_intent(
    chain: &Chain,
    payer: &Keypair,
    payload: &[u8],
    intent: &RelayIntent,
    gross_cap: u64,
) -> Result<(Vec<u8>, Transaction)> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(&intent.packet)?;
    let payment = wire::decode(chain.network.network, payload)?;
    let transaction: Transaction = bincode::deserialize(&bytes)?;
    transaction.verify()?;
    let expected = Transaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instructions::inline(chain.network.network, payload)?,
        ],
        Some(&payer.pubkey()),
        &[payer],
        transaction.message.recent_blockhash,
    );
    if intent.format != "native-inline-relay-wire-v1"
        || intent.network != chain.network
        || intent.payer != payer.pubkey().to_string()
        || intent.payload_digest != payload_digest(payload)
        || intent.packet_sha256 != sha(&bytes)
        || intent.signature != transaction.signatures[0].to_string()
        || intent.expires_at != payment.context.expires_at
        || intent.last_valid_block_height == 0
        || payment.context.sponsor != payer.pubkey().to_bytes()
        || intent.gross_cap != gross_cap
        || intent.transaction_fee == 0
        || intent.marker_rent == 0
        || intent.transaction_fee.checked_add(intent.marker_rent) != Some(intent.reserved_debit)
        || intent.reserved_debit > gross_cap
        || payment
            .context
            .shielded_fee
            .is_none_or(|fee| fee < intent.reserved_debit)
        || bytes.len() <= 1232
        || bytes.len() > MAX_PACKET
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != intent.packet
        || bincode::serialize(&transaction)? != bytes
        || bincode::serialize(&expected)? != bytes
    {
        return Err("native relay journal wire, authorization or original budget mismatch".into());
    }
    Ok((bytes, transaction))
}

fn submit(endpoint: SocketAddr, bytes: &[u8], signature: &str) -> bool {
    let attempt = || -> Result<()> {
        let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_millis(500))?;
        stream.set_nodelay(true)?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
        stream.write_all(bytes)?;
        let mut line = String::new();
        BufReader::new(stream.take(2048)).read_line(&mut line)?;
        let response: Value = serde_json::from_str(&line)?;
        if response["status"] != "admitted"
            || response["signature"] != signature
            || response["finalized"] != false
        {
            return Err("native ingress supplied no matching admission-only ACK".into());
        }
        Ok(())
    };
    attempt().is_ok()
}

fn finalized_packet(
    chain: &Chain,
    bytes: &[u8],
    slot: u64,
    payload: &[u8],
    transaction_fee: u64,
) -> Result<()> {
    let block = chain.rpc.get_block_with_config(
        slot,
        RpcBlockConfig {
            encoding: Some(UiTransactionEncoding::Base64),
            transaction_details: Some(TransactionDetails::Full),
            rewards: Some(false),
            commitment: Some(CommitmentConfig::finalized()),
            max_supported_transaction_version: Some(0),
        },
    )?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let transactions = block
        .transactions
        .ok_or("finalized native block omits transaction bytes")?;
    let matching: Vec<_> = transactions
        .iter()
        .filter(|tx| {
            matches!(&tx.transaction,
        EncodedTransaction::Binary(raw, TransactionBinaryEncoding::Base64) if raw == &encoded)
        })
        .collect();
    if matching.len() != 1
        || matching[0]
            .meta
            .as_ref()
            .is_none_or(|meta| meta.err.is_some() || meta.fee != transaction_fee)
    {
        return Err("finalized native block lacks the exact successful full packet".into());
    }
    let payment = wire::decode(chain.network.network, payload)?;
    let nullifiers: Vec<_> = payment
        .bundle
        .actions()
        .iter()
        .map(|action| action.nullifier().to_bytes())
        .collect();
    let addresses: Vec<_> = nullifiers
        .iter()
        .map(native_payment_program::nullifiers::address)
        .collect();
    let markers = chain
        .rpc
        .get_multiple_accounts_with_commitment(&addresses, CommitmentConfig::finalized())?;
    if markers.context.slot < slot
        || markers.value.len() != nullifiers.len()
        || markers
            .value
            .iter()
            .zip(nullifiers)
            .any(|(account, nullifier)| {
                account.as_ref().is_none_or(|account| {
                    account.owner != id()
                        || account.executable
                        || account.lamports < 1
                        || account.data != native_payment_program::nullifiers::encode(&nullifier)
                })
            })
    {
        return Err("finalized native packet lacks its permanent exact nullifiers".into());
    }
    Ok(())
}

fn finish_relay_accepted(
    chain: &Chain,
    bytes: &[u8],
    slot: u64,
    payload: &[u8],
    intent: &RelayIntent,
    operation: &WalletOperation,
) -> Result<Value> {
    finalized_packet(chain, bytes, slot, payload, intent.transaction_fee)?;
    let outcome = json!({"accepted":true,"signature":intent.signature,"packet_sha256":intent.packet_sha256,
        "execution_slot":slot,"shielded_fee":wire::decode(chain.network.network,payload)?.context.shielded_fee,
        "transport":"native-inline-v1","exact_packet_canonical":true,"permanent_nullifiers":2,
        "actual_transaction_fee":intent.transaction_fee,"permanent_marker_rent":intent.marker_rent,
        "reserved_gross_debit":intent.reserved_debit});
    persist_outcome(operation, &operation.native, &outcome)?;
    Ok(outcome)
}

/// Operator-only: fixed job, payer and ingress arrive from reviewed local config.
/// An existing journal always wins over new blockhashes, caps or signatures.
pub fn relay_inline(
    chain: &Chain,
    payer: &Keypair,
    payload: &[u8],
    operation: &WalletOperation,
    gross_cap: u64,
    endpoints: &[SocketAddr],
) -> Result<Value> {
    chain.require_native_inline()?;
    if gross_cap == 0
        || gross_cap > 250_000_000
        || endpoints.is_empty()
        || endpoints.len() > 3
        || endpoints
            .iter()
            .any(|endpoint| !endpoint.ip().is_loopback() || endpoint.port() == 0)
        || operation.has_pending()
        || operation.has_staging()
    {
        return Err("native relay requires bounded fixed endpoints, cap and an unmixed job".into());
    }
    let intent = if operation.native.exists() {
        serde_json::from_slice::<RelayIntent>(&read_private(&operation.native, 32_768)?)?
    } else {
        chain.validate_shielded_payload(payload)?;
        let payment = wire::decode(chain.network.network, payload)?;
        if payment.context.sponsor != payer.pubkey().to_bytes() {
            return Err("native relay payer mismatch".into());
        }
        let (blockhash, last_valid_block_height) = chain
            .rpc
            .get_latest_blockhash_with_commitment(CommitmentConfig::finalized())?;
        let transaction = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                instructions::inline(chain.network.network, payload)?,
            ],
            Some(&payer.pubkey()),
            &[payer],
            blockhash,
        );
        let bytes = bincode::serialize(&transaction)?;
        if bytes.len() <= 1232 || bytes.len() > MAX_PACKET {
            return Err("native packet exceeds its strict transport bounds".into());
        }
        let fee: solana_rpc_client_api::response::Response<Option<u64>> = chain.rpc.send(
            solana_rpc_client_api::request::RpcRequest::Custom { method:"getNativePrivateTransactionFee" },
            json!([base64::engine::general_purpose::STANDARD.encode(&bytes), {"commitment":"finalized"}]))?;
        let transaction_fee = fee
            .value
            .filter(|fee| *fee > 0)
            .ok_or("exact native transaction fee is unavailable")?;
        let marker_rent = chain
            .rpc
            .get_minimum_balance_for_rent_exemption(
                native_payment_program::nullifiers::MARKER_BYTES,
            )?
            .max(1)
            .checked_mul(2)
            .ok_or("native marker rent overflow")?;
        let reserved_debit = check_reservation(
            transaction_fee,
            marker_rent,
            payment.context.shielded_fee,
            gross_cap,
        )?;
        let remaining = chain.rpc.get_minimum_balance_for_rent_exemption(0)?;
        if chain
            .rpc
            .get_balance_with_commitment(&payer.pubkey(), CommitmentConfig::finalized())?
            .value
            < reserved_debit
                .checked_add(remaining)
                .ok_or("native payer balance overflow")?
        {
            return Err(
                "native relay payer lacks its exact reserved gross debit and remaining floor"
                    .into(),
            );
        }
        let intent = RelayIntent {
            format: "native-inline-relay-wire-v1".into(),
            network: chain.network.clone(),
            payer: payer.pubkey().to_string(),
            payload_digest: payload_digest(payload),
            packet: base64::engine::general_purpose::STANDARD.encode(&bytes),
            packet_sha256: sha(&bytes),
            signature: transaction.signatures[0].to_string(),
            expires_at: payment.context.expires_at,
            last_valid_block_height,
            gross_cap,
            transaction_fee,
            marker_rent,
            reserved_debit,
        };
        validate_intent(chain, payer, payload, &intent, gross_cap)?;
        write_private_new(&operation.native, &serde_json::to_vec(&intent)?)?;
        intent
    };
    let (bytes, transaction) = validate_intent(chain, payer, payload, &intent, gross_cap)?;
    let began = Instant::now();
    let mut next_send = Instant::now();
    while began.elapsed() < Duration::from_secs(60) {
        let status = chain
            .rpc
            .get_signature_statuses_with_history(&[transaction.signatures[0]])?;
        if let Some(status) = status.value.first().and_then(Option::as_ref) {
            if status.satisfies_commitment(CommitmentConfig::finalized()) && status.err.is_none() {
                return finish_relay_accepted(
                    chain,
                    &bytes,
                    status.slot,
                    payload,
                    &intent,
                    operation,
                );
            }
        }
        let finalized_slot = chain
            .rpc
            .get_slot_with_commitment(CommitmentConfig::finalized())?;
        if finalized_slot > intent.expires_at
            && strict_expiries(
                finalized_slot,
                intent.expires_at,
                chain
                    .rpc
                    .get_block_height_with_commitment(CommitmentConfig::finalized())?,
                intent.last_valid_block_height,
            )
        {
            let observer = WalletKey::generate(chain.network.clone())?;
            let outcome = chain.shielded_outcome(&observer, payload, Some(&intent.signature))?;
            if outcome["accepted"] == true && outcome["signature"] == intent.signature {
                let slot = outcome["execution_slot"]
                    .as_u64()
                    .ok_or("canonical original payment slot missing; packet retained")?;
                return finish_relay_accepted(chain, &bytes, slot, payload, &intent, operation);
            }
            if outcome["accepted"] == false && outcome["expired_without_execution"] == true {
                let outcome = json!({"accepted":false,"expired_without_execution":true,"signature":intent.signature,
                    "packet_sha256":intent.packet_sha256,"transport":"native-inline-v1","absence_source":"complete canonical proof replay plus both strict expiries"});
                persist_outcome(operation, &operation.native, &outcome)?;
                return Ok(outcome);
            }
            return Err(
                "native proof execution remains unresolved; original packet retained".into(),
            );
        }
        if Instant::now() >= next_send {
            thread::scope(|scope| {
                let packet = bytes.as_slice();
                let signature = intent.signature.as_str();
                let handles: Vec<_> = endpoints
                    .iter()
                    .map(|endpoint| scope.spawn(move || submit(*endpoint, packet, signature)))
                    .collect();
                for handle in handles {
                    let _ = handle.join();
                }
            });
            next_send = Instant::now() + Duration::from_millis(250);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("native relay outcome remains unresolved; original exact packet and cap retained".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_fee_reservation_never_spends_past_cap_or_shielded_reimbursement() {
        assert_eq!(
            check_reservation(5_000, 2_338_560, Some(3_000_000), 3_000_000).unwrap(),
            2_343_560
        );
        for (fee, rent, reimbursement, cap) in [
            (5_000, 2_338_560, Some(2_343_559), 3_000_000),
            (5_000, 2_338_560, Some(3_000_000), 2_343_559),
            (5_000, 2_338_560, None, 3_000_000),
            (0, 2_338_560, Some(3_000_000), 3_000_000),
            (5_000, 0, Some(3_000_000), 3_000_000),
            (u64::MAX, 1, Some(u64::MAX), 250_000_000),
        ] {
            assert!(check_reservation(fee, rent, reimbursement, cap).is_err());
        }
    }
    #[test]
    fn expiry_gate_requires_both_strict_bounds_and_never_asserts_absence_itself() {
        for (slot, height, expected) in [
            (100, 201, false),
            (101, 200, false),
            (100, 200, false),
            (101, 201, true),
        ] {
            assert_eq!(strict_expiries(slot, 100, height, 200), expected);
        }
        // The relay still requires complete canonical proof replay after true.
    }
}
