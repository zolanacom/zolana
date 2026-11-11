//! The fixed gas-grant transaction lifecycle for one durable claim.
//! Save its original signed transaction before broadcast, reconcile canonical
//! status before retry, and keep the existing finite attempt budget.

use super::{save, Claim, Gas, Progress, ATTEMPTS, GAS_GRANT};
use crate::Result;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::path::Path;

pub(super) fn gas(
    rpc: &solana_rpc_client::rpc_client::RpcClient,
    payer: &Keypair,
    claim: &Claim,
    p: &mut Progress,
    path: &Path,
) -> Result<()> {
    let recipient: Pubkey = claim.fee_address.parse()?;
    if p.gas.is_none() {
        if p.gas_attempts >= ATTEMPTS {
            return Ok(());
        }
        let (hash, height) =
            rpc.get_latest_blockhash_with_commitment(CommitmentConfig::finalized())?;
        let tx = Transaction::new_signed_with_payer(
            &[solana_system_interface::instruction::transfer(
                &payer.pubkey(),
                &recipient,
                GAS_GRANT,
            )],
            Some(&payer.pubkey()),
            &[payer],
            hash,
        );
        let fee = rpc.get_fee_for_message(&tx.message)?;
        if fee > 10_000 {
            return Err("faucet gas transfer fee exceeds fixed limit".into());
        }
        p.gas_attempts += 1;
        p.gas = Some(Gas {
            transaction: bincode::serialize(&tx)?,
            last_valid_block_height: height,
        });
        save(path, p)?; // Full signed identity, not just a recipient balance, before broadcast.
    }
    let gas = p.gas.as_ref().ok_or("missing gas identity")?;
    let tx: Transaction = bincode::deserialize(&gas.transaction)?;
    let expected = Transaction::new_signed_with_payer(
        &[solana_system_interface::instruction::transfer(
            &payer.pubkey(),
            &recipient,
            GAS_GRANT,
        )],
        Some(&payer.pubkey()),
        &[payer],
        tx.message.recent_blockhash,
    );
    if tx != expected {
        return Err("saved gas transaction differs from fixed claim".into());
    }
    let signature = tx.signatures[0];
    let statuses = rpc.get_signature_statuses_with_history(&[signature])?;
    if let Some(s) = statuses.value.first().and_then(Option::as_ref) {
        if s.satisfies_commitment(CommitmentConfig::finalized()) {
            if s.err.is_some() {
                return Err("gas transaction failed canonically; original record retained".into());
            }
            p.gas_done = true;
            save(path, p)?;
            return Ok(());
        }
        // The original identity is already observed. Wait for canonical finality
        // or disappearance on a later tick instead of racing preflight with it.
        return Ok(());
    }
    if rpc.get_block_height_with_commitment(CommitmentConfig::finalized())?
        > gas.last_valid_block_height
    {
        // Resolve once more after the finalized expiry checkpoint before re-signing.
        if rpc
            .get_signature_statuses_with_history(&[signature])?
            .value
            .first()
            .and_then(Option::as_ref)
            .is_none()
        {
            p.gas = None;
            save(path, p)?;
            return Ok(());
        }
        return Ok(());
    }
    rpc.send_transaction_with_config(
        &tx,
        RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
            max_retries: Some(0),
            ..Default::default()
        },
    )?;
    Ok(())
}
