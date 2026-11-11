//! Staged transaction submission and recovery of the original signed intent.
//! Pending and staging journals retain their established serialization and ordering.
use super::{Chain, Pending, StagingRecovery, Submitted};
use crate::{
    keys::{read_private, write_private_new, WalletKey},
    operation::WalletOperation,
    Result,
};
use native_payment_program::{
    id, instructions, pool_address,
    staging::{Buffer, ACCOUNT_BYTES},
};
use native_payments::{staging::payload_digest, state::PoolState, wire};
use solana_account::Account;
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::{RpcAccountInfoConfig, RpcSendTransactionConfig};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction as system;
use solana_transaction::Transaction;
use std::{
    fs,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

impl Chain {
    pub fn expiry(&self) -> Result<u64> {
        Ok(self
            .rpc
            .get_slot_with_commitment(CommitmentConfig::confirmed())?
            .checked_add(512)
            .ok_or("slot overflow")?)
    }

    fn send(
        &self,
        sponsor: &Keypair,
        instructions: &[Instruction],
        extra: &[&Keypair],
    ) -> Result<Signature> {
        let mut signers = vec![sponsor];
        signers.extend_from_slice(extra);
        let tx = Transaction::new_signed_with_payer(
            instructions,
            Some(&sponsor.pubkey()),
            &signers,
            self.rpc.get_latest_blockhash()?,
        );
        self.send_signed(&tx)
    }

    fn send_signed(&self, tx: &Transaction) -> Result<Signature> {
        self.send_signed_debit(tx, 0)
    }

    fn send_signed_debit(&self, tx: &Transaction, native_debit: u64) -> Result<Signature> {
        if 1 + tx.signatures.len() * 64 + tx.message_data().len() > 1232 {
            return Err("signed wallet transaction exceeds the network packet limit".into());
        }
        self.charge_sponsor(tx, native_debit)?;
        let signature = self.rpc.send_transaction_with_config(
            tx,
            RpcSendTransactionConfig {
                skip_preflight: false,
                preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                max_retries: Some(3),
                ..Default::default()
            },
        )?;
        self.wait(&signature, CommitmentConfig::confirmed())?;
        Ok(signature)
    }

    fn wait(&self, signature: &Signature, commitment: CommitmentConfig) -> Result<()> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self
                .rpc
                .get_signature_status_with_commitment(signature, commitment)?
            {
                status?;
                return Ok(());
            }
            thread::sleep(Duration::from_millis(150));
        }
        Err(format!("execution status is unknown for {signature}; sync the wallet and check this signature before retrying").into())
    }

    /// Staging only: collect every confirmed outcome before repairing a suffix.
    /// An unknown/missing status aborts; never race late writes against repair.
    fn wait_upload_burst(&self, signatures: &[Signature]) -> Result<(usize, u64)> {
        if signatures.is_empty() || signatures.len() > 32 {
            return Err("invalid upload burst size".into());
        }
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            let response = self.rpc.get_signature_statuses(signatures)?;
            if response.value.len() != signatures.len() {
                return Err(
                    "upload status response omitted a transaction; reclaim staging before retrying"
                        .into(),
                );
            }
            if response.value.iter().all(|status| {
                status
                    .as_ref()
                    .is_some_and(|s| s.satisfies_commitment(CommitmentConfig::confirmed()))
            }) {
                let failed = response
                    .value
                    .iter()
                    .flatten()
                    .filter(|s| s.err.is_some())
                    .count();
                let slot = response
                    .value
                    .iter()
                    .flatten()
                    .map(|s| s.slot)
                    .max()
                    .unwrap();
                return Ok((failed, slot));
            }
            thread::sleep(Duration::from_millis(150));
        }
        Err("upload outcomes remain unknown; original staging identity retained for reclaim".into())
    }

    fn check_upload(tx: &Transaction) -> Result<()> {
        // Only internally generated write/seal instructions may skip preflight.
        // Initialization, payment finalization and cleanup retain preflight.
        if tx.message.instructions.iter().any(|ix| {
            tx.message.account_keys.get(ix.program_id_index as usize) != Some(&id())
                || !matches!(ix.data.first(), Some(1 | 2))
        }) || tx.message.instructions.is_empty()
        {
            return Err("upload burst accepts only staging writes and seal".into());
        }
        if 1 + tx.signatures.len() * 64 + tx.message_data().len() > 1232 {
            return Err("signed upload transaction exceeds the network packet limit".into());
        }
        Ok(())
    }

    pub(super) fn send_uploads(&self, transactions: &[Transaction]) -> Result<Vec<Signature>> {
        if transactions.is_empty() || transactions.len() > 16 {
            return Err("invalid bounded upload sequence".into());
        }
        for tx in transactions {
            Self::check_upload(tx)?;
        }
        let fees = if self.sponsor_budget.is_some() || self.user_fees.is_some() {
            self.transaction_fees(transactions)?
        } else {
            vec![0; transactions.len()]
        };
        transactions
            .iter()
            .zip(fees)
            .map(|(tx, fee)| {
                // Debit each actual attempt durably before its first broadcast.
                // Quoting a future chunk never spends/refills its authorization.
                self.charge_quoted(tx, 0, fee)?;
                Ok(self.rpc.send_transaction_with_config(
                    tx,
                    RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                        max_retries: Some(3),
                        ..Default::default()
                    },
                )?)
            })
            .collect()
    }

    pub fn resolve(
        &self,
        wallet: &WalletKey,
        operation: &WalletOperation,
    ) -> Result<serde_json::Value> {
        let path = &operation.pending;
        let pending: Pending = serde_json::from_slice(&read_private(path, 4096)?)?;
        if pending.network != self.network {
            return Err("pending transaction network mismatch".into());
        }
        let signature = Signature::from_str(&pending.signature)?;
        Pubkey::from_str(&pending.staging_account)?;
        // Private sends can extend the same authenticated, canonically pinned
        // checkpoint used by normal wallet sync. Withdrawal intent still needs
        // full receipt replay: that recipient/amount map is not cached.
        let mut synced = if pending.withdrawal.is_none() {
            self.sync_cached(wallet, operation)?
        } else {
            self.sync(wallet)?
        };
        let statuses = self.rpc.get_signature_statuses_with_history(&[signature])?;
        let mut failed = statuses
            .value
            .first()
            .and_then(Option::as_ref)
            .is_some_and(|status| {
                status.satisfies_commitment(CommitmentConfig::finalized()) && status.err.is_some()
            });
        if !synced.accepted_finalizations.contains(&pending.signature)
            && !failed
            && synced.canonical_from_slot != 0
        {
            // Recover old/retained-derived checkpoints when a full canonical
            // archive is available. Never substitute ciphertext metadata here.
            synced = self.scan_source_mode(&[wallet], None, None, None, false)
                .map_err(|_| "canonical full RPC history is required; retained ciphertexts and checkpoints cannot prove absence; pending record retained")?
                .finish().pop().ok_or("missing canonical recovery state")?;
        }
        let accepted = synced.accepted_finalizations.contains(&pending.signature);
        if let Some((staging, canonical_failed)) = synced.finalizations.get(&pending.signature) {
            if staging != &pending.staging_account {
                return Err("canonical finalization differs from the saved staging account; pending record retained".into());
            }
            failed |= *canonical_failed;
        }
        let withdrawal = synced.withdrawals.get(&pending.signature).cloned();
        if accepted
            && pending
                .withdrawal
                .as_ref()
                .is_some_and(|intent| Some(intent) != withdrawal.as_ref())
        {
            return Err("canonical withdrawal differs from the saved recipient/amount/sponsor intent; pending record retained".into());
        }
        let expired_without_execution =
            !accepted && !failed && synced.block_height > pending.last_valid_block_height;
        if !accepted && !failed && !expired_without_execution {
            return Err(format!(
                "transaction {} is still pending; no new payment was authorized",
                pending.signature
            )
            .into());
        }
        operation.record_outcome(&serde_json::json!({"signature":pending.signature,"accepted":accepted,"failed":failed,"expired_without_execution":expired_without_execution}))?;
        fs::remove_file(path)?;
        Ok(
            serde_json::json!({"signature":pending.signature,"accepted":accepted,"failed":failed,
            "expired_without_execution":expired_without_execution,"staging_account":pending.staging_account,
            "balance":synced.state.balance()?,"pending_cleared":true,
            "staging_recovery_required":operation.staging.exists(),"withdrawal":withdrawal,"sync":synced.scan}),
        )
    }

    pub fn submit(
        &self,
        sponsor: &Keypair,
        bytes: &[u8],
        operation: &WalletOperation,
    ) -> Result<Submitted> {
        operation.ensure_resolved()?;
        self.submit_inner(sponsor, bytes, operation)
            .map_err(|error| {
                if operation.pending.exists() {
                    format!("{error}; payment remains recorded; run resolve before retrying").into()
                } else if operation.staging.exists() {
                    format!("{error}; staging remains recorded; run reclaim before retrying").into()
                } else {
                    error
                }
            })
    }

    fn submit_inner(
        &self,
        sponsor: &Keypair,
        bytes: &[u8],
        operation: &WalletOperation,
    ) -> Result<Submitted> {
        let pending_path = &operation.pending;
        let upload_started = Instant::now();
        let payment = wire::decode(self.network.network, bytes)?;
        if payment.context.sponsor != sponsor.pubkey().to_bytes() {
            return Err("payment sponsor does not match the local signer".into());
        }
        if self.sponsor_budget.is_some()
            && payment.context.public_value_balance > 0
            && payment.context.withdrawal_recipient.is_none()
        {
            return Err(
                "managed withdrawals require a separately authorized public recipient".into(),
            );
        }
        if let Some(recipient) = payment.context.withdrawal_recipient {
            if recipient == sponsor.pubkey().to_bytes() {
                return Err("withdrawal recipient must differ from fee sponsor".into());
            }
            self.check_withdrawal(
                Pubkey::new_from_array(recipient),
                payment.context.public_value_balance as u64,
            )?;
        }
        let checkpoint = self
            .rpc
            .get_account_with_commitment(&pool_address(), CommitmentConfig::confirmed())?;
        let current = checkpoint.value.ok_or("native pool is missing")?;
        let current_state = PoolState::decode(&current.data)?;
        self.check_pool_format(&current_state)?;
        if current.owner != id()
            || !current_state
                .accepted_roots(checkpoint.context.slot)?
                .contains(&payment.bundle.anchor().to_bytes())
        {
            return Err(
                "payment anchor is no longer available; sync and prepare a new payment".into(),
            );
        }
        if payment.context.expires_at < checkpoint.context.slot {
            return Err(
                "payment authorization expired before upload; sync and prepare a new payment"
                    .into(),
            );
        }
        let user_fee = if let Some((payer, maximum, _)) = &self.user_fees {
            if self.sponsor_budget.is_some() || *payer != sponsor.pubkey() {
                return Err(
                    "user-paid mode requires the user's fee signer and no operator sponsor".into(),
                );
            }
            let kind = crate::fees::PaymentKind::from_context(&payment.context)?;
            let quote = self.payment_fee_quote(*payer, kind)?;
            if *maximum < quote.maximum_gross_debit {
                return Err(format!(
                    "user fee debit cap is below the current {} quote",
                    kind.name()
                )
                .into());
            }
            if self.public_balance(*payer)?
                < maximum
                    .checked_add(quote.minimum_remaining_balance)
                    .ok_or("fee funding overflow")?
            {
                return Err("user fee account needs more public native coins for the authorized cap and minimum balance".into());
            }
            Some(crate::fees::Authorization::new(
                *maximum,
                quote.cleanup_reserve,
            )?)
        } else {
            None
        };
        let expiry = payment.context.expires_at;
        let buffer = Keypair::new();
        let (blockhash, last_valid_block_height) = self
            .rpc
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())?;
        let staging_rent = self
            .rpc
            .get_minimum_balance_for_rent_exemption(ACCOUNT_BYTES)?;
        let initialization = Transaction::new_signed_with_payer(
            &[
                system::create_account(
                    &sponsor.pubkey(),
                    &buffer.pubkey(),
                    staging_rent,
                    ACCOUNT_BYTES as u64,
                    &id(),
                ),
                instructions::initialize(
                    buffer.pubkey(),
                    sponsor.pubkey(),
                    bytes.len() as u32,
                    payload_digest(bytes),
                    expiry,
                ),
                crate::upload::first_write(buffer.pubkey(), sponsor.pubkey(), bytes),
            ],
            Some(&sponsor.pubkey()),
            &[sponsor, &buffer],
            blockhash,
        );
        // The initialization identity is persisted before any staging broadcast.
        // Only the account's public key is needed to reclaim its sponsor's rent.
        write_private_new(
            &operation.staging,
            &serde_json::to_vec_pretty(&StagingRecovery {
                network: self.network.clone(),
                sponsor: sponsor.pubkey().to_string(),
                staging_account: buffer.pubkey().to_string(),
                initialize_signature: initialization.signatures[0].to_string(),
                last_valid_block_height,
                expiry,
                payload_len: bytes.len() as u32,
                payload_digest: payload_digest(bytes),
                user_fee,
                sponsor_request_id: self
                    .sponsor_budget
                    .as_ref()
                    .map(|budget| budget.request_id().to_owned()),
            })?,
        )?;
        self.send_signed_debit(&initialization, staging_rent)?;
        let batches = crate::upload::remaining(buffer.pubkey(), sponsor.pubkey(), bytes);
        let mut upload_transactions = 1 + batches.len();
        let mut transactions = Vec::with_capacity(batches.len());
        for batch in batches {
            let tx = Transaction::new_signed_with_payer(
                &batch,
                Some(&sponsor.pubkey()),
                &[sponsor],
                blockhash,
            );
            transactions.push(tx);
        }
        let signatures = self.send_uploads(&transactions)?;
        let (upload_failed_transactions, confirmed_slot) = self.wait_upload_burst(&signatures)?;
        let account = self
            .staging_account(
                &buffer.pubkey(),
                CommitmentConfig::confirmed(),
                confirmed_slot,
            )?
            .ok_or("confirmed staging account disappeared; reclaim before retrying")?;
        if account.owner != id() {
            return Err("confirmed staging owner mismatch".into());
        }
        let repair = crate::upload::repair(
            buffer.pubkey(),
            sponsor.pubkey(),
            bytes,
            expiry,
            &account.data,
        )?;
        // One bounded suffix repair; never reinitialize, regenerate a payment,
        // replenish a debit allowance or silently resubmit unknown transactions.
        if repair.len() > signatures.len() {
            return Err("staging repair exceeds original bounded suffix".into());
        }
        let upload_repair_transactions = repair.len();
        if !repair.is_empty() {
            let repair_hash = self
                .rpc
                .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())?
                .0;
            if repair_hash == blockhash {
                return Err("repair needs a fresh blockhash; staging remains recorded".into());
            }
            for batch in repair {
                let tx = Transaction::new_signed_with_payer(
                    &batch,
                    Some(&sponsor.pubkey()),
                    &[sponsor],
                    repair_hash,
                );
                self.send_signed(&tx)?;
                upload_transactions += 1;
            }
        }
        let upload_ms = upload_started.elapsed().as_millis();
        crate::progress::report("confirm");
        let finalization_started = Instant::now();
        let nullifiers = std::array::from_fn(|index| {
            payment
                .bundle
                .actions()
                .get(index)
                .unwrap()
                .nullifier()
                .to_bytes()
        });
        let mut finalization = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        finalization.extend(instructions::finalize_and_close(
            buffer.pubkey(),
            sponsor.pubkey(),
            nullifiers,
            payment
                .context
                .withdrawal_recipient
                .map(Pubkey::new_from_array),
        ));
        let (blockhash, last_valid_block_height) = self
            .rpc
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())?;
        let tx = Transaction::new_signed_with_payer(
            &finalization,
            Some(&sponsor.pubkey()),
            &[sponsor],
            blockhash,
        );
        if 1 + tx.signatures.len() * 64 + tx.message_data().len() > 1232 {
            return Err("finalization exceeds the signed packet limit".into());
        }
        let signature = tx.signatures[0];
        // Gross debit includes the temporary staging rent, permanent markers,
        // public deposit and every fee. Refunds/withdrawal credits never refill it.
        let marker_rent = self
            .rpc
            .get_minimum_balance_for_rent_exemption(
                native_payment_program::nullifiers::MARKER_BYTES,
            )?
            .max(1);
        let deposit = if payment.context.public_value_balance < 0 {
            payment.context.public_value_balance.unsigned_abs()
        } else {
            0
        };
        let native_debit = marker_rent
            .checked_mul(2)
            .and_then(|n| n.checked_add(deposit))
            .ok_or("sponsor debit overflow")?;
        self.charge_sponsor(&tx, native_debit)?;
        // Durable create_new is also an inter-process lock. The signed identity
        // is saved before the first possible broadcast of value-changing effects.
        write_private_new(
            pending_path,
            &serde_json::to_vec_pretty(&Pending {
                network: self.network.clone(),
                signature: signature.to_string(),
                staging_account: buffer.pubkey().to_string(),
                last_valid_block_height,
                withdrawal: crate::payments::withdrawal_receipt(&payment),
            })?,
        )?;
        self.rpc.send_transaction_with_config(&tx, RpcSendTransactionConfig {
            skip_preflight: false, preflight_commitment: Some(CommitmentConfig::confirmed().commitment), max_retries: Some(3), ..Default::default()
        }).map_err(|error| format!("finalization {signature} remains recorded as pending; run resolve before retrying: {error}"))?;
        self.wait(&signature, CommitmentConfig::confirmed())
            .map_err(|error| {
                format!(
                    "finalization {signature} remains recorded as pending; run resolve: {error}"
                )
            })?;
        let confirmation_ms = finalization_started.elapsed().as_millis();
        crate::progress::report("finalize");
        self.wait(&signature, CommitmentConfig::finalized())
            .map_err(|error| {
                format!(
                    "finalization {signature} remains recorded as pending; run resolve: {error}"
                )
            })?;
        operation.record_outcome(
            &serde_json::json!({"signature":signature.to_string(),"accepted":true}),
        )?;
        fs::remove_file(pending_path)?;
        let finalization_ms = finalization_started.elapsed().as_millis();
        let cleanup_started = Instant::now();
        // The same finalized transaction already closed the account. Verify its
        // absence at that signature's slot; never submit a second close or wait
        // for another transaction to finalize. A failed RPC check retains the
        // original recovery record without turning an accepted payment into failure.
        let reclaimed = self.wait_closed(&buffer.pubkey(), &signature).is_ok();
        let user_fee_charged = if self.user_fees.is_some() {
            read_private(&operation.staging, 4096)
                .ok()
                .and_then(|raw| serde_json::from_slice::<StagingRecovery>(&raw).ok())
                .and_then(|r| r.user_fee.map(|a| a.charged))
        } else {
            None
        };
        if reclaimed {
            // Payment acceptance must remain a success even if local cleanup fails.
            let _ = fs::remove_file(&operation.staging);
        }
        Ok(Submitted {
            signature: signature.to_string(),
            staging_account: buffer.pubkey().to_string(),
            staging_rent_reclaimed: reclaimed,
            upload_transactions,
            upload_failed_transactions,
            upload_repair_transactions,
            upload_ms,
            finalization_ms,
            confirmation_ms,
            cleanup_ms: cleanup_started.elapsed().as_millis(),
            withdrawal: crate::payments::withdrawal_receipt(&payment),
            user_fee_charged,
        })
    }

    fn account_config(commitment: CommitmentConfig, minimum_slot: u64) -> RpcAccountInfoConfig {
        RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(commitment),
            min_context_slot: Some(minimum_slot),
            ..Default::default()
        }
    }

    fn staging_account(
        &self,
        buffer: &Pubkey,
        commitment: CommitmentConfig,
        minimum_slot: u64,
    ) -> Result<Option<Account>> {
        let response = self
            .rpc
            .get_account_with_config(buffer, Self::account_config(commitment, minimum_slot))?;
        if response.context.slot < minimum_slot {
            return Err("RPC staging account checkpoint is older than required".into());
        }
        Ok(response.value)
    }

    fn wait_closed(&self, buffer: &Pubkey, signature: &Signature) -> Result<()> {
        self.wait(signature, CommitmentConfig::finalized())?;
        let status = self
            .rpc
            .get_signature_statuses_with_history(&[*signature])?
            .value
            .into_iter()
            .next()
            .flatten()
            .ok_or("finalized staging-close status is unavailable")?;
        if status.err.is_some() || !status.satisfies_commitment(CommitmentConfig::finalized()) {
            return Err("staging close has not finalized successfully".into());
        }
        if self
            .staging_account(buffer, CommitmentConfig::finalized(), status.slot)?
            .is_some()
        {
            return Err("staging account remains present after finalized close".into());
        }
        Ok(())
    }

    pub fn reclaim(
        &self,
        sponsor: &Keypair,
        operation: &WalletOperation,
    ) -> Result<serde_json::Value> {
        if operation.pending.exists() {
            return Err(
                "an unresolved payment exists; run resolve before reclaiming staging".into(),
            );
        }
        let recovery: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096)?)?;
        if recovery.network != self.network || recovery.sponsor != sponsor.pubkey().to_string() {
            return Err("staging recovery network or sponsor mismatch".into());
        }
        if recovery.user_fee.is_some() != self.user_fees.is_some() {
            return Err("recovery must use the original recorded fee mode".into());
        }
        let buffer = Pubkey::from_str(&recovery.staging_account)?;
        let initialization = Signature::from_str(&recovery.initialize_signature)?;
        let checkpoint = self
            .rpc
            .get_epoch_info_with_commitment(CommitmentConfig::finalized())?;
        let confirmed = self.staging_account(
            &buffer,
            CommitmentConfig::confirmed(),
            checkpoint.absolute_slot,
        )?;
        let mut close_signature = None;
        if let Some(account) = confirmed {
            if account.owner != id() || account.data.len() != ACCOUNT_BYTES {
                return Err("staging recovery account owner or size mismatch".into());
            }
            let staged = Buffer::decode(&account.data)?;
            if staged.sponsor() != sponsor.pubkey().to_bytes()
                || staged.expiry() != recovery.expiry
                || account.data[40..44] != recovery.payload_len.to_le_bytes()
                || account.data[48..80] != recovery.payload_digest
            {
                return Err("staging recovery account does not match the saved upload".into());
            }
            let signature = self.send(
                sponsor,
                &[instructions::close(buffer, sponsor.pubkey())],
                &[],
            )?;
            self.wait_closed(&buffer, &signature)?;
            close_signature = Some(signature.to_string());
        } else {
            let status = self
                .rpc
                .get_signature_statuses_with_history(&[initialization])?
                .value
                .into_iter()
                .next()
                .flatten();
            let finalized_slot = status
                .as_ref()
                .filter(|s| s.satisfies_commitment(CommitmentConfig::finalized()))
                .map(|s| s.slot);
            let expired = checkpoint.block_height > recovery.last_valid_block_height;
            if finalized_slot.is_none() && !expired {
                return Err(
                    "staging initialization is still pending; recovery record retained".into(),
                );
            }
            let minimum = checkpoint.absolute_slot.max(finalized_slot.unwrap_or(0));
            if self
                .staging_account(&buffer, CommitmentConfig::finalized(), minimum)?
                .is_some()
            {
                return Err("staging account is still present; run reclaim again".into());
            }
        }
        fs::remove_file(&operation.staging)?;
        Ok(
            serde_json::json!({"staging_account":buffer.to_string(),"close_signature":close_signature,
            "recovery_cleared":true,"rent_reclaimed":close_signature.is_some()}),
        )
    }
}
