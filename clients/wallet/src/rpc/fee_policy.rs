//! Fee quotation, withdrawal eligibility and durable debit authorization.
//! Charge journals are updated before transaction transport is attempted.
use super::{reads, Chain, StagingRecovery};
use crate::{keys::read_private, operation::WalletOperation, Result};
use base64::Engine;
use native_payment_program::{id, instructions, staging::ACCOUNT_BYTES};
use native_payments::staging::payload_digest;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_system_interface::instruction as system;
use solana_transaction::Transaction;

impl Chain {
    pub fn with_sponsor_budget(mut self, budget: crate::sponsor::Budget) -> Self {
        self.sponsor_budget = Some(budget);
        self
    }

    pub fn public_balance(&self, recipient: Pubkey) -> Result<u64> {
        Ok(self.rpc.get_balance(&recipient)?)
    }
    pub fn minimum_withdrawal(&self, recipient: Pubkey) -> Result<u64> {
        if !recipient.is_on_curve() {
            return Err("withdrawal recipient must be a public signing address".into());
        }
        let account = self
            .rpc
            .get_account_with_commitment(&recipient, CommitmentConfig::confirmed())?
            .value;
        let balance = if let Some(account) = account {
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
        Ok(self
            .rpc
            .get_minimum_balance_for_rent_exemption(0)?
            .saturating_sub(balance)
            .max(1))
    }
    pub fn check_withdrawal(&self, recipient: Pubkey, amount: u64) -> Result<()> {
        self.check_withdrawal_activation()?;
        let minimum = self.minimum_withdrawal(recipient)?;
        if amount < minimum {
            return Err(format!("withdrawal needs at least {minimum} native units to meet the public account minimum balance").into());
        }
        Ok(())
    }

    pub(super) fn check_withdrawal_activation(&self) -> Result<()> {
        let feature = self
            .rpc
            .get_account(&native_payment_program::WITHDRAWAL_ACTIVATION_ID)?;
        let active =
            solana_feature_gate_interface::from_account(&feature).and_then(|f| f.activated_at);
        if !active.is_some_and(|slot| self.rpc.get_slot().is_ok_and(|current| slot <= current)) {
            return Err("recipient-bound withdrawals are not active on this network".into());
        }
        Ok(())
    }

    pub fn with_user_fees(
        mut self,
        payer: Pubkey,
        maximum: u64,
        operation: &WalletOperation,
    ) -> Result<Self> {
        if self.sponsor_budget.is_some() {
            return Err("fee modes cannot be combined".into());
        }
        self.user_fees = Some((payer, maximum, operation.staging.clone()));
        Ok(self)
    }

    pub fn recovery_user_limit(
        &self,
        operation: &WalletOperation,
        payer: Pubkey,
    ) -> Result<Option<u64>> {
        let recovery: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096)?)?;
        if recovery.network != self.network {
            return Err("staging recovery network mismatch".into());
        }
        if let Some(a) = recovery.user_fee {
            a.validate()?;
            if recovery.sponsor != payer.to_string() || recovery.sponsor_request_id.is_some() {
                return Err("user fee recovery authority or mode mismatch".into());
            }
            return Ok(Some(a.maximum));
        }
        Ok(None)
    }

    fn transaction_fee(&self, tx: &Transaction) -> Result<u64> {
        let response: solana_rpc_client_api::response::Response<Option<u64>> = self.rpc.send(
            solana_rpc_client_api::request::RpcRequest::GetFeeForMessage,
            serde_json::json!([
                base64::engine::general_purpose::STANDARD.encode(tx.message.serialize()),
                CommitmentConfig::confirmed()
            ]),
        )?;
        response
            .value
            .ok_or_else(|| "fee unavailable for this blockhash".into())
    }

    pub fn withdrawal_fee_quote(
        &self,
        payer: Pubkey,
        recipient: Pubkey,
    ) -> Result<crate::fees::Quote> {
        self.payment_fee_quote(payer, crate::fees::PaymentKind::Withdraw(recipient))
    }

    pub fn private_send_fee_quote(&self, payer: Pubkey) -> Result<crate::fees::Quote> {
        self.payment_fee_quote(payer, crate::fees::PaymentKind::Send)
    }

    pub fn payment_fee_quote(
        &self,
        payer: Pubkey,
        kind: crate::fees::PaymentKind,
    ) -> Result<crate::fees::Quote> {
        let reads::QuoteInputs {
            rent,
            markers,
            remaining,
            balance,
            hash,
        } = self.quote_inputs(payer)?;
        let hash = hash.parse()?;
        let bytes = vec![0; kind.payload_len()]; // Exact two-action shape; no proof or private recipient is sent.
        let buffer = Pubkey::new_unique();
        let mut batches = vec![vec![
            system::create_account(&payer, &buffer, rent, ACCOUNT_BYTES as u64, &id()),
            instructions::initialize(buffer, payer, bytes.len() as u32, payload_digest(&bytes), 1),
            crate::upload::first_write(buffer, payer, &bytes),
        ]];
        let uploads = crate::upload::remaining(buffer, payer, &bytes);
        batches.extend(uploads.clone());
        let mut finalization = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        finalization.extend(instructions::finalize_and_close(
            buffer,
            payer,
            [[1; 32], [2; 32]],
            match kind {
                crate::fees::PaymentKind::Send | crate::fees::PaymentKind::ShieldedSend => None,
                crate::fees::PaymentKind::Withdraw(recipient) => Some(recipient),
            },
        ));
        batches.push(finalization);
        let message = |ix: &[Instruction]| {
            let mut tx = Transaction::new_with_payer(ix, Some(&payer));
            tx.message.recent_blockhash = hash;
            tx
        };
        let mut transactions: Vec<_> = batches.iter().map(|batch| message(batch)).collect();
        transactions.push(message(&[instructions::close(buffer, payer)]));
        let fees = self.transaction_fees(&transactions)?;
        // Reserve one complete ordered repair of the suffix, without assuming
        // burst ordering or refunding fees for failed staging transactions.
        // Reuse the exact same message's quote rather than repeating RPC reads.
        let mut normal_fees = 0u64;
        let mut upload_repair_reserve = 0u64;
        for (index, &quoted) in fees[..batches.len()].iter().enumerate() {
            normal_fees = normal_fees.checked_add(quoted).ok_or("fee overflow")?;
            if (1..=uploads.len()).contains(&index) {
                upload_repair_reserve = upload_repair_reserve
                    .checked_add(quoted)
                    .ok_or("repair fee overflow")?;
            }
        }
        let close_fee = fees[batches.len()];
        let reserve = close_fee
            .checked_mul(2)
            .filter(|v| *v > 0)
            .ok_or("invalid cleanup fee")?;
        let maximum = rent
            .checked_add(markers)
            .and_then(|n| n.checked_add(normal_fees))
            .and_then(|n| n.checked_add(upload_repair_reserve))
            .and_then(|n| n.checked_add(reserve))
            .ok_or("fee quote overflow")?;
        let required = maximum.checked_add(remaining).ok_or("fee quote overflow")?;
        Ok(crate::fees::Quote {
            payment: kind.name(),
            fee_address: payer.to_string(),
            public_balance: balance,
            refundable_staging_rent: rent,
            permanent_nullifier_rent: markers,
            transaction_fees: normal_fees,
            upload_repair_reserve,
            cleanup_reserve: reserve,
            maximum_gross_debit: maximum,
            minimum_remaining_balance: remaining,
            funding_required: required,
            funding_shortfall: required.saturating_sub(balance),
        })
    }

    pub(super) fn charge_sponsor(&self, tx: &Transaction, native_debit: u64) -> Result<()> {
        let fee = if self.sponsor_budget.is_some() || self.user_fees.is_some() {
            self.transaction_fee(tx)?
        } else {
            0
        };
        self.charge_quoted(tx, native_debit, fee)
    }

    // Private entry point: fee comes from this exact serialized message's read,
    // never from the caller, a shape estimate or a persisted fee cache.
    pub(super) fn charge_quoted(
        &self,
        tx: &Transaction,
        native_debit: u64,
        fee: u64,
    ) -> Result<()> {
        if self.user_fees.is_some() && self.sponsor_budget.is_some() {
            return Err("fee modes cannot be combined".into());
        }
        if self.sponsor_budget.is_some() || self.user_fees.is_some() {
            let debit = fee.checked_add(native_debit).ok_or("fee debit overflow")?;
            if let Some(budget) = &self.sponsor_budget {
                budget.charge(debit)?;
            }
            if let Some((payer, maximum, path)) = &self.user_fees {
                let mut record: StagingRecovery =
                    serde_json::from_slice(&read_private(path, 4096)?)?;
                if record.network != self.network
                    || record.sponsor != payer.to_string()
                    || record.sponsor_request_id.is_some()
                    || tx.message.account_keys.first() != Some(payer)
                {
                    return Err("user fee journal or signing authority mismatch".into());
                }
                let authorization = record
                    .user_fee
                    .as_mut()
                    .ok_or("missing original user fee authorization")?;
                if authorization.maximum != *maximum {
                    return Err("user fee limit cannot change during recovery".into());
                }
                let cleanup = tx.message.instructions.len() == 1
                    && tx.message.instructions[0].data == [4]
                    && tx
                        .message
                        .account_keys
                        .get(tx.message.instructions[0].program_id_index as usize)
                        == Some(&id());
                authorization.charge(debit, cleanup)?;
                crate::sponsor::replace(path, &serde_json::to_vec_pretty(&record)?)?;
            }
        }
        Ok(())
    }
}
