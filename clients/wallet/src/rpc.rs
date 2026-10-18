use crate::{
    archive::{Archive, HistoryBlock, Writer},
    cache::{self, Checkpoint},
    history::{HistoryInstruction, Replay, WalletState},
    keys::{read_private, write_private_new, Network, WalletKey},
    operation::WalletOperation,
    Result,
};
use base64::Engine;
use native_payment_program::{
    id, instructions, pool_address,
    staging::{Buffer, ACCOUNT_BYTES},
};
use native_payments::{staging::payload_digest, state::PoolState, wire};
use serde::{Deserialize, Serialize};
use solana_account::Account;
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::{
    http_sender::HttpSender,
    rpc_client::{RpcClient, RpcClientConfig},
};
use solana_rpc_client_api::config::{
    RpcAccountInfoConfig, RpcBlockConfig, RpcSendTransactionConfig,
};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction as system;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, TransactionDetails, UiTransactionEncoding,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

pub struct Chain {
    pub(crate) rpc: RpcClient,
    network: Network,
    sponsor_budget: Option<crate::sponsor::Budget>,
    user_fees: Option<(Pubkey, u64, std::path::PathBuf)>,
}

pub struct Synced {
    pub state: WalletState,
    pub slot: u64,
    pub block_height: u64,
    accepted_finalizations: BTreeSet<String>,
    withdrawals: BTreeMap<String, crate::payments::WithdrawalReceipt>,
    pub scan: ScanStats,
}

#[derive(Clone, Default, Serialize)]
pub struct ScanStats {
    pub cache_used: bool,
    pub cache_saved: bool,
    pub blocks_fetched: usize,
    pub payments_verified: usize,
    pub from_slot: u64,
    pub cache_reset: Option<String>,
    pub history_blocks_read: usize,
}

struct ScanResult {
    replay: Replay,
    secondary: Vec<WalletState>,
    slot: u64,
    block_hash: Option<String>,
    block_height: u64,
    accepted: BTreeSet<String>,
    withdrawals: BTreeMap<String, crate::payments::WithdrawalReceipt>,
    scan: ScanStats,
}

impl ScanResult {
    fn apply_block(&mut self, mut block: HistoryBlock) -> Result<HistoryBlock> {
        if block.slot <= self.slot
            || block.parent_slot != self.slot
            || self
                .block_hash
                .as_ref()
                .is_some_and(|hash| hash != &block.previous_blockhash)
            || !crate::archive::valid_hash(&block.blockhash)
            || !crate::archive::valid_hash(&block.previous_blockhash)
        {
            return Err("finalized block history is incomplete or discontinuous; an archive RPC or recovery history is required".into());
        }
        let mut retained = Vec::new();
        for encoded in block.transactions.drain(..) {
            let tx = encoded
                .transaction
                .decode()
                .ok_or("cannot decode archived transaction")?;
            let mut keys = tx.message.static_account_keys().to_vec();
            if tx
                .message
                .address_table_lookups()
                .is_some_and(|lookups| !lookups.is_empty())
            {
                let meta = encoded
                    .meta
                    .as_ref()
                    .ok_or("versioned transaction metadata is unavailable")?;
                let OptionSerializer::Some(loaded) = &meta.loaded_addresses else {
                    return Err("loaded account addresses are unavailable".into());
                };
                for address in loaded.writable.iter().chain(&loaded.readonly) {
                    keys.push(Pubkey::from_str(address)?);
                }
            }
            if !tx
                .message
                .instructions()
                .iter()
                .any(|ix| keys.get(ix.program_id_index as usize) == Some(&id()))
            {
                continue;
            }
            let meta = encoded
                .meta
                .as_ref()
                .ok_or("native payment execution metadata is unavailable")?;
            if meta.err.is_some() {
                continue;
            }
            tx.verify_and_hash_message()?;
            for ix in tx.message.instructions() {
                if keys.get(ix.program_id_index as usize) != Some(&id()) {
                    continue;
                }
                let accounts = ix
                    .accounts
                    .iter()
                    .map(|index| {
                        let index = *index as usize;
                        Ok((
                            *keys.get(index).ok_or("invalid archived account index")?,
                            tx.message.is_signer(index),
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let instruction = HistoryInstruction {
                    accounts,
                    data: ix.data.clone(),
                };
                if let Some(accepted) = self.replay.apply_verified(&instruction, block.slot)? {
                    if let Some(withdrawal) = accepted.withdrawal() {
                        self.withdrawals
                            .insert(tx.signatures[0].to_string(), withdrawal);
                    }
                    self.scan.payments_verified += 1;
                    for state in &mut self.secondary {
                        accepted.apply(state)?;
                    }
                }
                if ix.data.first() == Some(&3) {
                    self.accepted.insert(tx.signatures[0].to_string());
                }
            }
            retained.push(encoded);
        }
        block.transactions = retained;
        self.slot = block.slot;
        self.block_hash = Some(block.blockhash.clone());
        self.block_height = block.block_height;
        Ok(block)
    }

    fn finish(self) -> Vec<Synced> {
        let mut states = self.secondary;
        states.insert(0, self.replay.state);
        states
            .into_iter()
            .map(|state| Synced {
                state,
                slot: self.slot,
                block_height: self.block_height,
                accepted_finalizations: self.accepted.clone(),
                withdrawals: self.withdrawals.clone(),
                scan: self.scan.clone(),
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    network: Network,
    signature: String,
    staging_account: String,
    last_valid_block_height: u64,
    #[serde(default)]
    withdrawal: Option<crate::payments::WithdrawalReceipt>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingRecovery {
    network: Network,
    sponsor: String,
    staging_account: String,
    initialize_signature: String,
    last_valid_block_height: u64,
    expiry: u64,
    payload_len: u32,
    payload_digest: [u8; 32],
    #[serde(default)]
    sponsor_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_fee: Option<crate::fees::Authorization>,
}

#[derive(Serialize)]
pub struct Submitted {
    pub signature: String,
    pub staging_account: String,
    pub staging_rent_reclaimed: bool,
    pub upload_transactions: usize,
    pub upload_ms: u128,
    pub finalization_ms: u128,
    pub withdrawal: Option<crate::payments::WithdrawalReceipt>,
    pub user_fee_charged: Option<u64>,
}

impl Chain {
    pub fn connect(url: &str, network: Network) -> Result<Self> {
        let endpoint = crate::connection::Endpoint {
            transport: "loopback-http".into(),
            url: url.into(),
        };
        endpoint.validate()?;
        Self::connect_endpoint(url, network)
    }

    pub fn connect_profile(profile: &crate::connection::TesterProfile) -> Result<Self> {
        profile.validate()?;
        Self::connect_endpoint(&profile.rpc.url, profile.network())
    }

    pub fn connect_invited(
        profile: &crate::connection::TesterProfile,
        wallet: &WalletKey,
    ) -> Result<Self> {
        profile.validate()?;
        let proof = crate::access::Proof::signed(wallet, &profile.rpc.url, "rpc", b"")?;
        Self::connect_authenticated(&profile.rpc.url, profile.network(), Some(proof.header()?))
    }
    fn connect_endpoint(url: &str, network: Network) -> Result<Self> {
        Self::connect_authenticated(url, network, None)
    }
    fn connect_authenticated(url: &str, network: Network, access: Option<String>) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(proof) = access {
            headers.insert("X-Testnet-Access", proof.parse()?);
        }
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        let rpc = RpcClient::new_sender(
            HttpSender::new_with_client(url, http),
            RpcClientConfig::with_commitment(CommitmentConfig::finalized()),
        );
        if rpc.get_genesis_hash()?.to_string() != network.genesis_hash {
            return Err("RPC genesis does not match the wallet network".into());
        }
        Ok(Self {
            rpc,
            network,
            sponsor_budget: None,
            user_fees: None,
        })
    }

    /// Read-only diagnosis without decrypting a seed or sending a transaction.
    pub fn health(&self) -> Result<serde_json::Value> {
        let response = self
            .rpc
            .get_account_with_commitment(&pool_address(), CommitmentConfig::finalized())?;
        let account = response.value.ok_or("native pool is missing")?;
        let pool = PoolState::decode(&account.data)?;
        if account.owner != id()
            || pool.network != self.network.network
            || account.lamports
                < pool
                    .rent_floor
                    .checked_add(pool.backing)
                    .ok_or("pool backing overflow")?
        {
            return Err("native pool owner, domain or backing mismatch".into());
        }
        self.check_withdrawal_activation()?;
        Ok(
            serde_json::json!({"connected":true, "genesis_hash":self.network.genesis_hash,
            "finalized_slot":response.context.slot, "pool_format":"NPOOL003", "recipient_withdrawals":true}),
        )
    }

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

    fn check_withdrawal_activation(&self) -> Result<()> {
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

    fn payment_fee_quote(
        &self,
        payer: Pubkey,
        kind: crate::fees::PaymentKind,
    ) -> Result<crate::fees::Quote> {
        self.minimum_withdrawal(payer)?; // An ordinary public account must pay the fees.
        let bytes = vec![0; kind.payload_len()]; // Exact two-action shape; no proof or private recipient is sent.
        let buffer = Pubkey::new_unique();
        let rent = self
            .rpc
            .get_minimum_balance_for_rent_exemption(ACCOUNT_BYTES)?;
        let markers = self
            .rpc
            .get_minimum_balance_for_rent_exemption(
                native_payment_program::nullifiers::MARKER_BYTES,
            )?
            .checked_mul(2)
            .ok_or("rent overflow")?;
        let hash = self
            .rpc
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())?
            .0;
        let mut batches = vec![vec![
            system::create_account(&payer, &buffer, rent, ACCOUNT_BYTES as u64, &id()),
            instructions::initialize(buffer, payer, bytes.len() as u32, payload_digest(&bytes), 1),
            crate::upload::first_write(buffer, payer, &bytes),
        ]];
        batches.extend(crate::upload::remaining(buffer, payer, &bytes));
        batches.push(vec![
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            match kind {
                crate::fees::PaymentKind::Send => {
                    instructions::finalize(buffer, payer, [[1; 32], [2; 32]])
                }
                crate::fees::PaymentKind::Withdraw(recipient) => {
                    instructions::finalize_to(buffer, payer, [[1; 32], [2; 32]], recipient)
                }
            },
        ]);
        let fee = |ix: &[Instruction]| -> Result<u64> {
            let mut tx = Transaction::new_with_payer(ix, Some(&payer));
            tx.message.recent_blockhash = hash;
            self.transaction_fee(&tx)
        };
        let normal_fees = batches.iter().try_fold(0u64, |sum, batch| -> Result<u64> {
            sum.checked_add(fee(batch)?)
                .ok_or_else(|| "fee overflow".into())
        })?;
        let close_fee = fee(&[instructions::close(buffer, payer)])?;
        let reserve = close_fee
            .checked_mul(2)
            .filter(|v| *v > 0)
            .ok_or("invalid cleanup fee")?;
        let maximum = rent
            .checked_add(markers)
            .and_then(|n| n.checked_add(normal_fees))
            .and_then(|n| n.checked_add(reserve))
            .ok_or("fee quote overflow")?;
        let remaining = self.rpc.get_minimum_balance_for_rent_exemption(0)?;
        let balance = self.public_balance(payer)?;
        let required = maximum.checked_add(remaining).ok_or("fee quote overflow")?;
        Ok(crate::fees::Quote {
            payment: kind.name(),
            fee_address: payer.to_string(),
            public_balance: balance,
            refundable_staging_rent: rent,
            permanent_nullifier_rent: markers,
            transaction_fees: normal_fees.checked_add(close_fee).ok_or("fee overflow")?,
            cleanup_reserve: reserve,
            maximum_gross_debit: maximum,
            minimum_remaining_balance: remaining,
            funding_required: required,
            funding_shortfall: required.saturating_sub(balance),
        })
    }

    fn charge_sponsor(&self, tx: &Transaction, native_debit: u64) -> Result<()> {
        if self.user_fees.is_some() && self.sponsor_budget.is_some() {
            return Err("fee modes cannot be combined".into());
        }
        if self.sponsor_budget.is_some() || self.user_fees.is_some() {
            let debit = self
                .transaction_fee(tx)?
                .checked_add(native_debit)
                .ok_or("fee debit overflow")?;
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

    pub fn sync(&self, wallet: &WalletKey) -> Result<Synced> {
        self.sync_many(&[wallet])?
            .pop()
            .ok_or_else(|| "missing synchronized wallet".into())
    }

    /// Scan the authenticated archive once for a bounded set of local wallets.
    pub fn sync_many(&self, wallets: &[&WalletKey]) -> Result<Vec<Synced>> {
        Ok(self.scan(wallets, None)?.finish())
    }

    /// The operation guard serializes cache replacement with wallet submissions.
    pub fn sync_cached(&self, wallet: &WalletKey, operation: &WalletOperation) -> Result<Synced> {
        self.sync_cached_source(wallet, operation, None)
    }

    pub fn sync_cached_with_history(
        &self,
        wallet: &WalletKey,
        operation: &WalletOperation,
        path: &Path,
    ) -> Result<Synced> {
        let history = Archive::open(path, &self.network)?;
        self.sync_cached_source(wallet, operation, Some(&history))
    }

    /// This public-data collector needs no wallet seed or sponsor key.
    pub fn export_history(&self, path: &Path) -> Result<serde_json::Value> {
        let mut writer = Writer::open(path, &self.network)?;
        let prior = writer.archive.clone();
        let view = WalletKey::generate(self.network.clone())?;
        let result = self.scan_source(&[&view], None, Some(&prior), Some(&mut writer))?;
        let bytes = writer.commit()?;
        Ok(
            serde_json::json!({"manifest_committed":true,"from_slot":prior.tip().saturating_add(1),
            "finalized_slot":result.slot,"new_blocks":result.scan.blocks_fetched,
            "retained_blocks_verified":result.scan.history_blocks_read,
            "payments_verified":result.scan.payments_verified,"bytes_written":bytes}),
        )
    }

    fn sync_cached_source(
        &self,
        wallet: &WalletKey,
        operation: &WalletOperation,
        history: Option<&Archive>,
    ) -> Result<Synced> {
        let (candidate, discarded) = if operation.scan_cache.exists() {
            match cache::read(&operation.scan_cache, wallet) {
                Ok(checkpoint) => (Some(checkpoint), false),
                Err(_) => (None, true),
            }
        } else {
            (None, false)
        };
        let mut result = self.scan_source(&[wallet], candidate, history, None)?;
        if discarded {
            result.scan.cache_reset = Some("invalid_cache".into());
        }
        let checkpoint = Checkpoint {
            network: wallet.network.clone(),
            address: wallet.address_text(),
            slot: result.slot,
            block_hash: result.block_hash.clone(),
            block_height: result.block_height,
            accepted: result.accepted.clone(),
            replay: result.replay.snapshot(),
        };
        // A cache is optional. Its write failure must not invalidate verified
        // state or encourage retrying a value-changing operation.
        result.scan.cache_saved = cache::write(&operation.scan_cache, wallet, &checkpoint).is_ok();
        result
            .finish()
            .pop()
            .ok_or_else(|| "missing synchronized wallet".into())
    }

    fn scan(&self, wallets: &[&WalletKey], candidate: Option<Checkpoint>) -> Result<ScanResult> {
        self.scan_source(wallets, candidate, None, None)
    }

    fn scan_source(
        &self,
        wallets: &[&WalletKey],
        candidate: Option<Checkpoint>,
        history: Option<&Archive>,
        mut writer: Option<&mut Writer>,
    ) -> Result<ScanResult> {
        if wallets.is_empty()
            || wallets.len() > 64
            || wallets.iter().any(|wallet| wallet.network != self.network)
        {
            return Err("expected 1..64 wallets on this network".into());
        }
        let response = self
            .rpc
            .get_account_with_commitment(&pool_address(), CommitmentConfig::finalized())?;
        let account = response.value.ok_or("native pool is missing")?;
        if account.owner != id() {
            return Err("native pool owner mismatch".into());
        }
        let pool = PoolState::decode(&account.data)?;
        if pool.network != self.network.network
            || account.lamports
                < pool
                    .rent_floor
                    .checked_add(pool.backing)
                    .ok_or("pool balance overflow")?
        {
            return Err("native pool network or backing mismatch".into());
        }
        let target = response.context.slot;
        if writer.is_some() && history.is_some_and(|history| history.tip() > target) {
            return Err("RPC is behind retained history; refusing archive rollback".into());
        }
        // Batched full scans share one verifier key with the primary replay.
        let shared_key = (wallets.len() > 1).then(|| {
            std::sync::Arc::new(orchard::circuit::VerifyingKey::build(
                native_payments::verification::bundle_version().circuit_version(),
            ))
        });
        let mut stats = ScanStats::default();
        let mut cached = None;
        if let Some(checkpoint) = candidate {
            if checkpoint.slot > target {
                return Err("RPC finalized state is behind the verified wallet checkpoint; wait or use an up-to-date RPC".into());
            }
            let canonical = if checkpoint.slot == 0 {
                true
            } else {
                self.rpc
                    .get_block_with_config(
                        checkpoint.slot,
                        RpcBlockConfig {
                            transaction_details: Some(TransactionDetails::None),
                            rewards: Some(false),
                            commitment: Some(CommitmentConfig::finalized()),
                            ..Default::default()
                        },
                    )
                    .is_ok_and(|block| Some(block.blockhash) == checkpoint.block_hash)
            };
            if canonical {
                match Replay::restore(wallets[0], checkpoint.replay) {
                    Ok(replay) => {
                        cached = Some((
                            replay,
                            checkpoint.slot,
                            checkpoint.block_hash,
                            checkpoint.block_height,
                            checkpoint.accepted,
                        ));
                        stats.cache_used = true;
                    }
                    Err(_) => stats.cache_reset = Some("invalid_cached_state".into()),
                }
            } else {
                stats.cache_reset = Some("checkpoint_unavailable_or_changed".into());
            }
        }
        let (replay, previous_slot, previous_hash, block_height, accepted_finalizations) =
            if let Some(cached) = cached {
                cached
            } else {
                (
                    if let Some(key) = &shared_key {
                        Replay::from_state(WalletState::with_key(
                            wallets[0],
                            pool.rent_floor,
                            key.clone(),
                        )?)
                    } else {
                        Replay::new(wallets[0], pool.rent_floor)?
                    },
                    0,
                    None,
                    0,
                    BTreeSet::new(),
                )
            };
        let states = if let Some(key) = shared_key {
            wallets
                .iter()
                .skip(1)
                .map(|wallet| WalletState::with_key(wallet, pool.rent_floor, key.clone()))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let start = if stats.cache_used {
            previous_slot.checked_add(1).ok_or("cached slot overflow")?
        } else {
            0
        };
        stats.from_slot = start;
        let mut result = ScanResult {
            replay,
            secondary: states,
            slot: previous_slot,
            block_hash: previous_hash,
            block_height,
            accepted: accepted_finalizations,
            withdrawals: BTreeMap::new(),
            scan: stats,
        };
        if let Some(history) = history {
            for block in history.reader() {
                let block = block?;
                if block.slot > target {
                    break;
                }
                if block.slot <= result.slot {
                    continue;
                }
                result.scan.history_blocks_read += 1;
                result.apply_block(block)?;
            }
        }
        let mut start = result.slot.checked_add(1).ok_or("history slot overflow")?;
        while start <= target {
            let end = start.saturating_add(9999).min(target);
            let blocks = self.rpc.get_blocks(start, Some(end))?;
            for slot in blocks.into_iter().filter(|slot| *slot != 0) {
                result.scan.blocks_fetched += 1;
                let block = self.rpc.get_block_with_config(slot, RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Base64), transaction_details: Some(TransactionDetails::Full),
                    rewards: Some(false), commitment: Some(CommitmentConfig::finalized()), max_supported_transaction_version: Some(0),
                }).map_err(|error| format!("cannot read finalized block {slot}; complete archive history or retained recovery history is required: {error}"))?;
                let compact = result.apply_block(HistoryBlock::from_rpc(slot, block)?)?;
                if let Some(writer) = &mut writer {
                    writer.push(compact)?;
                }
            }
            if end == target {
                break;
            }
            start = end + 1;
        }
        if result.slot != target {
            return Err(
                "finalized history does not reach the pool checkpoint; archive history is required"
                    .into(),
            );
        }
        if history.is_some() && target != 0 {
            let header = self.rpc.get_block_with_config(target, RpcBlockConfig {
                transaction_details:Some(TransactionDetails::None), rewards:Some(false),
                commitment:Some(CommitmentConfig::finalized()), ..Default::default()
            }).map_err(|error| format!("cannot authenticate retained history against finalized RPC header: {error}"))?;
            if result.block_hash.as_ref() != Some(&header.blockhash) {
                return Err("retained history does not match the finalized RPC block hash".into());
            }
            result.block_height = header
                .block_height
                .ok_or("finalized RPC block height is unavailable")?;
        }
        result.replay.state.reconcile(&pool)?;
        for state in &result.secondary {
            state.reconcile(&pool)?;
        }
        // Retained proof effects reconstruct state, but retained metadata is
        // never evidence that a particular outer transaction was canonical.
        if history.is_some() {
            result.accepted.clear();
            result.withdrawals.clear();
        }
        Ok(result)
    }

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
        let synced = self.sync(wallet)?;
        let accepted = synced.accepted_finalizations.contains(&pending.signature);
        let withdrawal = synced.withdrawals.get(&pending.signature).cloned();
        if accepted
            && pending
                .withdrawal
                .as_ref()
                .is_some_and(|intent| Some(intent) != withdrawal.as_ref())
        {
            return Err("canonical withdrawal differs from the saved recipient/amount/sponsor intent; pending record retained".into());
        }
        let statuses = self.rpc.get_signature_statuses_with_history(&[signature])?;
        let failed = statuses
            .value
            .first()
            .and_then(Option::as_ref)
            .is_some_and(|status| {
                status.satisfies_commitment(CommitmentConfig::finalized()) && status.err.is_some()
            });
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
            "staging_recovery_required":operation.staging.exists(),"withdrawal":withdrawal}),
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
        if current.owner != id()
            || !PoolState::decode(&current.data)?
                .roots()
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
        let upload_transactions = 1 + batches.len();
        for batch in batches {
            self.send(sponsor, &batch, &[])?;
        }
        let upload_ms = upload_started.elapsed().as_millis();
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
        let finalization = [
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            match payment.context.withdrawal_recipient {
                Some(recipient) => instructions::finalize_to(
                    buffer.pubkey(),
                    sponsor.pubkey(),
                    nullifiers,
                    Pubkey::new_from_array(recipient),
                ),
                None => instructions::finalize(buffer.pubkey(), sponsor.pubkey(), nullifiers),
            },
        ];
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
        let marker_rent = self.rpc.get_minimum_balance_for_rent_exemption(
            native_payment_program::nullifiers::MARKER_BYTES,
        )?;
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
        // Finalization is already durable. Failure to reclaim staging rent must
        // not report a failed payment or encourage an unsafe fresh deposit retry.
        let reclaimed = self
            .send(
                sponsor,
                &[instructions::close(buffer.pubkey(), sponsor.pubkey())],
                &[],
            )
            .and_then(|signature| self.wait_closed(&buffer.pubkey(), &signature))
            .is_ok();
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
            upload_ms,
            finalization_ms,
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

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use serde_json::json;
    use solana_rpc_client::mock_sender::MocksMap;
    use solana_rpc_client_api::request::RpcRequest;

    #[test]
    fn sponsor_checks_rpc_fee_plus_native_debit_before_broadcast() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy");
        let payer = Keypair::new();
        let network = Network {
            network: [3; 32],
            genesis_hash: bs58::encode([4; 32]).into_string(),
        };
        crate::sponsor::Policy {
            format: "native-sponsor-policy-v1".into(),
            network: network.clone(),
            sponsor: payer.pubkey().to_string(),
            operation_allowance: 10,
            lifetime_allowance: 10,
            max_deposit: 100,
            max_send: 100,
            max_withdraw: None,
            max_requests_per_wallet: 1,
        }
        .create(&path)
        .unwrap();
        let budget = crate::sponsor::Budget::reserve(
            &path,
            &network,
            &payer.pubkey(),
            "wallet",
            "deposit",
            1,
            "fee-test-request-0001",
        )
        .unwrap();
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map(
                "succeeds",
                MocksMap::from_iter(std::iter::repeat_n(
                    (
                        RpcRequest::GetFeeForMessage,
                        json!({"context":{"slot":1},"value":7}),
                    ),
                    3,
                )),
            ),
            network,
            sponsor_budget: Some(budget),
            user_fees: None,
        };
        let tx = Transaction::new_signed_with_payer(
            &[system::transfer(&payer.pubkey(), &Pubkey::new_unique(), 1)],
            Some(&payer.pubkey()),
            &[&payer],
            Default::default(),
        );
        assert!(chain.charge_sponsor(&tx, 4).is_err());
        chain.charge_sponsor(&tx, 3).unwrap();
        assert!(chain.charge_sponsor(&tx, 0).is_err());
        let ledger: serde_json::Value = serde_json::from_slice(
            &fs::read(root.path().join("policy.reservations.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(ledger["requests"][0]["charged"], 10);
    }

    fn cached_fixture(
        target: u64,
        blocks: Vec<serde_json::Value>,
        slots: Vec<u64>,
    ) -> (WalletKey, Checkpoint, Chain) {
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let wallet = WalletKey::generate(network.clone()).unwrap();
        let replay = Replay::new(&wallet, 1000).unwrap();
        let pool = replay.state.pool.encode();
        let checkpoint = Checkpoint {
            network: network.clone(),
            address: wallet.address_text(),
            slot: 4,
            block_hash: Some(bs58::encode([4; 32]).into_string()),
            block_height: 4,
            accepted: BTreeSet::new(),
            replay: replay.snapshot(),
        };
        let mut mocks = MocksMap::from_iter([
            (
                RpcRequest::GetAccountInfo,
                json!({"context":{"slot":target},"value":{
                "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                "data":[bs58::encode(pool).into_string(),"base58"]}}),
            ),
            (RpcRequest::GetBlocks, json!(slots)),
        ]);
        for block in blocks {
            mocks.insert(RpcRequest::GetBlock, block);
        }
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
            sponsor_budget: None,
            user_fees: None,
            network,
        };
        (wallet, checkpoint, chain)
    }

    fn block(slot: u64, parent: u64) -> serde_json::Value {
        json!({"blockhash":bs58::encode([slot as u8;32]).into_string(),
            "previousBlockhash":bs58::encode([parent as u8;32]).into_string(),
            "parentSlot":parent,"blockHeight":slot,"blockTime":null,"transactions":[],"rewards":[]})
    }

    #[test]
    fn retained_prefix_and_rpc_tail_must_reconcile_with_the_live_finalized_header() {
        for valid in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("history");
            let (wallet, _, chain) = cached_fixture(
                6,
                vec![block(6, 2), block(if valid { 6 } else { 7 }, 2)],
                vec![6],
            );
            let mut writer = Writer::open(&path, &wallet.network).unwrap();
            writer
                .push(
                    HistoryBlock::from_rpc(2, serde_json::from_value(block(2, 0)).unwrap())
                        .unwrap(),
                )
                .unwrap();
            writer.commit().unwrap();
            let history = Archive::open(&path, &wallet.network).unwrap();
            let result = chain.scan_source(&[&wallet], None, Some(&history), None);
            if valid {
                let result = result.unwrap();
                assert_eq!(result.scan.history_blocks_read, 1);
                assert_eq!(result.scan.blocks_fetched, 1);
                assert_eq!(result.replay.state.balance().unwrap(), 0);
            } else {
                assert!(result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("finalized RPC block hash"));
            }
        }
        for cached in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("history");
            let headers = if cached {
                vec![block(4, 0), block(4, 0)]
            } else {
                vec![block(4, 0)]
            };
            let (wallet, mut checkpoint, chain) = cached_fixture(4, headers, vec![]);
            checkpoint
                .accepted
                .insert("metadata-is-not-canonical-inclusion".into());
            let mut writer = Writer::open(&path, &wallet.network).unwrap();
            let mut archived =
                HistoryBlock::from_rpc(4, serde_json::from_value(block(4, 0)).unwrap()).unwrap();
            archived.block_height = u64::MAX;
            writer.push(archived).unwrap();
            writer.commit().unwrap();
            let history = Archive::open(&path, &wallet.network).unwrap();
            let result = chain
                .scan_source(
                    &[&wallet],
                    cached.then_some(checkpoint),
                    Some(&history),
                    None,
                )
                .unwrap();
            assert_eq!(
                result.block_height, 4,
                "use finalized RPC height, not retained metadata"
            );
            assert!(
                result.accepted.is_empty(),
                "never expose retained identities as canonical inclusion"
            );
        }
    }

    #[test]
    fn public_history_export_extends_immutable_prefix_and_refuses_rpc_rollback() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        let (_, _, chain) =
            cached_fixture(6, vec![block(2, 0), block(6, 2), block(6, 2)], vec![2, 6]);
        let first = chain.export_history(&path).unwrap();
        assert_eq!(first["new_blocks"], 2);
        let (_, _, next) = cached_fixture(8, vec![block(8, 6), block(8, 6)], vec![8]);
        let second = next.export_history(&path).unwrap();
        assert_eq!(second["new_blocks"], 1);
        assert_eq!(second["retained_blocks_verified"], 2);
        let before = fs::read(path.join("manifest.json")).unwrap();
        let (_, _, behind) = cached_fixture(7, vec![], vec![]);
        assert!(behind
            .export_history(&path)
            .unwrap_err()
            .to_string()
            .contains("refusing archive rollback"));
        assert_eq!(fs::read(path.join("manifest.json")).unwrap(), before);
    }

    #[test]
    fn incremental_scan_checks_canonical_checkpoint_and_extension_continuity() {
        let (wallet, checkpoint, chain) =
            cached_fixture(6, vec![block(4, 3), block(6, 4)], vec![6]);
        let result = chain.scan(&[&wallet], Some(checkpoint)).unwrap();
        assert!(result.scan.cache_used);
        assert_eq!(result.scan.from_slot, 5);
        assert_eq!(result.scan.blocks_fetched, 1);
        assert_eq!(result.scan.payments_verified, 0);
        for parent in [0, 5] {
            let (wallet, checkpoint, chain) =
                cached_fixture(6, vec![block(4, 3), block(6, parent)], vec![6]);
            assert!(chain
                .scan(&[&wallet], Some(checkpoint))
                .err()
                .unwrap()
                .to_string()
                .contains("discontinuous"));
        }
    }

    #[test]
    fn lagging_rpc_and_missing_archive_cannot_authorize_cached_balance() {
        let (wallet, checkpoint, chain) = cached_fixture(3, vec![], vec![]);
        assert!(chain
            .scan(&[&wallet], Some(checkpoint))
            .err()
            .unwrap()
            .to_string()
            .contains("behind the verified"));
        let (wallet, checkpoint, chain) =
            cached_fixture(6, vec![serde_json::Value::Null, block(6, 4)], vec![6]);
        assert!(chain
            .scan(&[&wallet], Some(checkpoint))
            .err()
            .unwrap()
            .to_string()
            .contains("discontinuous"));
        let (wallet, checkpoint, chain) = cached_fixture(6, vec![block(4, 3)], vec![]);
        assert!(chain
            .scan(&[&wallet], Some(checkpoint))
            .err()
            .unwrap()
            .to_string()
            .contains("does not reach"));
    }

    #[test]
    fn changed_checkpoint_requires_complete_rescan_before_cache_replacement() {
        let (wallet, checkpoint, chain) =
            cached_fixture(6, vec![block(5, 3), block(2, 0), block(6, 2)], vec![2, 6]);
        let result = chain.scan(&[&wallet], Some(checkpoint)).unwrap();
        assert!(!result.scan.cache_used);
        assert_eq!(
            result.scan.cache_reset.as_deref(),
            Some("checkpoint_unavailable_or_changed")
        );
        assert_eq!(result.scan.from_slot, 0);
        assert_eq!(result.scan.blocks_fetched, 2);
    }

    #[test]
    fn cache_storage_failure_does_not_discard_verified_state() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        fs::create_dir(&operation.scan_cache).unwrap();
        let (wallet, _, chain) = cached_fixture(0, vec![], vec![]);
        let synced = chain.sync_cached(&wallet, &operation).unwrap();
        assert_eq!(synced.state.balance().unwrap(), 0);
        assert!(!synced.scan.cache_saved);
        assert_eq!(synced.scan.cache_reset.as_deref(), Some("invalid_cache"));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }

    fn fixture(operation: &WalletOperation, sponsor: &Keypair, height: u64) -> Network {
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let recovery = StagingRecovery {
            network: network.clone(),
            sponsor: sponsor.pubkey().to_string(),
            staging_account: Pubkey::new_unique().to_string(),
            initialize_signature: Signature::from([3; 64]).to_string(),
            last_valid_block_height: height,
            expiry: 2000,
            payload_len: 10,
            payload_digest: [7; 32],
            sponsor_request_id: None,
            user_fee: None,
        };
        write_private_new(&operation.staging, &serde_json::to_vec(&recovery).unwrap()).unwrap();
        network
    }

    fn absent_chain(network: Network, slot: u64, url: &str) -> Chain {
        let response = json!({"context":{"slot":slot},"value":null});
        let mocks = MocksMap::from_iter([
            (RpcRequest::GetAccountInfo, response.clone()),
            (RpcRequest::GetAccountInfo, response),
        ]);
        Chain {
            rpc: RpcClient::new_mock_with_mocks_map(url, mocks),
            sponsor_budget: None,
            user_fees: None,
            network,
        }
    }

    #[test]
    fn user_fee_charges_are_durable_and_original_cap_survives_recovery() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let payer = Keypair::new();
        let network = fixture(&operation, &payer, 100);
        let mut record: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
        record.user_fee = Some(crate::fees::Authorization::new(100, 10).unwrap());
        crate::sponsor::replace(&operation.staging, &serde_json::to_vec(&record).unwrap()).unwrap();
        let mocks = MocksMap::from_iter(std::iter::repeat_n(
            (
                RpcRequest::GetFeeForMessage,
                json!({"context":{"slot":34},"value":7}),
            ),
            4,
        ));
        let chain = Chain {
            rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
            network: network.clone(),
            sponsor_budget: None,
            user_fees: Some((payer.pubkey(), 100, operation.staging.clone())),
        };
        let tx = Transaction::new_with_payer(
            &[instructions::seal(Pubkey::new_unique(), payer.pubkey())],
            Some(&payer.pubkey()),
        );
        chain.charge_sponsor(&tx, 80).unwrap();
        assert!(chain.charge_sponsor(&tx, 0).is_err());
        let restored: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
        assert_eq!(restored.user_fee.unwrap().charged, 87);
        assert_eq!(
            chain
                .recovery_user_limit(&operation, payer.pubkey())
                .unwrap(),
            Some(100)
        );
        assert!(chain
            .recovery_user_limit(&operation, Keypair::new().pubkey())
            .is_err());
        let close = Transaction::new_with_payer(
            &[instructions::close(Pubkey::new_unique(), payer.pubkey())],
            Some(&payer.pubkey()),
        );
        chain.charge_sponsor(&close, 0).unwrap();
        let restored: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
        assert_eq!(restored.user_fee.unwrap().charged, 94);
        let other = chain
            .with_user_fees(payer.pubkey(), 101, &operation)
            .unwrap();
        assert!(other.charge_sponsor(&close, 0).is_err());
    }

    #[test]
    fn user_paid_recovery_cannot_silently_bypass_its_recorded_cap() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let payer = Keypair::new();
        let network = fixture(&operation, &payer, 100);
        let mut record: StagingRecovery =
            serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
        record.user_fee = Some(crate::fees::Authorization::new(100, 10).unwrap());
        crate::sponsor::replace(&operation.staging, &serde_json::to_vec(&record).unwrap()).unwrap();
        let chain = Chain {
            rpc: RpcClient::new_mock("succeeds"),
            network,
            sponsor_budget: None,
            user_fees: None,
        };
        assert!(chain
            .reclaim(&payer, &operation)
            .unwrap_err()
            .to_string()
            .contains("original recorded fee mode"));
        assert!(operation.staging.exists());
    }

    #[test]
    fn absent_live_initialization_is_retained_until_finalized_expiry() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let sponsor = Keypair::new();
        let network = fixture(&operation, &sponsor, 100);
        let chain = absent_chain(network.clone(), 34, "sig_not_found");
        assert!(chain
            .reclaim(&sponsor, &operation)
            .unwrap_err()
            .to_string()
            .contains("still pending"));
        assert!(operation.staging.exists());
        let mut recovery: StagingRecovery =
            serde_json::from_slice(&fs::read(&operation.staging).unwrap()).unwrap();
        recovery.last_valid_block_height = 20; // A synthetic unit fixture, never broadcast.
        fs::write(&operation.staging, serde_json::to_vec(&recovery).unwrap()).unwrap();
        let cleared = absent_chain(network, 34, "sig_not_found")
            .reclaim(&sponsor, &operation)
            .unwrap();
        assert_eq!(cleared["recovery_cleared"], true);
        assert_eq!(cleared["rent_reclaimed"], false);
        assert!(!operation.staging.exists());
    }

    #[test]
    fn stale_absence_cannot_clear_an_expired_initialization() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let sponsor = Keypair::new();
        let network = fixture(&operation, &sponsor, 20);
        let error = absent_chain(network, 1, "sig_not_found")
            .reclaim(&sponsor, &operation)
            .unwrap_err();
        assert!(error.to_string().contains("checkpoint is older"));
        assert!(operation.staging.exists());
    }

    #[test]
    fn pending_payment_and_wrong_signer_block_reclamation() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let sponsor = Keypair::new();
        let network = fixture(&operation, &sponsor, 20);
        let chain = absent_chain(network, 34, "sig_not_found");
        write_private_new(&operation.pending, b"unresolved").unwrap();
        assert!(chain
            .reclaim(&sponsor, &operation)
            .unwrap_err()
            .to_string()
            .contains("unresolved payment"));
        fs::remove_file(&operation.pending).unwrap();
        assert!(chain
            .reclaim(&Keypair::new(), &operation)
            .unwrap_err()
            .to_string()
            .contains("sponsor mismatch"));
        assert!(operation.staging.exists());
    }
}
