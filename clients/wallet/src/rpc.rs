mod archival;
mod retained;
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
    history_batches: bool,
    verification_key: Option<std::sync::Arc<orchard::circuit::VerifyingKey>>,
}

pub struct Synced {
    pub state: WalletState,
    pub slot: u64,
    pub block_height: u64,
    accepted_finalizations: BTreeSet<String>,
    canonical_from_slot: u64,
    withdrawals: BTreeMap<String, crate::payments::WithdrawalReceipt>,
    finalizations: BTreeMap<String, (String, bool)>,
    pub scan: ScanStats,
}

#[derive(Clone, Default, Serialize)]
pub struct ScanStats {
    pub cache_used: bool,
    pub cache_saved: bool,
    pub blocks_fetched: usize,
    pub payments_verified: usize,
    pub block_rpc_requests: usize,
    pub retained_rpc_requests: usize,
    pub archival_rpc_requests: usize,
    pub fetch_ms: u128,
    pub replay_ms: u128,
    pub setup_ms: u128,
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
    canonical_from_slot: u64,
    withdrawals: BTreeMap<String, crate::payments::WithdrawalReceipt>,
    finalizations: BTreeMap<String, (String, bool)>,
    scan: ScanStats,
}

impl ScanResult {
    fn apply_block(&mut self, block: HistoryBlock) -> Result<HistoryBlock> {
        self.apply_source_block(block, true)
    }

    fn apply_retained_block(&mut self, block: HistoryBlock) -> Result<HistoryBlock> {
        self.canonical_from_slot = self.canonical_from_slot.max(block.slot.saturating_add(1));
        self.apply_source_block(block, false)
    }

    fn apply_source_block(
        &mut self,
        mut block: HistoryBlock,
        canonical: bool,
    ) -> Result<HistoryBlock> {
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
            tx.verify_and_hash_message()?;
            if canonical {
                for ix in tx.message.instructions() {
                    if keys.get(ix.program_id_index as usize) == Some(&id()) && ix.data == [3] {
                        let staging = ix.accounts.get(1).and_then(|i| keys.get(*i as usize));
                        // A failed malformed instruction can have too few
                        // accounts. It supplies no matching receipt, but must
                        // not prevent every wallet from scanning the chain.
                        if let Some(staging) = staging {
                            self.finalizations.insert(
                                tx.signatures[0].to_string(),
                                (staging.to_string(), meta.err.is_some()),
                            );
                        }
                    }
                }
            }
            if meta.err.is_some() {
                continue;
            }
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
                    if let Some(withdrawal) = accepted.withdrawal().filter(|_| canonical) {
                        self.withdrawals
                            .insert(tx.signatures[0].to_string(), withdrawal);
                    }
                    self.scan.payments_verified += 1;
                    for state in &mut self.secondary {
                        accepted.apply(state)?;
                    }
                }
                if canonical && ix.data.first() == Some(&3) {
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
                canonical_from_slot: self.canonical_from_slot,
                withdrawals: self.withdrawals.clone(),
                finalizations: self.finalizations.clone(),
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
    pub upload_failed_transactions: usize,
    pub upload_repair_transactions: usize,
    pub upload_ms: u128,
    pub finalization_ms: u128,
    pub confirmation_ms: u128,
    pub cleanup_ms: u128,
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
        Self::connect_authenticated(
            &profile.rpc.url,
            profile.network(),
            None,
            None,
            profile.local_tls_ca_pem.as_deref(),
        )
    }

    pub fn connect_invited(
        profile: &crate::connection::TesterProfile,
        wallet: &WalletKey,
    ) -> Result<Self> {
        profile.validate()?;
        let proof = crate::access::Proof::signed(wallet, &profile.rpc.url, "rpc", b"")?;
        Self::connect_authenticated(
            &profile.rpc.url,
            profile.network(),
            Some(proof.header()?),
            None,
            profile.local_tls_ca_pem.as_deref(),
        )
    }
    fn connect_endpoint(url: &str, network: Network) -> Result<Self> {
        Self::connect_authenticated(url, network, None, None, None)
    }
    pub fn connect_operator(url: &str, network: Network, credential: &Path) -> Result<Self> {
        crate::connection::Endpoint {
            transport: "loopback-http".into(),
            url: url.into(),
        }
        .validate()?;
        Self::connect_authenticated(
            url,
            network,
            None,
            Some(native_rpc_access::read_credential(credential)?),
            None,
        )
    }
    pub fn operator_client(url: &str, network: Network, credential: &Path) -> Result<RpcClient> {
        Ok(Self::connect_operator(url, network, credential)?.rpc)
    }
    fn connect_authenticated(
        url: &str,
        network: Network,
        access: Option<String>,
        operator: Option<native_rpc_access::Credential>,
        ca: Option<&str>,
    ) -> Result<Self> {
        let history_batches = access.is_some();
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(proof) = access {
            headers.insert("X-Testnet-Access", proof.parse()?);
        }
        if let Some(ref credential) = operator {
            headers.insert(native_rpc_access::HEADER, credential.token.parse()?);
        }
        let mut http = reqwest::Client::builder()
            .default_headers(headers)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15));
        if let Some(pem) = ca {
            http = http.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?);
        }
        if let Some(ref credential) = operator {
            let parsed = reqwest::Url::parse(url)?;
            if let Some(path) =
                credential.socket(parsed.port().ok_or("operator RPC port required")?)?
            {
                native_rpc_access::check_socket(path)?;
                http = http.unix_socket(path);
            }
        }
        let http = http.build()?;
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
            history_batches,
            verification_key: None,
        })
    }

    /// Reuse this process's public circuit key; history remains independently
    /// authenticated and every newly scanned payment is still verified.
    pub fn with_payment_prover(mut self, prover: &crate::payments::PaymentProver) -> Self {
        self.verification_key = Some(prover.verifying_key());
        self
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
        let uploads = crate::upload::remaining(buffer, payer, &bytes);
        batches.extend(uploads.clone());
        let mut finalization = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        finalization.extend(instructions::finalize_and_close(
            buffer,
            payer,
            [[1; 32], [2; 32]],
            match kind {
                crate::fees::PaymentKind::Send => None,
                crate::fees::PaymentKind::Withdraw(recipient) => Some(recipient),
            },
        ));
        batches.push(finalization);
        let fee = |ix: &[Instruction]| -> Result<u64> {
            let mut tx = Transaction::new_with_payer(ix, Some(&payer));
            tx.message.recent_blockhash = hash;
            self.transaction_fee(&tx)
        };
        // Reserve one complete ordered repair of the suffix, without assuming
        // burst ordering or refunding fees for failed staging transactions.
        // Reuse the exact same message's quote rather than repeating RPC reads.
        let mut normal_fees = 0u64;
        let mut upload_repair_reserve = 0u64;
        for (index, batch) in batches.iter().enumerate() {
            let quoted = fee(batch)?;
            normal_fees = normal_fees.checked_add(quoted).ok_or("fee overflow")?;
            if (1..=uploads.len()).contains(&index) {
                upload_repair_reserve = upload_repair_reserve
                    .checked_add(quoted)
                    .ok_or("repair fee overflow")?;
            }
        }
        let close_fee = fee(&[instructions::close(buffer, payer)])?;
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
        let remaining = self.rpc.get_minimum_balance_for_rent_exemption(0)?;
        let balance = self.public_balance(payer)?;
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
            canonical_from_slot: result.canonical_from_slot,
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

    fn fetch_history_blocks(&self, slots: &[u64]) -> Result<Vec<HistoryBlock>> {
        use solana_rpc_client_api::request::RpcRequest;
        use solana_transaction_status_client_types::UiConfirmedBlock;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Block {
            slot: u64,
            block: UiConfirmedBlock,
        }
        if slots.is_empty() || slots.len() > 16 {
            return Err("invalid history request size".into());
        }
        if self.history_batches {
            let blocks: Vec<Block> = self.rpc.send(RpcRequest::Custom { method: "getWalletHistoryBlocks" }, serde_json::json!([slots]))
                .map_err(|error| format!("cannot read complete finalized history batch; an updated invited gateway is required: {error}"))?;
            if blocks.len() != slots.len()
                || blocks
                    .iter()
                    .zip(slots)
                    .any(|(block, slot)| block.slot != *slot)
            {
                return Err(
                    "history batch omitted, reordered or substituted a requested block".into(),
                );
            }
            blocks
                .into_iter()
                .map(|block| HistoryBlock::from_rpc(block.slot, block.block))
                .collect()
        } else {
            slots.iter().map(|slot| {
                let block = self.rpc.get_block_with_config(*slot, RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Base64), transaction_details: Some(TransactionDetails::Full),
                    rewards: Some(false), commitment: Some(CommitmentConfig::finalized()), max_supported_transaction_version: Some(0),
                }).map_err(|error| format!("cannot read finalized block {slot}; complete archive history or retained recovery history is required: {error}"))?;
                HistoryBlock::from_rpc(*slot, block)
            }).collect()
        }
    }

    fn scan_source(
        &self,
        wallets: &[&WalletKey],
        candidate: Option<Checkpoint>,
        history: Option<&Archive>,
        writer: Option<&mut Writer>,
    ) -> Result<ScanResult> {
        self.scan_source_mode(wallets, candidate, history, writer, true)
    }

    fn scan_source_mode(
        &self,
        wallets: &[&WalletKey],
        candidate: Option<Checkpoint>,
        history: Option<&Archive>,
        mut writer: Option<&mut Writer>,
        allow_remote_retained: bool,
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
        let setup_started = Instant::now();
        // Batched full scans share one verifier key with the primary replay.
        let shared_key = self.verification_key.clone().or_else(|| {
            (wallets.len() > 1).then(|| {
                std::sync::Arc::new(orchard::circuit::VerifyingKey::build(
                    native_payments::verification::bundle_version().circuit_version(),
                ))
            })
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
                match Replay::restore_with_key(wallets[0], checkpoint.replay, shared_key.clone()) {
                    Ok(replay) => {
                        cached = Some((
                            replay,
                            checkpoint.slot,
                            checkpoint.block_hash,
                            checkpoint.block_height,
                            checkpoint.accepted,
                            checkpoint
                                .canonical_from_slot
                                .min(checkpoint.slot.saturating_add(1)),
                        ));
                        stats.cache_used = true;
                    }
                    Err(_) => stats.cache_reset = Some("invalid_cached_state".into()),
                }
            } else {
                stats.cache_reset = Some("checkpoint_unavailable_or_changed".into());
            }
        }
        let (
            replay,
            previous_slot,
            previous_hash,
            block_height,
            accepted_finalizations,
            canonical_from_slot,
        ) = if let Some(cached) = cached {
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
                0,
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
            canonical_from_slot,
            withdrawals: BTreeMap::new(),
            finalizations: BTreeMap::new(),
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
                result.apply_retained_block(block)?;
            }
        }
        result.scan.setup_ms = setup_started.elapsed().as_millis();
        // Only pending-outcome recovery requests a full canonical archive.
        // Ordinary balance restoration keeps its distinct retained provenance.
        let remote_archival =
            if !allow_remote_retained && self.history_batches && result.slot == 0 && target > 0 {
                self.scan_archival(&mut result, target)?
            } else {
                false
            };
        // A pinned checkpoint already supplies verified state. Read its recent
        // canonical suffix directly, including original pending-send receipts.
        let remote_retained = if allow_remote_retained
            && self.history_batches
            && history.is_none()
            && !result.scan.cache_used
            && result.slot < target
        {
            self.scan_retained(&mut result, target)?
        } else {
            false
        };
        let mut start = result.slot.checked_add(1).ok_or("history slot overflow")?;
        while start <= target {
            let end = start.saturating_add(9999).min(target);
            let blocks: Vec<_> = self
                .rpc
                .get_blocks(start, Some(end))?
                .into_iter()
                .filter(|slot| *slot != 0)
                .collect();
            if blocks.iter().any(|slot| *slot < start || *slot > end)
                || blocks.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err("invalid finalized block range".into());
            }
            for slots in blocks.chunks(if self.history_batches { 16 } else { 1 }) {
                let fetched_at = Instant::now();
                let batch = self.fetch_history_blocks(slots)?;
                result.scan.fetch_ms += fetched_at.elapsed().as_millis();
                result.scan.block_rpc_requests += 1;
                for block in batch {
                    result.scan.blocks_fetched += 1;
                    let replay_at = Instant::now();
                    let compact = result.apply_block(block)?;
                    result.scan.replay_ms += replay_at.elapsed().as_millis();
                    if let Some(writer) = &mut writer {
                        writer.push(compact)?;
                    }
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
        if (history.is_some() || remote_retained || remote_archival) && target != 0 {
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
            result.finalizations.clear();
            result.canonical_from_slot = result
                .canonical_from_slot
                .max(history.unwrap().tip().min(target).saturating_add(1));
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

    fn send_upload(&self, tx: &Transaction) -> Result<Signature> {
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
        self.charge_sponsor(tx, 0)?;
        Ok(self.rpc.send_transaction_with_config(
            tx,
            RpcSendTransactionConfig {
                skip_preflight: true,
                preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                max_retries: Some(3),
                ..Default::default()
            },
        )?)
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
        let mut upload_transactions = 1 + batches.len();
        let mut signatures = Vec::with_capacity(batches.len());
        for batch in batches {
            let tx = Transaction::new_signed_with_payer(
                &batch,
                Some(&sponsor.pubkey()),
                &[sponsor],
                blockhash,
            );
            signatures.push(self.send_upload(&tx)?);
        }
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

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use serde_json::json;
    use solana_rpc_client::mock_sender::MocksMap;
    use solana_rpc_client_api::request::RpcRequest;

    #[test]
    fn confirmed_failed_burst_repairs_once_with_a_new_identity_before_finalization() {
        let network = Network {
            network: [3; 32],
            genesis_hash: bs58::encode([4; 32]).into_string(),
        };
        let wallet = WalletKey::generate(network.clone()).unwrap();
        let sponsor = Keypair::new();
        let prover = crate::payments::PaymentProver::new();
        let state = WalletState::with_key(&wallet, 1000, prover.verifying_key()).unwrap();
        let bytes = prover
            .build(
                &wallet,
                &state,
                sponsor.pubkey().to_bytes(),
                100,
                crate::payments::Payment::Deposit {
                    amount: 1,
                    recipient: &wallet.address_text(),
                },
            )
            .unwrap();
        let count = crate::upload::remaining(Pubkey::new_unique(), sponsor.pubkey(), &bytes).len();
        let mut prefix = Buffer::initialize(
            &vec![0; ACCOUNT_BYTES],
            sponsor.pubkey().to_bytes(),
            bytes.len() as u32,
            payload_digest(&bytes),
            100,
        )
        .unwrap();
        prefix
            .write(0, &bytes[..native_payments::staging::MAX_CHUNK_BYTES])
            .unwrap();
        let account = |data: Vec<u8>| {
            json!({"context":{"slot":10},"value":{"lamports":1000,"owner":id().to_string(),
            "executable":false,"rentEpoch":0,"data":[bs58::encode(data).into_string(),"base58"]}})
        };
        for new_hash in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
            let mut mocks = MocksMap::from_iter([
                (RpcRequest::GetAccountInfo, account(state.pool.encode())),
                (RpcRequest::GetAccountInfo, account(prefix.bytes().to_vec())),
                (
                    RpcRequest::GetAccountInfo,
                    json!({"context":{"slot":10},"value":null}),
                ),
                (
                    RpcRequest::GetSignatureStatuses,
                    json!({"context":{"slot":10},"value":[{"slot":10,"confirmations":null,
                    "err":null,"status":{"Ok":null},"confirmationStatus":"finalized"}]}),
                ),
                (
                    RpcRequest::GetSignatureStatuses,
                    json!({"context":{"slot":10},"value":vec![json!({"slot":10,"confirmations":null,
                    "err":{"InstructionError":[0,"InvalidInstructionData"]},"status":{"Err":{"InstructionError":[0,"InvalidInstructionData"]}},
                    "confirmationStatus":"finalized"});count]}),
                ),
            ]);
            for byte in [1u8, if new_hash { 2 } else { 1 }, 3] {
                mocks.insert(
                    RpcRequest::GetLatestBlockhash,
                    json!({"context":{"slot":10},"value":{
                    "blockhash":bs58::encode([byte;32]).into_string(),"lastValidBlockHeight":150}}),
                );
            }
            let chain = Chain {
                rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
                network: network.clone(),
                sponsor_budget: None,
                user_fees: None,
                history_batches: false,
                verification_key: None,
            };
            let result = chain.submit(&sponsor, &bytes, &operation);
            if new_hash {
                let receipt = result.unwrap();
                assert_eq!(receipt.upload_failed_transactions, count);
                assert_eq!(receipt.upload_repair_transactions, count);
                assert_eq!(receipt.upload_transactions, 1 + 2 * count);
                assert!(receipt.staging_rent_reclaimed);
                assert!(!operation.pending.exists() && !operation.staging.exists());
            } else {
                assert!(result.err().unwrap().to_string().contains("fresh blockhash"));
                assert!(operation.staging.exists() && !operation.pending.exists());
            }
        }
    }

    #[test]
    fn failed_initialization_or_invalid_burst_observations_never_record_a_payment() {
        let network = Network {
            network: [3; 32],
            genesis_hash: bs58::encode([4; 32]).into_string(),
        };
        let wallet = WalletKey::generate(network.clone()).unwrap();
        let sponsor = Keypair::new();
        let prover = crate::payments::PaymentProver::new();
        let state = WalletState::with_key(&wallet, 1000, prover.verifying_key()).unwrap();
        let bytes = prover
            .build(
                &wallet,
                &state,
                sponsor.pubkey().to_bytes(),
                100,
                crate::payments::Payment::Deposit {
                    amount: 1,
                    recipient: &wallet.address_text(),
                },
            )
            .unwrap();
        let count = crate::upload::remaining(Pubkey::new_unique(), sponsor.pubkey(), &bytes).len();
        let failed = json!({"slot":2,"confirmations":null,"err":{"InstructionError":[0,"InvalidAccountData"]},
            "status":{"Err":{"InstructionError":[0,"InvalidAccountData"]}},"confirmationStatus":"finalized"});
        let succeeded = json!({"slot":1,"confirmations":1,"err":null,"status":{"Ok":null},"confirmationStatus":"confirmed"});
        for mode in 0..3 {
            let root = tempfile::tempdir().unwrap();
            let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
            let mut mocks = MocksMap::from_iter([(
                RpcRequest::GetAccountInfo,
                json!({"context":{"slot":1},"value":{"lamports":1000,"owner":id().to_string(),
                    "executable":false,"rentEpoch":0,"data":[bs58::encode(state.pool.encode()).into_string(),"base58"]}}),
            )]);
            mocks.insert(RpcRequest::GetSignatureStatuses, json!({"context":{"slot":2},"value":[if mode == 0 {failed.clone()} else {succeeded.clone()}]}));
            if mode != 0 {
                mocks.insert(RpcRequest::GetSignatureStatuses, json!({"context":{"slot":2},"value": if mode == 1 {vec![failed.clone();count]} else {vec![]}}));
                // Even confirmed statuses cannot authorize a fabricated prefix.
                mocks.insert(RpcRequest::GetAccountInfo, json!({"context":{"slot":2},"value":{"lamports":1000,"owner":id().to_string(),
                    "executable":false,"rentEpoch":0,"data":[bs58::encode(vec![0; ACCOUNT_BYTES]).into_string(),"base58"]}}));
            }
            let chain = Chain {
                rpc: RpcClient::new_mock_with_mocks_map("succeeds", mocks),
                network: network.clone(),
                sponsor_budget: None,
                user_fees: None,
                history_batches: false,
                verification_key: None,
            };
            assert!(chain.submit(&sponsor, &bytes, &operation).is_err());
            assert!(operation.staging.exists());
            assert!(!operation.pending.exists());
            let saved: StagingRecovery =
                serde_json::from_slice(&read_private(&operation.staging, 4096).unwrap()).unwrap();
            assert_eq!(saved.payload_digest, payload_digest(&bytes));
            assert_eq!(saved.sponsor, sponsor.pubkey().to_string());
            // Arbitrary value-changing instructions cannot use the no-preflight path.
            let forbidden = Transaction::new_with_payer(
                &[instructions::close(Pubkey::new_unique(), sponsor.pubkey())],
                Some(&sponsor.pubkey()),
            );
            assert!(chain.send_upload(&forbidden).is_err());
        }
    }

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
            history_batches: false,
            verification_key: None,
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
            canonical_from_slot: 0,
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
            history_batches: false,
            verification_key: None,
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
    fn history_batches_require_every_requested_block_in_order_and_full_continuity() {
        for mode in 0..6 {
            let (wallet, _, mut chain) = cached_fixture(2, vec![], vec![1, 2]);
            chain.history_batches = true;
            let mut first = block(1, 0);
            if mode == 4 {
                first.as_object_mut().unwrap().remove("transactions");
            }
            let mut response = vec![
                json!({"slot":1,"block":first}),
                json!({"slot":2,"block":block(2, if mode == 3 { 0 } else { 1 })}),
            ];
            if mode == 1 {
                response.pop();
            }
            if mode == 2 {
                response.reverse();
            }
            if mode == 5 {
                response[1]["slot"] = json!(3);
            }
            let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
            chain.rpc = RpcClient::new_mock_with_mocks_map(
                "succeeds",
                MocksMap::from_iter([
                    (
                        RpcRequest::GetAccountInfo,
                        json!({"context":{"slot":2},"value":{
                    "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                    "data":[bs58::encode(pool).into_string(),"base58"]}}),
                    ),
                    (RpcRequest::GetBlocks, json!([1, 2])),
                    (
                        RpcRequest::Custom {
                            method: "getWalletHistoryBlocks",
                        },
                        json!(response),
                    ),
                ]),
            );
            let result = chain.scan(&[&wallet], None);
            if mode == 0 {
                let result = result.unwrap();
                assert_eq!(result.slot, 2);
                assert_eq!(result.scan.blocks_fetched, 2);
                assert_eq!(result.scan.block_rpc_requests, 1);
            } else {
                assert!(result.is_err(), "invalid batch mode {mode} accepted");
            }
        }
    }

    #[test]
    fn remote_pages_pin_identity_cursor_continuity_and_live_header() {
        for mode in 0..11 {
            let (wallet, _, mut chain) = cached_fixture(2, vec![], vec![]);
            chain.history_batches = true;
            let token = json!({"segments":1,"sha256":"a".repeat(64)});
            let compact = |slot, parent| {
                serde_json::to_value(
                    HistoryBlock::from_rpc(
                        slot,
                        serde_json::from_value(block(slot, parent)).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
            };
            let page = |after, slot, complete| {
                json!({"network":wallet.network,"checkpoint":token,"retained_tip":2,
                "after_slot":after,"through_slot":2,"next_slot":slot,"complete":complete,"blocks":[compact(slot,after)]})
            };
            let mut first = page(0, 1, false);
            let mut second = page(1, 2, true);
            match mode {
                1 => second["checkpoint"]["sha256"] = json!("b".repeat(64)),
                2 => first["network"]["network"][0] = json!(99),
                3 => first["blocks"] = json!([]),
                4 => second["blocks"][0]["parent_slot"] = json!(0),
                5 => first["next_slot"] = json!(2),
                6 => first["complete"] = json!(true),
                7 => second = serde_json::Value::Null,
                8 => first["blocks"][0]["slot"] = json!(3),
                9 => first["extra"] = json!("denied"),
                _ => (),
            }
            let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
            chain.rpc = RpcClient::new_mock_with_mocks_map(
                "succeeds",
                MocksMap::from_iter([
                    (
                        RpcRequest::GetAccountInfo,
                        json!({"context":{"slot":2},"value":{
                    "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                    "data":[bs58::encode(pool).into_string(),"base58"]}}),
                    ),
                    (
                        RpcRequest::Custom {
                            method: "getWalletRetainedHistory",
                        },
                        first,
                    ),
                    (
                        RpcRequest::Custom {
                            method: "getWalletRetainedHistory",
                        },
                        second,
                    ),
                    (
                        RpcRequest::GetBlock,
                        block(if mode == 10 { 3 } else { 2 }, 1),
                    ),
                ]),
            );
            let scanned = chain.scan(&[&wallet], None);
            if mode == 0 {
                let scanned = scanned.unwrap();
                assert_eq!(scanned.slot, 2);
                assert_eq!(scanned.canonical_from_slot, 3);
                assert_eq!(scanned.scan.history_blocks_read, 2);
                assert_eq!(scanned.scan.retained_rpc_requests, 2);
                assert!(scanned.accepted.is_empty());
            } else {
                assert!(scanned.is_err(), "invalid retained mode {mode}");
            }
        }
    }

    #[test]
    fn archival_pages_require_full_continuity_fixed_anchor_and_primary_header() {
        for mode in 0..12 {
            let (wallet, _, mut chain) = cached_fixture(2, vec![], vec![]);
            chain.history_batches = true;
            let anchor = json!({"slot":2,"blockhash":block(2,1)["blockhash"],"block_height":2});
            let page = |after, slot| {
                json!({"network":wallet.network,"anchor":anchor,
                "after_slot":after,"next_slot":slot,"complete":slot==2,"blocks":[{"slot":slot,"block":block(slot,after)}]})
            };
            let mut first = page(0, 1);
            let mut second = page(1, 2);
            match mode {
                1 => second["anchor"]["blockhash"] = json!(bs58::encode([33; 32]).into_string()),
                2 => first["network"]["network"][0] = json!(99),
                3 => first["blocks"] = json!([]),
                4 => second["blocks"][0]["block"]["parentSlot"] = json!(0),
                5 => first["next_slot"] = json!(2),
                6 => first["complete"] = json!(true),
                7 => second = serde_json::Value::Null,
                8 => first["blocks"][0]["slot"] = json!(3),
                9 => first["extra"] = json!("denied"),
                11 => {
                    first["anchor"]["block_height"] = json!(3);
                    second["anchor"]["block_height"] = json!(3);
                }
                _ => (),
            }
            let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
            chain.rpc = RpcClient::new_mock_with_mocks_map(
                "succeeds",
                MocksMap::from_iter([
                    (
                        RpcRequest::GetAccountInfo,
                        json!({"context":{"slot":2},"value":{
                    "lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,
                    "data":[bs58::encode(pool).into_string(),"base58"]}}),
                    ),
                    (
                        RpcRequest::Custom {
                            method: "getWalletCanonicalHistory",
                        },
                        first,
                    ),
                    (
                        RpcRequest::Custom {
                            method: "getWalletCanonicalHistory",
                        },
                        second,
                    ),
                    (
                        RpcRequest::GetBlock,
                        block(if mode == 10 { 3 } else { 2 }, 1),
                    ),
                ]),
            );
            let scanned = chain.scan_source_mode(&[&wallet], None, None, None, false);
            if mode == 0 {
                let scanned = scanned.unwrap();
                assert_eq!(scanned.slot, 2);
                assert_eq!(scanned.canonical_from_slot, 0);
                assert_eq!(scanned.scan.archival_rpc_requests, 2);
                assert_eq!(scanned.scan.retained_rpc_requests, 0);
            } else {
                assert!(scanned.is_err(), "invalid archival mode {mode}");
            }
        }
    }

    #[test]
    fn canonical_failed_finalization_requires_a_valid_signature_and_preserves_staging_identity() {
        let (wallet, _, chain) = cached_fixture(0, vec![], vec![]);
        let payer = Keypair::new();
        let staging = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: id(),
            accounts: vec![
                solana_instruction::AccountMeta::new(pool_address(), false),
                solana_instruction::AccountMeta::new(staging, false),
            ],
            data: vec![3],
        };
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer],
            Default::default(),
        );
        let signature = tx.signatures[0].to_string();
        let encoded = json!({"transaction":[base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap()),"base64"],
            "meta":{"err":{"InstructionError":[0,{"Custom":1}]},"status":{"Err":{"InstructionError":[0,{"Custom":1}]}},"fee":5000,"preBalances":[],"postBalances":[]}});
        let malformed = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: id(),
                accounts: vec![],
                data: vec![3],
            }],
            Some(&payer.pubkey()),
            &[&payer],
            Default::default(),
        );
        let mut malformed_encoded = encoded.clone();
        malformed_encoded["transaction"][0] = json!(base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&malformed).unwrap()));
        let mut canonical = block(1, 0);
        canonical["transactions"] = json!([encoded, malformed_encoded]);
        let mut result = chain.scan(&[&wallet], None).unwrap();
        result
            .apply_block(
                HistoryBlock::from_rpc(1, serde_json::from_value(canonical.clone()).unwrap())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            result.finalizations.get(&signature),
            Some(&(staging.to_string(), true))
        );
        assert!(result.accepted.is_empty());
        assert_eq!(result.finalizations.len(), 1);
        assert_eq!(result.scan.payments_verified, 0);
        let (retained_wallet, _, retained_chain) = cached_fixture(0, vec![], vec![]);
        let mut retained = retained_chain.scan(&[&retained_wallet], None).unwrap();
        retained
            .apply_retained_block(
                HistoryBlock::from_rpc(1, serde_json::from_value(canonical).unwrap()).unwrap(),
            )
            .unwrap();
        assert!(retained.finalizations.is_empty());
        let mut bad = tx;
        bad.signatures[0] = Signature::from([12; 64]);
        let mut block = block(2, 1);
        block["transactions"] = json!([{"transaction":[base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&bad).unwrap()),"base64"],"meta":{"err":"AccountNotFound","status":{"Err":"AccountNotFound"},"fee":5000,"preBalances":[],"postBalances":[]}}]);
        assert!(result
            .apply_block(HistoryBlock::from_rpc(2, serde_json::from_value(block).unwrap()).unwrap())
            .is_err());
    }

    #[test]
    fn old_pending_archival_absence_requires_complete_coverage_and_expiry() {
        for mode in 0..5 {
            let root = tempfile::tempdir().unwrap();
            let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
            let (wallet, mut checkpoint, mut chain) = cached_fixture(6, vec![], vec![]);
            checkpoint.canonical_from_slot = u64::MAX;
            cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
            chain.history_batches = true;
            let payer = Keypair::new();
            let staging = Pubkey::new_unique();
            let tx = Transaction::new_signed_with_payer(
                &[Instruction {
                    program_id: id(),
                    accounts: vec![
                        solana_instruction::AccountMeta::new(pool_address(), false),
                        solana_instruction::AccountMeta::new(staging, false),
                    ],
                    data: vec![3],
                }],
                Some(&payer.pubkey()),
                &[&payer],
                Default::default(),
            );
            let mut old = block(2, 0);
            if mode == 2 || mode == 3 {
                old["transactions"] = json!([{"transaction":[base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap()),"base64"],
                    "meta":{"err":"AccountNotFound","status":{"Err":"AccountNotFound"},"fee":5000,"preBalances":[],"postBalances":[]}}]);
            }
            let mut page = json!({"network":wallet.network,"anchor":{"slot":6,"blockhash":block(6,2)["blockhash"],"block_height":6},
                "after_slot":0,"next_slot":6,"complete":true,"blocks":[{"slot":2,"block":old},{"slot":6,"block":block(6,2)}]});
            if mode == 4 {
                page["blocks"][1]["block"]["parentSlot"] = json!(4);
            }
            let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
            let account = json!({"context":{"slot":6},"value":{"lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,"data":[bs58::encode(pool).into_string(),"base58"]}});
            chain.rpc = RpcClient::new_mock_with_mocks_map(
                "succeeds",
                MocksMap::from_iter([
                    (RpcRequest::GetAccountInfo, account.clone()),
                    (RpcRequest::GetAccountInfo, account),
                    (RpcRequest::GetBlock, block(4, 3)),
                    (RpcRequest::GetBlock, block(6, 2)),
                    (RpcRequest::GetBlocks, json!([6])),
                    (
                        RpcRequest::Custom {
                            method: "getWalletHistoryBlocks",
                        },
                        json!([{"slot":6,"block":block(6,4)}]),
                    ),
                    (
                        RpcRequest::Custom {
                            method: "getWalletCanonicalHistory",
                        },
                        page,
                    ),
                ]),
            );
            let pending = Pending {
                network: wallet.network.clone(),
                signature: tx.signatures[0].to_string(),
                staging_account: if mode == 3 {
                    Pubkey::new_unique().to_string()
                } else {
                    staging.to_string()
                },
                last_valid_block_height: if mode == 1 { 100 } else { 0 },
                withdrawal: None,
            };
            let original = serde_json::to_vec(&pending).unwrap();
            write_private_new(&operation.pending, &original).unwrap();
            let outcome = chain.resolve(&wallet, &operation);
            if mode == 0 || mode == 2 {
                let outcome = outcome.unwrap();
                assert_eq!(outcome["accepted"], false);
                assert_eq!(outcome["failed"], mode == 2);
                assert_eq!(outcome["expired_without_execution"], mode == 0);
                assert!(!operation.pending.exists());
                assert_eq!(outcome["sync"]["archival_rpc_requests"], 1);
            } else {
                assert!(outcome.is_err());
                assert_eq!(fs::read(&operation.pending).unwrap(), original);
            }
        }
    }

    #[test]
    fn retained_and_legacy_checkpoints_cannot_clear_unknown_expired_payments() {
        for canonical_from_slot in [5, u64::MAX] {
            let root = tempfile::tempdir().unwrap();
            let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
            let (wallet, mut checkpoint, chain) =
                cached_fixture(6, vec![block(4, 3), block(6, 4)], vec![6]);
            checkpoint.canonical_from_slot = canonical_from_slot;
            cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
            let pending = Pending {
                network: wallet.network.clone(),
                signature: Signature::from([12; 64]).to_string(),
                staging_account: Pubkey::new_unique().to_string(),
                last_valid_block_height: 0,
                withdrawal: None,
            };
            let original = serde_json::to_vec(&pending).unwrap();
            write_private_new(&operation.pending, &original).unwrap();
            let error = chain.resolve(&wallet, &operation).unwrap_err().to_string();
            assert!(error.contains("cannot prove absence"), "{error}");
            assert_eq!(fs::read(&operation.pending).unwrap(), original);
            assert!(
                cache::read(&operation.scan_cache, &wallet)
                    .unwrap()
                    .canonical_from_slot
                    > 0
            );
        }
    }

    #[test]
    fn legacy_unknown_outcome_recovers_with_a_complete_canonical_rescan() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let (wallet, mut checkpoint, mut chain) = cached_fixture(6, vec![], vec![]);
        checkpoint.canonical_from_slot = u64::MAX;
        cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
        let pool = Replay::new(&wallet, 1000).unwrap().state.pool.encode();
        let account = json!({"context":{"slot":6},"value":{"lamports":1000,"owner":id().to_string(),"executable":false,"rentEpoch":0,"data":[bs58::encode(pool).into_string(),"base58"]}});
        chain.rpc = RpcClient::new_mock_with_mocks_map(
            "succeeds",
            MocksMap::from_iter([
                (RpcRequest::GetAccountInfo, account.clone()),
                (RpcRequest::GetAccountInfo, account),
                (RpcRequest::GetBlocks, json!([6])),
                (RpcRequest::GetBlocks, json!([2, 6])),
                (RpcRequest::GetBlock, block(4, 3)),
                (RpcRequest::GetBlock, block(6, 4)),
                (RpcRequest::GetBlock, block(2, 0)),
                (RpcRequest::GetBlock, block(6, 2)),
            ]),
        );
        let pending = Pending {
            network: wallet.network.clone(),
            signature: Signature::from([12; 64]).to_string(),
            staging_account: Pubkey::new_unique().to_string(),
            last_valid_block_height: 0,
            withdrawal: None,
        };
        write_private_new(&operation.pending, &serde_json::to_vec(&pending).unwrap()).unwrap();
        let resolved = chain.resolve(&wallet, &operation).unwrap();
        assert_eq!(resolved["expired_without_execution"], true);
        assert!(!operation.pending.exists());
        assert_eq!(resolved["sync"]["cache_used"], false);
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
    fn private_pending_resolution_extends_authenticated_checkpoint_without_genesis_rescan() {
        let root = tempfile::tempdir().unwrap();
        let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
        let (wallet, mut checkpoint, chain) =
            cached_fixture(6, vec![block(4, 3), block(6, 4)], vec![6]);
        let signature = Signature::from([11; 64]).to_string();
        checkpoint.accepted.insert(signature.clone());
        cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
        let pending = Pending {
            network: wallet.network.clone(),
            signature: signature.clone(),
            staging_account: Pubkey::new_unique().to_string(),
            last_valid_block_height: 100,
            withdrawal: None,
        };
        write_private_new(&operation.pending, &serde_json::to_vec(&pending).unwrap()).unwrap();
        let resolution = chain.resolve(&wallet, &operation).unwrap();
        assert_eq!(resolution["signature"], signature);
        assert_eq!(resolution["accepted"], true);
        assert_eq!(resolution["sync"]["cache_used"], true);
        assert_eq!(resolution["sync"]["blocks_fetched"], 1);
        assert!(!operation.pending.exists());
        assert_eq!(cache::read(&operation.scan_cache, &wallet).unwrap().slot, 6);
    }

    #[test]
    fn pending_resolution_preserves_journal_on_rpc_rollback_and_missing_withdrawal_history() {
        for withdrawal in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let operation = WalletOperation::acquire(&root.path().join("wallet")).unwrap();
            let (wallet, mut checkpoint, chain) = if withdrawal {
                cached_fixture(6, vec![block(6, 4)], vec![6])
            } else {
                cached_fixture(3, vec![], vec![])
            };
            let signature = Signature::from([12; 64]).to_string();
            checkpoint.accepted.insert(signature.clone());
            cache::write(&operation.scan_cache, &wallet, &checkpoint).unwrap();
            let pending = Pending {
                network: wallet.network.clone(),
                signature,
                staging_account: Pubkey::new_unique().to_string(),
                last_valid_block_height: 100,
                withdrawal: withdrawal.then(|| crate::payments::WithdrawalReceipt {
                    recipient: Pubkey::new_unique().to_string(),
                    amount: 10,
                    sponsor: Pubkey::new_unique().to_string(),
                }),
            };
            let original = serde_json::to_vec(&pending).unwrap();
            write_private_new(&operation.pending, &original).unwrap();
            let error = chain.resolve(&wallet, &operation).unwrap_err().to_string();
            assert!(
                error.contains(if withdrawal {
                    "discontinuous"
                } else {
                    "behind the verified"
                }),
                "{error}"
            );
            assert_eq!(fs::read(&operation.pending).unwrap(), original);
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
            history_batches: false,
            verification_key: None,
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
            history_batches: false,
            verification_key: None,
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
            history_batches: false,
            verification_key: None,
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
