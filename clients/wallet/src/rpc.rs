use crate::{
    history::{HistoryInstruction, Replay, WalletState},
    keys::{read_private, write_private_new, Network, WalletKey},
    operation::WalletOperation,
    Result,
};
use native_payment_program::{
    id, instructions, pool_address,
    staging::{Buffer, ACCOUNT_BYTES},
};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::PoolState,
    wire,
};
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
    collections::BTreeSet,
    fs,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

pub struct Chain {
    rpc: RpcClient,
    network: Network,
}

pub struct Synced {
    pub state: WalletState,
    pub slot: u64,
    pub block_height: u64,
    accepted_finalizations: BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    network: Network,
    signature: String,
    staging_account: String,
    last_valid_block_height: u64,
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
}

#[derive(Serialize)]
pub struct Submitted {
    pub signature: String,
    pub staging_account: String,
    pub staging_rent_reclaimed: bool,
}

impl Chain {
    pub fn connect(url: &str, network: Network) -> Result<Self> {
        let port: u16 = url
            .strip_prefix("http://127.0.0.1:")
            .ok_or("local wallet RPC must use http://127.0.0.1:<port>")?
            .parse()?;
        if port == 0 {
            return Err("RPC port must be nonzero".into());
        }
        let http = reqwest::Client::builder()
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
        Ok(Self { rpc, network })
    }

    pub fn sync(&self, wallet: &WalletKey) -> Result<Synced> {
        if wallet.network != self.network {
            return Err("wallet network mismatch".into());
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
        let mut replay = Replay::new(wallet, pool.rent_floor)?;
        let mut previous_slot = 0;
        let mut previous_hash = None;
        let mut block_height = 0;
        let mut accepted_finalizations = BTreeSet::new();
        let mut start = 0;
        while start <= target {
            let end = start.saturating_add(9999).min(target);
            let blocks = self.rpc.get_blocks(start, Some(end))?;
            for slot in blocks.into_iter().filter(|slot| *slot != 0) {
                let block = self.rpc.get_block_with_config(slot, RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Base64), transaction_details: Some(TransactionDetails::Full),
                    rewards: Some(false), commitment: Some(CommitmentConfig::finalized()), max_supported_transaction_version: Some(0),
                }).map_err(|error| format!("cannot read finalized block {slot}; complete archive history is required: {error}"))?;
                if block.parent_slot != previous_slot
                    || previous_hash
                        .as_ref()
                        .is_some_and(|hash| hash != &block.previous_blockhash)
                {
                    return Err("finalized block history is incomplete or discontinuous; an archive RPC is required".into());
                }
                previous_slot = slot;
                previous_hash = Some(block.blockhash);
                block_height = block
                    .block_height
                    .ok_or("archived block height is unavailable")?;
                for encoded in block
                    .transactions
                    .ok_or("full transaction history is unavailable")?
                {
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
                    let relevant = tx
                        .message
                        .instructions()
                        .iter()
                        .any(|ix| keys.get(ix.program_id_index as usize) == Some(&id()));
                    if !relevant {
                        continue;
                    }
                    let meta = encoded
                        .meta
                        .ok_or("native payment execution metadata is unavailable")?;
                    // Failed transactions leave no native or staging effects at all.
                    if meta.err.is_some() {
                        continue;
                    }
                    tx.verify_and_hash_message()?;
                    for ix in tx.message.instructions() {
                        if keys.get(ix.program_id_index as usize) != Some(&id()) {
                            continue;
                        }
                        let mut accounts = Vec::new();
                        for index in &ix.accounts {
                            let index = *index as usize;
                            accounts.push((
                                *keys.get(index).ok_or("invalid archived account index")?,
                                tx.message.is_signer(index),
                            ));
                        }
                        replay.apply(
                            &HistoryInstruction {
                                accounts,
                                data: ix.data.clone(),
                            },
                            slot,
                        )?;
                        if ix.data.first() == Some(&3) {
                            accepted_finalizations.insert(tx.signatures[0].to_string());
                        }
                    }
                }
            }
            if end == target {
                break;
            }
            start = end + 1;
        }
        if previous_slot != target {
            return Err(
                "finalized history does not reach the pool checkpoint; archive history is required"
                    .into(),
            );
        }
        replay.state.reconcile(&pool)?;
        Ok(Synced {
            state: replay.state,
            slot: target,
            block_height,
            accepted_finalizations,
        })
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
        if 1 + tx.signatures.len() * 64 + tx.message_data().len() > 1232 {
            return Err("signed wallet transaction exceeds the network packet limit".into());
        }
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
        fs::remove_file(path)?;
        Ok(
            serde_json::json!({"signature":pending.signature,"accepted":accepted,"failed":failed,
            "expired_without_execution":expired_without_execution,"staging_account":pending.staging_account,
            "balance":synced.state.balance()?,"pending_cleared":true,
            "staging_recovery_required":operation.staging.exists()}),
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
        let payment = wire::decode(self.network.network, bytes)?;
        if payment.context.sponsor != sponsor.pubkey().to_bytes() {
            return Err("payment sponsor does not match the local signer".into());
        }
        let expiry = payment.context.expires_at;
        let buffer = Keypair::new();
        let (blockhash, last_valid_block_height) = self
            .rpc
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())?;
        let initialization = Transaction::new_signed_with_payer(
            &[
                system::create_account(
                    &sponsor.pubkey(),
                    &buffer.pubkey(),
                    self.rpc
                        .get_minimum_balance_for_rent_exemption(ACCOUNT_BYTES)?,
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
            })?,
        )?;
        self.send_signed(&initialization)?;
        for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            self.send(
                sponsor,
                &[instructions::write(
                    buffer.pubkey(),
                    sponsor.pubkey(),
                    (index * MAX_CHUNK_BYTES) as u32,
                    chunk,
                )],
                &[],
            )?;
        }
        self.send(
            sponsor,
            &[instructions::seal(buffer.pubkey(), sponsor.pubkey())],
            &[],
        )?;
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
            instructions::finalize(buffer.pubkey(), sponsor.pubkey(), nullifiers),
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
        // Durable create_new is also an inter-process lock. The signed identity
        // is saved before the first possible broadcast of value-changing effects.
        write_private_new(
            pending_path,
            &serde_json::to_vec_pretty(&Pending {
                network: self.network.clone(),
                signature: signature.to_string(),
                staging_account: buffer.pubkey().to_string(),
                last_valid_block_height,
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
        fs::remove_file(pending_path)?;
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
        if reclaimed {
            // Payment acceptance must remain a success even if local cleanup fails.
            let _ = fs::remove_file(&operation.staging);
        }
        Ok(Submitted {
            signature: signature.to_string(),
            staging_account: buffer.pubkey().to_string(),
            staging_rent_reclaimed: reclaimed,
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
            network,
        }
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
