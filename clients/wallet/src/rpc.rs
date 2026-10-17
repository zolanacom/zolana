use crate::{
    history::{HistoryInstruction, Replay, WalletState},
    keys::{read_private, write_private_new, Network, WalletKey},
    Result,
};
use native_payment_program::{id, instructions, pool_address, staging::ACCOUNT_BYTES};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::PoolState,
    wire,
};
use serde::{Deserialize, Serialize};
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::{
    http_sender::HttpSender,
    rpc_client::{RpcClient, RpcClientConfig},
};
use solana_rpc_client_api::config::{RpcBlockConfig, RpcSendTransactionConfig};
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
    path::Path,
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
        if 1 + tx.signatures.len() * 64 + tx.message_data().len() > 1232 {
            return Err("signed wallet transaction exceeds the network packet limit".into());
        }
        let signature = self.rpc.send_transaction_with_config(
            &tx,
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

    pub fn resolve(&self, wallet: &WalletKey, path: &Path) -> Result<serde_json::Value> {
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
            "balance":synced.state.balance()?,"pending_cleared":true}),
        )
    }

    pub fn submit(
        &self,
        sponsor: &Keypair,
        bytes: &[u8],
        pending_path: &Path,
    ) -> Result<Submitted> {
        if pending_path.exists() {
            return Err("an unresolved payment exists; run resolve before sending again".into());
        }
        let payment = wire::decode(self.network.network, bytes)?;
        if payment.context.sponsor != sponsor.pubkey().to_bytes() {
            return Err("payment sponsor does not match the local signer".into());
        }
        let expiry = payment.context.expires_at;
        let buffer = Keypair::new();
        self.send(
            sponsor,
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
            &[&buffer],
        )?;
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
            .is_ok();
        Ok(Submitted {
            signature: signature.to_string(),
            staging_account: buffer.pubkey().to_string(),
            staging_rent_reclaimed: reclaimed,
        })
    }
}
