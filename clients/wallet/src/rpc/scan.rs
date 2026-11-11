//! Verified history replay, cache reconciliation and archive export.
//! Retained pages reconstruct balances; canonical replay decides payment outcomes.
use super::{fetch, reads, Chain, ScanResult, ScanStats, Synced};
use crate::{
    archive::{Archive, HistoryBlock, Writer},
    cache::{self, Checkpoint},
    history::{Replay, WalletState},
    keys::WalletKey,
    operation::WalletOperation,
    Result,
};
use native_payment_program::id;
use native_payments::state::PoolState;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcBlockConfig;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, TransactionDetails, UiTransactionEncoding,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    str::FromStr,
    time::Instant,
};

impl ScanResult {
    fn replay_fetched_block(
        &mut self,
        block: HistoryBlock,
        writer: &mut Option<&mut Writer>,
    ) -> Result<()> {
        self.scan.blocks_fetched += 1;
        let replay_at = Instant::now();
        let compact = self.apply_block(block)?;
        self.scan.replay_ms += replay_at.elapsed().as_millis();
        if let Some(writer) = writer {
            writer.push(compact)?;
        }
        Ok(())
    }

    pub(super) fn apply_block(&mut self, block: HistoryBlock) -> Result<HistoryBlock> {
        self.apply_source_block(block, true)
    }

    pub(super) fn apply_retained_block(&mut self, block: HistoryBlock) -> Result<HistoryBlock> {
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
            let loaded = if tx
                .message
                .address_table_lookups()
                .is_some_and(|v| !v.is_empty())
            {
                let meta = encoded
                    .meta
                    .as_ref()
                    .ok_or("versioned transaction metadata is unavailable")?;
                let OptionSerializer::Some(loaded) = &meta.loaded_addresses else {
                    return Err("loaded account addresses are unavailable".into());
                };
                Some(native_wallet_core::canonical::LoadedAddresses {
                    writable: loaded
                        .writable
                        .iter()
                        .map(|v| Ok(Pubkey::from_str(v)?.to_bytes()))
                        .collect::<Result<Vec<_>>>()?,
                    readonly: loaded
                        .readonly
                        .iter()
                        .map(|v| Ok(Pubkey::from_str(v)?.to_bytes()))
                        .collect::<Result<Vec<_>>>()?,
                })
            } else {
                None
            };
            let Some(authenticated) = native_wallet_core::canonical::authenticate(&tx, loaded)?
            else {
                continue;
            };
            let meta = encoded
                .meta
                .as_ref()
                .ok_or("native payment execution metadata is unavailable")?;
            if canonical {
                for ix in &authenticated.instructions {
                    if ix.data == [3] {
                        if let Some((staging, _)) = ix.accounts.get(1) {
                            self.finalizations.insert(
                                authenticated.signature.clone(),
                                (
                                    Pubkey::new_from_array(*staging).to_string(),
                                    meta.err.is_some(),
                                ),
                            );
                        }
                    }
                }
            }
            if meta.err.is_some() {
                continue;
            }
            for instruction in &authenticated.instructions {
                if let Some(accepted) = self.replay.apply_verified(instruction, block.slot)? {
                    if canonical {
                        self.payment_digests
                            .insert(tx.signatures[0].to_string(), accepted.payload_digest()?);
                        self.accepted.insert(tx.signatures[0].to_string());
                        self.payment_slots
                            .insert(tx.signatures[0].to_string(), block.slot);
                    }
                    if let Some(withdrawal) = accepted.withdrawal().filter(|_| canonical) {
                        self.withdrawals
                            .insert(tx.signatures[0].to_string(), withdrawal);
                    }
                    self.scan.payments_verified += 1;
                    for state in &mut self.secondary {
                        accepted.apply(state)?;
                    }
                }
            }
            retained.push(encoded);
        }
        block.transactions = retained;
        // The V4 transition is implicit at the end of every produced block,
        // including one with no native instructions. Seal after all effects.
        self.replay.finish_slot(block.slot)?;
        for state in &mut self.secondary {
            state.finish_slot(block.slot)?;
        }
        self.slot = block.slot;
        self.block_hash = Some(block.blockhash.clone());
        self.block_height = block.block_height;
        Ok(block)
    }

    pub(super) fn finish(self) -> Vec<Synced> {
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
                payment_digests: self.payment_digests.clone(),
                payment_slots: self.payment_slots.clone(),
                scan: self.scan.clone(),
            })
            .collect()
    }
}

impl Chain {
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
        let cache_read_at = Instant::now();
        let (candidate, discarded) = if operation.scan_cache.exists() {
            match cache::read(&operation.scan_cache, wallet) {
                Ok(checkpoint) => (Some(checkpoint), false),
                Err(_) => (None, true),
            }
        } else {
            (None, false)
        };
        let cache_read_ms = cache_read_at.elapsed().as_millis();
        let mut result = self.scan_source(&[wallet], candidate, history, None)?;
        result.scan.cache_read_ms = cache_read_ms;
        if discarded {
            result.scan.cache_reset = Some("invalid_cache".into());
        }
        let cache_write_at = Instant::now();
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
        result.scan.cache_write_ms = cache_write_at.elapsed().as_millis();
        result
            .finish()
            .pop()
            .ok_or_else(|| "missing synchronized wallet".into())
    }

    pub(super) fn scan(
        &self,
        wallets: &[&WalletKey],
        candidate: Option<Checkpoint>,
    ) -> Result<ScanResult> {
        self.scan_source(wallets, candidate, None, None)
    }

    fn fetch_history_blocks(&self, slots: &[u64]) -> Result<Vec<HistoryBlock>> {
        if slots.is_empty()
            || slots.len()
                > if self.history_batches {
                    fetch::PAGE
                } else {
                    fetch::LEGACY_PAGE
                }
        {
            return Err("invalid history request size".into());
        }
        if self.history_batches {
            Ok(fetch::invited_history_blocks(&self.rpc, slots)?)
        } else if self.standard_reads_enabled() {
            let calls = slots.iter().map(|slot| ("getBlock", serde_json::json!([
                slot, {"encoding":"base64", "transactionDetails":"full", "rewards":false,
                    "commitment":"finalized", "maxSupportedTransactionVersion":0}
            ]))).collect();
            self.standard_read_batch(calls)?
                .into_iter()
                .zip(slots)
                .map(|(block, slot)| HistoryBlock::from_rpc(*slot, serde_json::from_value(block)?))
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

    pub(super) fn scan_source(
        &self,
        wallets: &[&WalletKey],
        candidate: Option<Checkpoint>,
        history: Option<&Archive>,
        writer: Option<&mut Writer>,
    ) -> Result<ScanResult> {
        self.scan_source_mode(wallets, candidate, history, writer, true)
    }

    pub(super) fn scan_source_mode(
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
        let controls = reads::scan_controls(&self.rpc, candidate.as_ref().map(|cache| cache.slot))?;
        let response = controls.pool;
        let account = response.value.ok_or("native pool is missing")?;
        if account.owner != id() {
            return Err("native pool owner mismatch".into());
        }
        let pool = PoolState::decode(&account.data)?;
        self.check_pool_format(&pool)?;
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
        if pool.uses_slot_anchors()
            && !pool
                .slot_anchors()
                .and_then(|history| history.entries().last())
                .is_some_and(|entry| {
                    entry.slot == target
                        && entry.note_count == pool.note_count()
                        && entry.root == pool.root()
                })
        {
            return Err("finalized V4 pool is missing its exact completed slot checkpoint".into());
        }
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
        let mut stats = ScanStats {
            pool_rpc_ms: controls.pool_rpc_ms,
            checkpoint_rpc_ms: controls.checkpoint_rpc_ms,
            scan_control_rpc_ms: controls.elapsed_ms,
            ..ScanStats::default()
        };
        let mut cached = None;
        if let Some(checkpoint) = candidate {
            if checkpoint.slot > target {
                return Err("RPC finalized state is behind the verified wallet checkpoint; wait or use an up-to-date RPC".into());
            }
            let canonical = checkpoint.slot == 0
                || controls
                    .cached_blockhash
                    .is_some_and(|hash| Some(hash) == checkpoint.block_hash);
            if canonical {
                match Replay::restore_with_key(wallets[0], checkpoint.replay, shared_key.clone()) {
                    Ok(replay) => {
                        if replay.state.pool.uses_slot_anchors() != pool.uses_slot_anchors() {
                            return Err("cached pool format differs from the explicit network profile; no wallet migration was performed".into());
                        }
                        if replay.state.pool.uses_slot_anchors()
                            && !replay
                                .state
                                .pool
                                .slot_anchors()
                                .and_then(|history| history.entries().last())
                                .is_some_and(|entry| {
                                    entry.slot == checkpoint.slot
                                        && entry.note_count == replay.state.pool.note_count()
                                        && entry.root == replay.state.pool.root()
                                })
                        {
                            return Err(
                                "cached V4 replay does not end at its completed slot checkpoint"
                                    .into(),
                            );
                        }
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
                    Replay::from_state(WalletState::with_key_for_pool(
                        wallets[0],
                        &pool,
                        key.clone(),
                    )?)
                } else if pool.uses_slot_anchors() {
                    let mut replay = Replay::new_slot_anchored(wallets[0], pool.rent_floor)?;
                    replay.finish_slot(0)?;
                    replay
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
                .map(|wallet| WalletState::with_key_for_pool(wallet, &pool, key.clone()))
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
            payment_digests: BTreeMap::new(),
            payment_slots: BTreeMap::new(),
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
        // Recent cached suffixes stay on canonical RPC, including receipts.
        // After at least one full two-page fetch window (512 slots), an
        // explicitly compact-V2 client may instead replay a retained suffix.
        // Slot gaps can include skipped slots: this is only a read-path hint,
        // never permission to omit a produced block or weaken verification.
        // Canonical pending recovery still disables retained reads entirely.
        let remote_retained = if allow_remote_retained
            && self.history_batches
            && history.is_none()
            && (!result.scan.cache_used
                || (self.retained_history_v2
                    && target.saturating_sub(result.slot) >= fetch::WINDOW as u64))
            && result.slot < target
        {
            self.scan_retained(&mut result, target)?
        } else {
            false
        };
        let mut start = result.slot.checked_add(1).ok_or("history slot overflow")?;
        let mut legacy_history_pages = false;
        while start <= target {
            let end = start.saturating_add(9999).min(target);
            let block_range_rpc_at = Instant::now();
            let blocks: Vec<_> = self
                .rpc
                .get_blocks(start, Some(end))?
                .into_iter()
                .filter(|slot| *slot != 0)
                .collect();
            result.scan.block_range_rpc_ms += block_range_rpc_at.elapsed().as_millis();
            result.scan.block_range_rpc_requests += 1;
            if blocks.iter().any(|slot| *slot < start || *slot > end)
                || blocks.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err("invalid finalized block range".into());
            }
            for slots in blocks.chunks(if self.history_batches {
                fetch::WINDOW
            } else if self.standard_reads_enabled() {
                fetch::LEGACY_PAGE
            } else {
                1
            }) {
                let mut batch = None;
                if self.history_batches && !legacy_history_pages {
                    // Share only RpcClient: sponsor authorization contains a
                    // RefCell and must never enter concurrent fetch workers.
                    let rpc = &self.rpc;
                    let fetched_at = Instant::now();
                    let fetched = fetch::ordered_window(slots, |page| {
                        fetch::invited_history_blocks(rpc, page)
                    });
                    result.scan.fetch_ms += fetched_at.elapsed().as_millis();
                    result.scan.block_rpc_requests += slots.len().div_ceil(fetch::PAGE);
                    match fetched {
                        Ok(blocks) => batch = Some(blocks),
                        Err(fetch::FetchError::ResponseTooLarge) => {
                            // Both workers joined and all partial output was
                            // discarded. Preserve this exact target/window and
                            // use bounded pages for the rest of this scan.
                            legacy_history_pages = true;
                            result.scan.history_page_fallbacks += 1;
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else if !self.history_batches {
                    let fetched_at = Instant::now();
                    batch = Some(self.fetch_history_blocks(slots)?);
                    result.scan.fetch_ms += fetched_at.elapsed().as_millis();
                    result.scan.block_rpc_requests += 1;
                }
                if self.history_batches && legacy_history_pages {
                    let stats = fetch::replay_legacy_pages(
                        slots,
                        |page| fetch::invited_history_blocks(&self.rpc, page),
                        |block| {
                            result
                                .replay_fetched_block(block, &mut writer)
                                .map_err(|error| fetch::FetchError::Invalid(error.to_string()))
                        },
                    )?;
                    result.scan.fetch_ms += stats.fetch_ms;
                    result.scan.block_rpc_requests += stats.requests;
                    result.scan.history_page_fallbacks += stats.splits;
                } else {
                    for block in batch.ok_or("history fetch did not return a complete window")? {
                        result.replay_fetched_block(block, &mut writer)?;
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
        if let Some(history) = history {
            result.accepted.clear();
            result.withdrawals.clear();
            result.finalizations.clear();
            result.payment_digests.clear();
            result.payment_slots.clear();
            result.canonical_from_slot = result
                .canonical_from_slot
                .max(history.tip().min(target).saturating_add(1));
        }
        Ok(result)
    }
}
