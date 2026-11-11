//! Worker-local finalized history coordinator. RPC consensus is trusted, as in
//! the native reference. Retained history is never transaction inclusion proof.
//! Private note snapshots are authenticated/encrypted inside Rust before JS.
use crate::{
    error::{BrowserError, ErrorCode, Result},
    vault::BrowserVault,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use native_payments::{native_accounts, staging::payload_digest, state::PoolState, wire};
use native_wallet_core::{
    canonical::{self, LoadedAddresses},
    history::{ReplaySnapshot, WalletState},
    payments::{Payment, PaymentProver},
    replay::Replay,
};
use native_wallet_seed::Network;
use orchard::circuit::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
#[path = "compact.rs"]
mod compact;
#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "session_verification_key_tests.rs"]
mod verification_key_tests;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const CACHE_MAGIC: &[u8; 8] = b"NSCAN001";
const PENDING_MAGIC: &[u8; 8] = b"BPND0001";
thread_local! {
    static PROVER: RefCell<Option<PaymentProver>> = const { RefCell::new(None) };
    static REPLAY_KEY: RefCell<Option<Arc<VerifyingKey>>> = const { RefCell::new(None) };
}
fn with_prover<T>(f: impl FnOnce(&PaymentProver) -> Result<T>) -> Result<T> {
    PROVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(PaymentProver::new());
        }
        f(slot.as_ref().unwrap())
    })
}
/// Replay needs public verification material, not the larger proving key.
/// Prefer a ready prover's key; otherwise build only the same Orchard v2 VK.
/// This cache is public, circuit-specific material shared by worker wallets.
fn replay_verifying_key() -> Arc<VerifyingKey> {
    REPLAY_KEY.with(|slot| {
        let mut slot = slot.borrow_mut();
        Arc::clone(slot.get_or_insert_with(|| {
            PROVER.with(|prover| {
                prover
                    .borrow()
                    .as_ref()
                    .map(PaymentProver::verifying_key)
                    .unwrap_or_else(|| {
                        Arc::new(VerifyingKey::build(
                            native_payments::verification::bundle_version().circuit_version(),
                        ))
                    })
            })
        }))
    })
}
fn err(e: impl std::fmt::Display) -> BrowserError {
    e.to_string().into()
}
fn parsed<T: serde::de::DeserializeOwned>(text: &str, limit: usize) -> Result<T> {
    if text.len() > limit {
        return Err("history input exceeds byte limit".into());
    }
    serde_json::from_str(text).map_err(err)
}
fn hash(text: &str) -> Result<()> {
    if text.len() > 44 || bs58::decode(text).into_vec().map_err(err)?.len() != 32 {
        return Err("invalid finalized block hash".into());
    }
    Ok(())
}
fn n(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| BrowserError::from(format!("missing {key}")))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| BrowserError::from(format!("missing {key}")))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    network: Network,
    address: String,
    slot: u64,
    block_hash: Option<String>,
    block_height: u64,
    accepted: BTreeSet<String>,
    canonical_from_slot: u64,
    replay: ReplaySnapshot,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Token {
    segments: u32,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    network: Network,
    checkpoint: Token,
    retained_tip: u64,
    after_slot: u64,
    through_slot: u64,
    next_slot: u64,
    complete: bool,
    blocks: Vec<Block>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Block {
    slot: u64,
    parent_slot: u64,
    blockhash: String,
    previous_blockhash: String,
    block_height: u64,
    transactions: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAnchor {
    slot: u64,
    blockhash: String,
    block_height: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveBlock {
    slot: u64,
    block: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivePage {
    network: Network,
    anchor: ArchiveAnchor,
    after_slot: u64,
    next_slot: u64,
    complete: bool,
    blocks: Vec<ArchiveBlock>,
}
pub(crate) struct Session {
    replay: Replay,
    slot: u64,
    block_hash: Option<String>,
    height: u64,
    target: u64,
    target_hash: String,
    target_height: u64,
    pool: PoolState,
    token: Option<Token>,
    canonical_from: u64,
    verified: bool,
    // Exact ciphertext most recently returned by a successful finish_sync on
    // this unlocked handle. Never serialized, imported or shared across locks.
    checkpoint_pin: Option<[u8; 32]>,
    accepted: BTreeMap<[u8; 32], (String, u64)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    format: String,
    network: Network,
    payload: String,
    payer: String,
    fee: u64,
    maximum_fee: u64,
    expires_at: u64,
    created_slot: u64,
    created_height: u64,
    checkpoint_pin: [u8; 32],
}

impl BrowserVault {
    fn cache_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"NPayCacheKeyV1!!")
            .key(self.unlocked_seed()?)
            .to_state();
        h.update(&self.network().network);
        h.update(self.network().genesis_hash.as_bytes());
        Ok(Zeroizing::new(h.finalize().as_bytes().try_into().unwrap()))
    }
    fn seal(&self, magic: &[u8; 8], plain: &[u8]) -> Result<Vec<u8>> {
        if plain.len() > MAX_BYTES {
            return Err("encrypted record exceeds bound".into());
        }
        let key = self.cache_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(err)?;
        let nonce: [u8; 24] = rand::random();
        let encrypted = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plain,
                    aad: magic,
                },
            )
            .map_err(|_| "record encryption failed")?;
        let mut out = magic.to_vec();
        out.extend_from_slice(&nonce);
        out.extend(encrypted);
        Ok(out)
    }
    fn unseal(&self, magic: &[u8; 8], encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if encoded.len() < 48 || encoded.len() > MAX_BYTES + 48 || &encoded[..8] != magic {
            return Err(BrowserError::new(
                ErrorCode::Recovery,
                "invalid encrypted record envelope",
            ));
        }
        let key = self.cache_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(err)?;
        let nonce: [u8; 24] = encoded[8..32].try_into().map_err(err)?;
        Ok(Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &encoded[32..],
                        aad: magic,
                    },
                )
                .map_err(|_| {
                    BrowserError::new(
                        ErrorCode::Recovery,
                        "encrypted record authentication failed",
                    )
                })?,
        ))
    }
    fn read_checkpoint(&self, bytes: &[u8]) -> Result<Checkpoint> {
        let plain = self.unseal(CACHE_MAGIC, bytes)?;
        let c: Checkpoint = serde_json::from_slice(&plain).map_err(err)?;
        if c.network != *self.network()
            || c.address != self.identity()?.private_address
            || (c.slot == 0) != c.block_hash.is_none()
            || (c.canonical_from_slot != u64::MAX
                && c.canonical_from_slot > c.slot.saturating_add(1))
        {
            return Err(BrowserError::new(
                ErrorCode::Recovery,
                "checkpoint network, identity or coverage mismatch",
            ));
        }
        if let Some(h) = &c.block_hash {
            hash(h)?;
        }
        Ok(c)
    }
    pub fn checkpoint_info(&self, bytes: &[u8]) -> Result<String> {
        let c = self.read_checkpoint(bytes)?;
        Ok(
            json!({"slot":c.slot,"block_hash":c.block_hash,"block_height":c.block_height})
                .to_string(),
        )
    }
    pub fn begin_sync(
        &mut self,
        pool_json: &str,
        header_json: &str,
        checkpoint: &[u8],
        cached_header_json: &str,
    ) -> Result<String> {
        // Any rejected begin still destroys the earlier verified session.
        let mut previous = self.session.take();
        self.unlocked_seed()?;
        let response: Value = parsed(pool_json, 1024 * 1024)?;
        let target = n(&response["context"], "slot")?;
        let account = &response["value"];
        if text(account, "owner")?
            != Pubkey::new_from_array(native_accounts::PROGRAM_ID).to_string()
            || account["data"][1] != "base64"
        {
            return Err(BrowserError::new(
                ErrorCode::History,
                "native pool owner or encoding mismatch",
            ));
        }
        let bytes = STANDARD
            .decode(account["data"][0].as_str().ok_or("pool data missing")?)
            .map_err(err)?;
        let pool = PoolState::decode(&bytes).map_err(err)?;
        if &bytes[..8] != b"NPOOL004"
            || pool.network != self.network().network
            || n(account, "lamports")?
                < pool
                    .rent_floor
                    .checked_add(pool.backing)
                    .ok_or("backing overflow")?
            || !pool
                .slot_anchors()
                .and_then(|h| h.entries().last())
                .is_some_and(|a| {
                    a.slot == target && a.note_count == pool.note_count() && a.root == pool.root()
                })
        {
            return Err(BrowserError::new(
                ErrorCode::History,
                "finalized pool format, backing or completed slot mismatch",
            ));
        }
        let header: Value = parsed(header_json, 16384)?;
        let target_hash = text(&header, "blockhash")?.to_owned();
        hash(&target_hash)?;
        let target_height = n(&header, "blockHeight")?;
        let key = replay_verifying_key();
        let (replay, slot, block_hash, height, canonical_from) = if checkpoint.is_empty() {
            let state = WalletState::with_key_for_pool(self, &pool, key).map_err(err)?;
            (Replay::from_state(state), 0, None, 0, 0)
        } else {
            let c = self.read_checkpoint(checkpoint)?;
            if c.slot > target {
                return Err(BrowserError::new(
                    ErrorCode::History,
                    "RPC finalized state is behind the saved wallet; refusing rollback",
                ));
            }
            let cached: Value = parsed(cached_header_json, 16384)?;
            if c.slot != 0 && cached["blockhash"].as_str() != c.block_hash.as_deref() {
                return Err(BrowserError::new(
                    ErrorCode::History,
                    "saved checkpoint does not match finalized RPC history",
                ));
            }
            let pin: [u8; 32] = blake2b_simd::Params::new()
                .hash_length(32)
                .hash(checkpoint)
                .as_bytes()
                .try_into()
                .unwrap();
            let reuse = previous.as_ref().is_some_and(|s| {
                s.verified
                    && s.checkpoint_pin == Some(pin)
                    && s.slot == c.slot
                    && s.block_hash == c.block_hash
                    && s.height == c.block_height
            });
            let replay = if reuse {
                previous.take().expect("verified matching session").replay
            } else {
                Replay::restore_with_key(self, c.replay, Some(key)).map_err(err)?
            };
            if !replay.state.pool.uses_slot_anchors()
                || !replay
                    .state
                    .pool
                    .slot_anchors()
                    .and_then(|h| h.entries().last())
                    .is_some_and(|a| {
                        a.slot == c.slot
                            && a.note_count == replay.state.pool.note_count()
                            && a.root == replay.state.pool.root()
                    })
            {
                return Err(BrowserError::new(
                    ErrorCode::History,
                    "saved replay lacks its exact completed slot",
                ));
            }
            (
                replay,
                c.slot,
                c.block_hash,
                c.block_height,
                c.slot.saturating_add(1),
            )
        };
        self.session = Some(Session {
            replay,
            slot,
            block_hash,
            height,
            target,
            target_hash,
            target_height,
            pool,
            token: None,
            canonical_from,
            verified: false,
            checkpoint_pin: None,
            accepted: BTreeMap::new(),
        });
        self.sync_progress()
    }
    pub fn sync_progress(&self) -> Result<String> {
        self.unlocked_seed()?;
        let s = self
            .session
            .as_ref()
            .ok_or("verified sync has not started")?;
        Ok(json!({"slot":s.slot,"target":s.target,"block_height":s.height,"token":s.token,"complete":s.slot==s.target}).to_string())
    }
    pub fn apply_history_page(&mut self, page_json: &str) -> Result<String> {
        self.unlocked_seed()?;
        let page = match parsed(page_json, 16 * 1024 * 1024) {
            Ok(page) => page,
            Err(error) => {
                self.session.take();
                return Err(error);
            }
        };
        self.apply_retained_page(page)
    }
    pub fn apply_compact_history_page(
        &mut self,
        metadata_json: &str,
        headers: &[u8],
    ) -> Result<String> {
        self.unlocked_seed()?;
        let page = match compact::decode(metadata_json, headers) {
            Ok(page) => page,
            Err(error) => {
                self.session.take();
                return Err(error);
            }
        };
        self.apply_retained_page(page)
    }
    fn apply_retained_page(&mut self, page: Page) -> Result<String> {
        let mut s = self.session.take().ok_or("sync has not started")?;
        if s.verified {
            return Err("start a new sync before replay".into());
        }
        let through = s.target.min(page.retained_tip);
        if page.network != *self.network()
            || page.retained_tip == 0
            || page.after_slot != s.slot
            || page.through_slot != through
            || !(1..=16384).contains(&page.checkpoint.segments)
            || page.checkpoint.sha256.len() != 64
            || !page
                .checkpoint
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || s.token.as_ref().is_some_and(|t| t != &page.checkpoint)
            || page.blocks.len() > 32768
            || page.next_slot != page.blocks.last().map_or(s.slot, |b| b.slot)
            || page.complete != (page.next_slot >= through)
            || (s.slot < through && page.blocks.is_empty())
            || page
                .blocks
                .iter()
                .any(|b| b.slot <= s.slot || b.slot > through)
        {
            return Err(BrowserError::new(
                ErrorCode::History,
                "invalid, changed or incomplete retained history page",
            ));
        }
        for block in page.blocks {
            s.apply_block(block, false)?;
        }
        s.token = Some(page.checkpoint);
        self.session = Some(s);
        self.sync_progress()
    }
    pub fn apply_canonical_blocks(&mut self, blocks_json: &str) -> Result<String> {
        self.unlocked_seed()?;
        let mut s = self.session.take().ok_or("sync has not started")?;
        if s.verified {
            return Err("start a new sync before replay".into());
        }
        let blocks: Vec<Block> = parsed(blocks_json, 16 * 1024 * 1024)?;
        if blocks.is_empty() || blocks.len() > 256 {
            return Err("canonical history batch must contain 1..256 blocks".into());
        }
        for block in blocks {
            s.apply_block(block, true)?;
        }
        self.session = Some(s);
        self.sync_progress()
    }
    pub fn apply_archival_page(&mut self, page_json: &str) -> Result<String> {
        self.unlocked_seed()?;
        let mut s = self.session.take().ok_or("sync has not started")?;
        if s.verified {
            return Err("start a new sync before replay".into());
        }
        let page: ArchivePage = parsed(page_json, 16 * 1024 * 1024)?;
        if page.network != *self.network()
            || page.anchor.slot != s.target
            || page.anchor.blockhash != s.target_hash
            || page.anchor.block_height != s.target_height
            || page.after_slot != s.slot
            || page.blocks.is_empty()
            || page.blocks.len() > 16
            || page.next_slot != page.blocks.last().map_or(s.slot, |b| b.slot)
            || page.complete != (page.next_slot == s.target)
        {
            return Err(BrowserError::new(
                ErrorCode::History,
                "canonical archive page differs from the exact finalized target or cursor",
            ));
        }
        for b in page.blocks {
            let block = Block {
                slot: b.slot,
                parent_slot: n(&b.block, "parentSlot")?,
                blockhash: text(&b.block, "blockhash")?.into(),
                previous_blockhash: text(&b.block, "previousBlockhash")?.into(),
                block_height: n(&b.block, "blockHeight")?,
                transactions: b.block["transactions"]
                    .as_array()
                    .ok_or("canonical archive transactions unavailable")?
                    .clone(),
            };
            s.apply_block(block, true)?;
        }
        self.session = Some(s);
        self.sync_progress()
    }
    fn checkpoint_bytes(&self, s: &Session) -> Result<Vec<u8>> {
        let c = Checkpoint {
            network: self.network().clone(),
            address: self.identity()?.private_address,
            slot: s.slot,
            block_hash: s.block_hash.clone(),
            block_height: s.height,
            accepted: BTreeSet::new(),
            canonical_from_slot: s.canonical_from,
            replay: s.replay.snapshot(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&c).map_err(err)?);
        self.seal(CACHE_MAGIC, &plain)
    }
    pub fn finish_sync(&mut self) -> Result<Vec<u8>> {
        self.unlocked_seed()?;
        let mut s = self.session.take().ok_or("sync has not started")?;
        if s.slot != s.target
            || s.block_hash.as_deref() != Some(&s.target_hash)
            || s.height != s.target_height
        {
            return Err(BrowserError::new(
                ErrorCode::History,
                "history did not reach exact finalized target hash and height",
            ));
        }
        s.replay.state.reconcile(&s.pool).map_err(err)?;
        for note in s.replay.state.unspent() {
            s.replay.state.witness(note.position).map_err(err)?;
        }
        s.verified = true;
        let out = self.checkpoint_bytes(&s)?;
        s.checkpoint_pin = Some(
            blake2b_simd::Params::new()
                .hash_length(32)
                .hash(&out)
                .as_bytes()
                .try_into()
                .unwrap(),
        );
        self.session = Some(s);
        Ok(out)
    }
    pub fn payment_status(&self) -> Result<String> {
        self.unlocked_seed()?;
        let s = self
            .session
            .as_ref()
            .filter(|s| s.verified)
            .ok_or_else(|| {
                BrowserError::new(
                    ErrorCode::SyncRequired,
                    "history must be verified and saved before payments",
                )
            })?;
        Ok(json!({"balance":s.replay.state.balance().map_err(err)?.to_string(),"max_payment":s.replay.state.max_payment().map_err(err)?.to_string(),"slot":s.slot,"block_height":s.height,"verified":true,"finality_source":"verified finalized RPC history; RPC consensus is trusted"}).to_string())
    }
    pub fn build_payment(
        &self,
        recipient: &str,
        amount: u64,
        maximum_fee: u64,
        quote_json: &str,
        expiry: u64,
        saved_checkpoint: &[u8],
    ) -> Result<String> {
        self.unlocked_seed()?;
        let preparation_timer = crate::Timer::start();
        let s = self
            .session
            .as_ref()
            .filter(|s| s.verified)
            .ok_or_else(|| {
                BrowserError::new(ErrorCode::SyncRequired, "verified checkpoint required")
            })?;
        let q: Value = parsed(quote_json, 8192)?;
        let fee = n(&q, "fee")?;
        let payer = text(&q, "payer")?;
        let payer_key = Pubkey::from_str(payer).map_err(err)?;
        if q["format"] != "native-shielded-fee-quote-v1"
            || q["network"] != serde_json::to_value(self.network()).map_err(err)?
            || q["transport"] != "native-inline-v1"
            || q["pool_format"] != "NPOOL004"
            || fee == 0
            || fee > maximum_fee
            || maximum_fee > 100_000_000
            || !payer_key.is_on_curve()
            || expiry <= s.slot
            || expiry.saturating_sub(s.slot) > native_payments::verification::MAX_EXPIRY_WINDOW
        {
            return Err(BrowserError::new(
                ErrorCode::Review,
                "fee quote, recipient authorization or expiry differs from explicit bounds",
            ));
        }
        let saved = self.read_checkpoint(saved_checkpoint)?;
        if saved.slot != s.slot
            || saved.block_hash != s.block_hash
            || saved.block_height != s.height
        {
            return Err(BrowserError::new(
                ErrorCode::SyncRequired,
                "payment must use the exact durable current checkpoint",
            ));
        }
        let mut build_timings_ms = BTreeMap::new();
        build_timings_ms.insert("checkpoint", preparation_timer.ms());
        let build_timer = crate::Timer::start();
        let mut previous_ms = 0;
        let payload = with_prover(|p| {
            p.build_with_metrics(
                self,
                &s.replay.state,
                payer_key.to_bytes(),
                expiry,
                Payment::ShieldedSend {
                    amount,
                    recipient,
                    fee,
                },
                |phase| {
                    let elapsed = build_timer.ms();
                    build_timings_ms.insert(phase.as_str(), elapsed.saturating_sub(previous_ms));
                    previous_ms = elapsed;
                },
            )
            .map_err(err)
        })?;
        build_timings_ms.insert("wallet_build", build_timer.ms());
        let seal_timer = crate::Timer::start();
        let id = crate::hex(&payload_digest(&payload));
        let pending = Pending {
            format: "zolana-browser-native-pending-v1".into(),
            network: self.network().clone(),
            payload: STANDARD.encode(payload),
            payer: payer.into(),
            fee,
            maximum_fee,
            expires_at: expiry,
            created_slot: s.slot,
            created_height: s.height,
            checkpoint_pin: blake2b_simd::Params::new()
                .hash_length(32)
                .hash(saved_checkpoint)
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&pending).map_err(err)?);
        let encrypted = self.seal(PENDING_MAGIC, &plain)?;
        build_timings_ms.insert("seal", seal_timer.ms());
        // Only ciphertext is returned here. The worker must commit its original
        // reservation before asking pending_packet() for the public wire packet.
        Ok(json!({"packet_id":id,"encrypted_pending":encrypted,"amount":amount.to_string(),"fee":fee.to_string(),"expires_at":expiry,"build_timings_ms":build_timings_ms}).to_string())
    }
    fn read_pending(&self, encrypted: &[u8]) -> Result<(Pending, Vec<u8>)> {
        if encrypted.len() > 32768 {
            return Err("pending record exceeds storage bound".into());
        }
        let plain = self.unseal(PENDING_MAGIC, encrypted)?;
        let p: Pending = serde_json::from_slice(&plain).map_err(err)?;
        let bytes = STANDARD.decode(&p.payload).map_err(err)?;
        let pay = wire::decode(self.network().network, &bytes).map_err(err)?;
        let payer = Pubkey::from_str(&p.payer).map_err(err)?;
        if p.format != "zolana-browser-native-pending-v1"
            || p.network != *self.network()
            || p.payload.len() != 12308
            || STANDARD.encode(&bytes) != p.payload
            || !payer.is_on_curve()
            || pay.context.sponsor != payer.to_bytes()
            || pay.context.shielded_fee != Some(p.fee)
            || p.fee == 0
            || p.fee > p.maximum_fee
            || p.maximum_fee > 100_000_000
            || pay.context.expires_at != p.expires_at
        {
            return Err(BrowserError::new(
                ErrorCode::Recovery,
                "pending packet differs from its original authorization",
            ));
        }
        Ok((p, bytes))
    }
    pub fn pending_packet(&self, encrypted: &[u8]) -> Result<String> {
        let (p, bytes) = self.read_pending(encrypted)?;
        Ok(json!({"id":crate::hex(&payload_digest(&bytes)),"packet":{"network":p.network,"payload":p.payload},"created_slot":p.created_slot,"created_height":p.created_height,"expires_at":p.expires_at}).to_string())
    }
    pub fn validate_pending_checkpoint(
        &self,
        encrypted: &[u8],
        checkpoint: &[u8],
    ) -> Result<String> {
        let (p, _) = self.read_pending(encrypted)?;
        let pin: [u8; 32] = blake2b_simd::Params::new()
            .hash_length(32)
            .hash(checkpoint)
            .as_bytes()
            .try_into()
            .unwrap();
        let c = self.read_checkpoint(checkpoint)?;
        if pin != p.checkpoint_pin || c.slot != p.created_slot || c.block_height != p.created_height
        {
            return Err(BrowserError::new(
                ErrorCode::Recovery,
                "pending recovery checkpoint differs from original reservation",
            ));
        }
        self.checkpoint_info(checkpoint)
    }
    pub fn pending_outcome(&self, encrypted: &[u8]) -> Result<String> {
        let (p, bytes) = self.read_pending(encrypted)?;
        let s = self
            .session
            .as_ref()
            .filter(|s| s.verified)
            .ok_or_else(|| {
                BrowserError::new(ErrorCode::SyncRequired, "verified durable sync required")
            })?;
        let id = payload_digest(&bytes);
        if let Some((signature, slot)) = s.accepted.get(&id) {
            return Ok(json!({"packet_id":crate::hex(&id),"decision":"accepted","signature":signature,"slot":slot,"encrypted_receipt":self.seal(b"BRCPT001",&serde_json::to_vec(&json!({"packet_id":crate::hex(&id),"signature":signature,"slot":slot})).map_err(err)?)?}).to_string());
        }
        if s.canonical_from <= p.created_slot.saturating_add(1) && s.slot > p.expires_at {
            return Ok(json!({"packet_id":crate::hex(&id),"decision":"expired-absent","encrypted_receipt":self.seal(b"BRCPT001",&serde_json::to_vec(&json!({"packet_id":crate::hex(&id),"expired_without_execution":true,"through_slot":s.slot,"through_height":s.height})).map_err(err)?)?}).to_string());
        }
        Ok(json!({"packet_id":crate::hex(&id),"decision":"unknown"}).to_string())
    }
}
impl Session {
    fn apply_block(&mut self, block: Block, canonical: bool) -> Result<()> {
        if block.slot <= self.slot
            || block.slot > self.target
            || block.parent_slot != self.slot
            || self
                .block_hash
                .as_ref()
                .is_some_and(|v| v != &block.previous_blockhash)
            || block.block_height <= self.height
        {
            return Err(BrowserError::new(
                ErrorCode::History,
                "finalized block history is incomplete or discontinuous",
            ));
        }
        hash(&block.blockhash)?;
        hash(&block.previous_blockhash)?;
        // With canonical bounded hashes and u64 fields, an empty header is
        // always below 512 encoded bytes. Avoid allocating JSON for each empty
        // block; preserve the existing complete bound for nonempty blocks.
        if !block.transactions.is_empty()
            && serde_json::to_vec(&block).map_err(err)?.len() > 8 * 1024 * 1024
        {
            return Err(BrowserError::new(
                ErrorCode::History,
                "finalized block history is incomplete or discontinuous",
            ));
        }
        for encoded in block.transactions {
            let pair = encoded["transaction"]
                .as_array()
                .ok_or("base64 signed transaction required")?;
            if pair.len() != 2 || pair[1] != "base64" {
                return Err("base64 signed transaction required".into());
            }
            let raw = STANDARD
                .decode(pair[0].as_str().ok_or("transaction missing")?)
                .map_err(err)?;
            if raw.len() > 16384 {
                return Err("native transaction exceeds byte bound".into());
            }
            let tx: VersionedTransaction = bincode::deserialize(&raw).map_err(err)?;
            let loaded = if tx
                .message
                .address_table_lookups()
                .is_some_and(|v| !v.is_empty())
            {
                let l = &encoded["meta"]["loadedAddresses"];
                let parse = |k: &str| -> Result<Vec<[u8; 32]>> {
                    l[k].as_array()
                        .ok_or("loaded addresses unavailable")?
                        .iter()
                        .map(|v| {
                            Pubkey::from_str(v.as_str().ok_or("invalid loaded address")?)
                                .map(|k| k.to_bytes())
                                .map_err(err)
                        })
                        .collect()
                };
                Some(LoadedAddresses {
                    writable: parse("writable")?,
                    readonly: parse("readonly")?,
                })
            } else {
                None
            };
            let Some(auth) = canonical::authenticate(&tx, loaded).map_err(err)? else {
                continue;
            };
            let meta = encoded["meta"]
                .as_object()
                .ok_or("native execution metadata unavailable")?;
            let failed = meta
                .get("err")
                .ok_or("native execution result unavailable")?;
            if !failed.is_null() {
                continue;
            }
            for ix in auth.instructions {
                if let Some(accepted) = self.replay.apply_verified(&ix, block.slot).map_err(err)? {
                    if canonical {
                        self.accepted.insert(
                            accepted.payload_digest().map_err(err)?,
                            (auth.signature.clone(), block.slot),
                        );
                    }
                }
            }
        }
        self.replay.finish_slot(block.slot).map_err(err)?;
        self.slot = block.slot;
        self.height = block.block_height;
        self.block_hash = Some(block.blockhash);
        if !canonical {
            self.canonical_from = self.slot.saturating_add(1);
            self.accepted.clear();
        }
        Ok(())
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn prepare_wallet_prover() -> Result<String> {
    let t = crate::Timer::start();
    with_prover(|_| Ok(json!({"prepared":true,"elapsed_ms":t.ms()}).to_string()))
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = prepare_wallet_prover)]
pub fn js_prepare_wallet_prover() -> std::result::Result<String, JsValue> {
    prepare_wallet_prover().map_err(BrowserError::into_js)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl BrowserVault {
    #[wasm_bindgen(js_name=checkpoint_info)]
    pub fn js_checkpoint_info(&self, b: Vec<u8>) -> std::result::Result<String, JsValue> {
        self.checkpoint_info(&b).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=begin_sync)]
    pub fn js_begin_sync(
        &mut self,
        p: &str,
        h: &str,
        c: Vec<u8>,
        ch: &str,
    ) -> std::result::Result<String, JsValue> {
        self.begin_sync(p, h, &c, ch).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=apply_history_page)]
    pub fn js_apply_history_page(&mut self, p: &str) -> std::result::Result<String, JsValue> {
        self.apply_history_page(p).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=apply_compact_history_page)]
    pub fn js_apply_compact_history_page(
        &mut self,
        metadata: &str,
        headers: Vec<u8>,
    ) -> std::result::Result<String, JsValue> {
        self.apply_compact_history_page(metadata, &headers)
            .map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=apply_canonical_blocks)]
    pub fn js_apply_canonical_blocks(&mut self, p: &str) -> std::result::Result<String, JsValue> {
        self.apply_canonical_blocks(p)
            .map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=apply_archival_page)]
    pub fn js_apply_archival_page(&mut self, p: &str) -> std::result::Result<String, JsValue> {
        self.apply_archival_page(p).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=finish_sync)]
    pub fn js_finish_sync(&mut self) -> std::result::Result<Vec<u8>, JsValue> {
        self.finish_sync().map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=payment_status)]
    pub fn js_payment_status(&self) -> std::result::Result<String, JsValue> {
        self.payment_status().map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=build_payment)]
    pub fn js_build_payment(
        &self,
        r: &str,
        a: u64,
        m: u64,
        q: &str,
        e: u64,
        c: Vec<u8>,
    ) -> std::result::Result<String, JsValue> {
        self.build_payment(r, a, m, q, e, &c)
            .map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=pending_packet)]
    pub fn js_pending_packet(&self, p: Vec<u8>) -> std::result::Result<String, JsValue> {
        self.pending_packet(&p).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=validate_pending_checkpoint)]
    pub fn js_validate_pending_checkpoint(
        &self,
        p: Vec<u8>,
        c: Vec<u8>,
    ) -> std::result::Result<String, JsValue> {
        self.validate_pending_checkpoint(&p, &c)
            .map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=pending_outcome)]
    pub fn js_pending_outcome(&self, p: Vec<u8>) -> std::result::Result<String, JsValue> {
        self.pending_outcome(&p).map_err(BrowserError::into_js)
    }
}
