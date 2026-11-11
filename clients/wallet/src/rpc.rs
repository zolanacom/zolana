//! Native-wallet RPC connection and shared result types.
//! History, fee policy and staged payment operations live in private modules.
mod archival;
pub mod fast;
mod fee_policy;
mod fetch;
pub mod native;
mod reads;
mod retained;
mod scan;
mod staged_payment;
use crate::{
    history::{Replay, WalletState},
    keys::{Network, WalletKey},
    Result,
};
use native_payment_program::{id, pool_address};
use native_payments::{staging::payload_digest, state::PoolState, wire};
use serde::{Deserialize, Serialize};
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_rpc_client::{
    http_sender::HttpSender,
    rpc_client::{RpcClient, RpcClientConfig},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

/// Configured RPC connection and authorization policy shared by wallet operations.
pub struct Chain {
    pub(crate) rpc: RpcClient,
    network: Network,
    sponsor_budget: Option<crate::sponsor::Budget>,
    user_fees: Option<(Pubkey, u64, std::path::PathBuf)>,
    history_batches: bool,
    retained_history_v2: bool,
    standard_reads: Option<reads::StandardReads>,
    verification_key: Option<std::sync::Arc<orchard::circuit::VerifyingKey>>,
    pool_format: &'static str,
}

/// Verified wallet state at one finalized checkpoint, including recovery evidence.
pub struct Synced {
    pub state: WalletState,
    pub slot: u64,
    pub block_height: u64,
    accepted_finalizations: BTreeSet<String>,
    canonical_from_slot: u64,
    withdrawals: BTreeMap<String, crate::payments::WithdrawalReceipt>,
    finalizations: BTreeMap<String, (String, bool)>,
    payment_digests: BTreeMap<String, [u8; 32]>,
    payment_slots: BTreeMap<String, u64>,
    pub scan: ScanStats,
}

/// Timing and coverage counters collected during one wallet-history scan.
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
    pub cache_read_ms: u128,
    pub cache_write_ms: u128,
    pub pool_rpc_ms: u128,
    pub checkpoint_rpc_ms: u128,
    /// Wall time for joined pool/header reads; their individual times overlap.
    pub scan_control_rpc_ms: u128,
    pub block_range_rpc_ms: u128,
    pub block_range_rpc_requests: usize,
    pub history_page_fallbacks: usize,
    pub from_slot: u64,
    pub cache_reset: Option<String>,
    pub history_blocks_read: usize,
}

/// Mutable replay state retained until every requested wallet reaches the target.
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
    payment_digests: BTreeMap<String, [u8; 32]>,
    payment_slots: BTreeMap<String, u64>,
    scan: ScanStats,
}

/// Existing pending-payment JSON format. Fields also decode older wallet journals.
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

/// Existing staging-recovery JSON format, retained across process interruptions.
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

/// Accepted staged-payment receipt, including the independent cleanup result.
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
        )?
        .with_pool_format(&profile.pool_format)
    }

    pub fn connect_invited(
        profile: &crate::connection::TesterProfile,
        wallet: &WalletKey,
    ) -> Result<Self> {
        profile.validate()?;
        let proof = crate::access::Proof::signed(wallet, profile.rpc_audience(), "rpc", b"")?;
        Self::connect_authenticated(
            &profile.rpc.url,
            profile.network(),
            Some(proof.header()?),
            None,
            profile.local_tls_ca_pem.as_deref(),
        )?
        .with_pool_format(&profile.pool_format)
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
            // The invited gateway expires idle connections after five seconds.
            // Keep only the two bounded history workers' sockets, and retire
            // them first rather than racing a server-side idle close.
            .pool_max_idle_per_host(fetch::WORKERS)
            .pool_idle_timeout(Duration::from_secs(4))
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
        let standard_reads = Some(reads::StandardReads::new(url, http.clone()));
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
            retained_history_v2: false,
            standard_reads,
            verification_key: None,
            pool_format: "NPOOL003",
        })
    }

    /// Explicit profile opt-in. This does not change a network, wallet or cache.
    pub fn with_pool_format(mut self, pool_format: &str) -> Result<Self> {
        self.pool_format = match pool_format {
            "NPOOL003" => "NPOOL003",
            "NPOOL004" => "NPOOL004",
            _ => return Err("unsupported native pool profile format".into()),
        };
        Ok(self)
    }

    /// Explicit invited-profile opt-in; there is no endpoint discovery or
    /// authorization-error fallback to another history protocol.
    pub fn with_retained_history_format(mut self, format: Option<&str>) -> Result<Self> {
        self.retained_history_v2 = match format {
            None => false,
            Some("compact-v2")
                if self.history_batches
                    && reqwest::Url::parse(&self.rpc.url())?.scheme() == "https" =>
            {
                true
            }
            _ => {
                return Err("compact retained history requires an invited HTTPS connection".into())
            }
        };
        Ok(self)
    }

    pub(crate) fn check_pool_format(&self, pool: &PoolState) -> Result<()> {
        if pool.uses_slot_anchors() != (self.pool_format == "NPOOL004") {
            return Err(
                "native pool state does not match the explicit wallet profile format".into(),
            );
        }
        Ok(())
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
        self.check_pool_format(&pool)?;
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
            "finalized_slot":response.context.slot, "pool_format":self.pool_format, "recipient_withdrawals":true}),
        )
    }

    pub fn validate_shielded_payload(&self, bytes: &[u8]) -> Result<()> {
        let payment = wire::decode(self.network.network, bytes)?;
        if payment.context.shielded_fee.is_none() {
            return Err("shielded fee required".into());
        }
        let current = self
            .rpc
            .get_account_with_commitment(&pool_address(), CommitmentConfig::confirmed())?;
        let pool = current.value.ok_or("pool missing")?;
        if pool.owner != id() {
            return Err("pool owner mismatch".into());
        }
        let state = PoolState::decode(&pool.data)?;
        self.check_pool_format(&state)?;
        let addresses: Vec<_> = payment
            .bundle
            .actions()
            .iter()
            .map(|a| native_payment_program::nullifiers::address(&a.nullifier().to_bytes()))
            .collect();
        let markers = self
            .rpc
            .get_multiple_accounts_with_commitment(&addresses, CommitmentConfig::confirmed())?;
        if markers.value.len() != 2
            || markers
                .value
                .iter()
                .flatten()
                .any(|a| a.owner != solana_sdk_ids::system_program::id() || !a.data.is_empty())
        {
            return Err("nullifier spent or unavailable".into());
        }
        native_payments::verification::PaymentVerifier::new(
            self.network.network,
            orchard::circuit::VerifyingKey::build(
                native_payments::verification::bundle_version().circuit_version(),
            ),
        )?
        .verify(
            &payment.bundle,
            &payment.context,
            &native_payments::verification::ValidationView {
                current_slot: current.context.slot,
                accepted_anchors: &state.accepted_roots(current.context.slot)?,
                spent_nullifiers: &BTreeSet::new(),
                authorized_public_value_balance: payment.context.public_value_balance,
            },
        )?;
        Ok(())
    }

    pub fn relay_rpc(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        if ![
            "getShieldedFeeQuote",
            "submitShieldedPayment",
            "getShieldedPaymentStatus",
        ]
        .contains(&method)
        {
            return Err("unsupported shielded relay method".into());
        }
        Ok(self.rpc.send(
            solana_rpc_client_api::request::RpcRequest::Custom { method },
            params,
        )?)
    }

    /// Full canonical replay authenticates the exact proof, not a relay status assertion.
    pub fn shielded_outcome(
        &self,
        wallet: &WalletKey,
        bytes: &[u8],
        signature: Option<&str>,
    ) -> Result<serde_json::Value> {
        let payment = wire::decode(self.network.network, bytes)?;
        if payment.context.shielded_fee.is_none() {
            return Err("shielded fee required".into());
        }
        let synced = self
            .scan_source_mode(&[wallet], None, None, None, false)?
            .finish()
            .pop()
            .ok_or("missing canonical recovery state")?;
        let digest = payload_digest(bytes);
        let canonical = synced
            .payment_digests
            .iter()
            .find(|(_, value)| **value == digest);
        if let Some((original, _)) = canonical {
            if signature.is_some_and(|s| s != original) {
                return Err("relay signature differs from canonical payment".into());
            }
            let execution_slot = synced
                .payment_slots
                .get(original)
                .ok_or("canonical payment slot is unavailable")?;
            return Ok(
                serde_json::json!({"accepted":true,"signature":original,"shielded_fee":payment.context.shielded_fee,
                "execution_slot":execution_slot,
                "balance":synced.state.balance()?,"expires_at":payment.context.expires_at}),
            );
        }
        if synced.slot > payment.context.expires_at {
            return Ok(
                serde_json::json!({"accepted":false,"expired_without_execution":true,"balance":synced.state.balance()?}),
            );
        }
        Err(
            "shielded payment remains unresolved; original proof retained, no new spend authorized"
                .into(),
        )
    }
}

#[cfg(test)]
mod recovery_tests;
