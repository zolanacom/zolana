//! Conservative lifetime reservations, committed before any sponsor signature.
//! Reservations are never automatically refunded, even after failed/unknown work.
use crate::{
    keys::{read_private, write_private_new, Network},
    operation::WalletOperation,
    Result,
};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use std::{
    cell::RefCell,
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub format: String,
    pub network: Network,
    pub sponsor: String,
    pub operation_allowance: u64,
    pub lifetime_allowance: u64,
    pub max_deposit: u64,
    pub max_send: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_withdraw: Option<u64>,
    pub max_requests_per_wallet: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    request: String,
    wallet: String,
    kind: String,
    allowance: u64,
    charged: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    policy: Policy,
    reserved: u64,
    requests: Vec<Reservation>,
}

pub struct Budget {
    _lock: WalletOperation,
    ledger: RefCell<Ledger>,
    path: PathBuf,
    index: usize,
    request: String,
}
fn ledger_path(policy: &Path) -> PathBuf {
    PathBuf::from(format!("{}.reservations.json", policy.display()))
}
fn digest(raw: &[u8]) -> String {
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(raw)
        .to_hex()
        .to_string()
}
impl Policy {
    fn validate(&self) -> Result<()> {
        self.network.validate()?;
        self.sponsor.parse::<Pubkey>()?;
        if self.format != "native-sponsor-policy-v1"
            || self.operation_allowance == 0
            || self.lifetime_allowance < self.operation_allowance
            || self.max_deposit == 0
            || self.max_send == 0
            || self.max_withdraw == Some(0)
            || !(1..=1000).contains(&self.max_requests_per_wallet)
        {
            return Err("invalid sponsor policy".into());
        }
        Ok(())
    }
    pub fn create(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let ledger = ledger_path(path);
        if path.exists() || ledger.exists() {
            return Err("sponsor policy or ledger already exists".into());
        }
        // A partial setup is unusable, never interpreted as an empty budget.
        write_private_new(
            &ledger,
            &serde_json::to_vec_pretty(&Ledger {
                policy: self.clone(),
                reserved: 0,
                requests: vec![],
            })?,
        )?;
        write_private_new(path, &serde_json::to_vec_pretty(self)?)?;
        fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(())
    }
}
impl Budget {
    pub fn reserve(
        path: &Path,
        network: &Network,
        sponsor: &Pubkey,
        wallet: &str,
        kind: &str,
        amount: u64,
        request: &str,
    ) -> Result<Self> {
        let (lock, policy, mut ledger) = Self::load(path, network, sponsor)?;
        if !(16..=128).contains(&request.len())
            || !request
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("sponsor request ID must be 16..128 ASCII letters/digits/hyphens".into());
        }
        match kind {
            "deposit" if amount > 0 && amount <= policy.max_deposit => (),
            "send" if amount > 0 && amount <= policy.max_send => (),
            "withdraw"
                if amount > 0 && policy.max_withdraw.is_some_and(|limit| amount <= limit) => {}
            _ => {
                return Err(
                    "sponsor action or amount exceeds policy; withdrawals are not sponsored".into(),
                )
            }
        }
        let request_text = request.to_owned();
        let request = digest(request.as_bytes());
        let wallet = digest(wallet.as_bytes());
        if ledger.requests.iter().any(|r| r.request == request) {
            return Err("sponsor request was already reserved; resolve/reclaim original work, never retry it as new".into());
        }
        if ledger.requests.len() >= 10_000 {
            return Err("sponsor reservation capacity exhausted".into());
        }
        if ledger
            .requests
            .iter()
            .filter(|r| r.wallet == wallet)
            .count()
            >= policy.max_requests_per_wallet
        {
            return Err("wallet sponsor allowance exhausted".into());
        }
        let reserved = ledger
            .reserved
            .checked_add(policy.operation_allowance)
            .ok_or("reservation overflow")?;
        if reserved > policy.lifetime_allowance {
            return Err("sponsor lifetime allowance exhausted".into());
        }
        ledger.requests.push(Reservation {
            request,
            wallet,
            kind: kind.into(),
            allowance: policy.operation_allowance,
            charged: 0,
        });
        ledger.reserved = reserved;
        let ledger_path = ledger_path(path);
        replace(&ledger_path, &serde_json::to_vec_pretty(&ledger)?)?;
        let index = ledger.requests.len() - 1;
        Ok(Self {
            _lock: lock,
            ledger: RefCell::new(ledger),
            path: ledger_path,
            index,
            request: request_text,
        })
    }
    fn load(
        path: &Path,
        network: &Network,
        sponsor: &Pubkey,
    ) -> Result<(WalletOperation, Policy, Ledger)> {
        let lock = WalletOperation::acquire(path)?;
        let policy: Policy = serde_json::from_slice(&read_private(path, 4096)?)?;
        policy.validate()?;
        if policy.network != *network || policy.sponsor != sponsor.to_string() {
            return Err("sponsor policy network/signer mismatch".into());
        }
        let ledger_path = ledger_path(path);
        let ledger: Ledger = serde_json::from_slice(&read_private(&ledger_path, 4 * 1024 * 1024)?)?;
        let sum = ledger.requests.iter().try_fold(0u64, |n, r| {
            n.checked_add(r.allowance).ok_or("reservation overflow")
        })?;
        if ledger.policy != policy
            || ledger.reserved != sum
            || ledger.reserved > policy.lifetime_allowance
            || ledger.requests.len() > 10_000
            || ledger.requests.iter().any(|r| {
                r.allowance != policy.operation_allowance
                    || r.charged > r.allowance
                    || match r.kind.as_str() {
                        "deposit" | "send" => false,
                        "withdraw" => policy.max_withdraw.is_none(),
                        _ => true,
                    }
            })
        {
            return Err(
                "invalid or changed sponsor reservation ledger; operator recovery required".into(),
            );
        }

        let ids: std::collections::BTreeSet<_> =
            ledger.requests.iter().map(|r| &r.request).collect();
        if ids.len() != ledger.requests.len() {
            return Err("duplicate sponsor ledger identities".into());
        }
        Ok((lock, policy, ledger))
    }
    /// Cleanup can consume only the original reservation's remaining allowance.
    pub fn recover(
        path: &Path,
        network: &Network,
        sponsor: &Pubkey,
        wallet: &str,
        request: &str,
    ) -> Result<Self> {
        let (lock, _, ledger) = Self::load(path, network, sponsor)?;
        let index = ledger
            .requests
            .iter()
            .position(|r| {
                r.request == digest(request.as_bytes()) && r.wallet == digest(wallet.as_bytes())
            })
            .ok_or("original wallet sponsor reservation is missing")?;
        Ok(Self {
            _lock: lock,
            ledger: RefCell::new(ledger),
            path: ledger_path(path),
            index,
            request: request.into(),
        })
    }
    pub(crate) fn request_id(&self) -> &str {
        &self.request
    }
    pub(crate) fn charge(&self, debit: u64) -> Result<()> {
        let mut ledger = self.ledger.borrow_mut();
        let r = &mut ledger.requests[self.index];
        let charged = r
            .charged
            .checked_add(debit)
            .filter(|n| *n <= r.allowance)
            .ok_or("transaction would exceed reserved sponsor gross-debit allowance")?;
        r.charged = charged;
        // Persist potential debit before broadcast. Unknown/failed execution never
        // releases a charge, and a restored sponsor key cannot reset this journal.
        replace(&self.path, &serde_json::to_vec_pretty(&*ledger)?)
    }
}
pub(crate) fn replace(path: &Path, raw: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("reservation-{:032x}.tmp", rand::random::<u128>()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(raw)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    #[test]
    fn withdrawal_reservations_reopen_for_cleanup_without_resetting_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy");
        let key = Keypair::new();
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([4; 32]).into_string(),
        };
        Policy {
            format: "native-sponsor-policy-v1".into(),
            network: network.clone(),
            sponsor: key.pubkey().to_string(),
            operation_allowance: 10,
            lifetime_allowance: 20,
            max_deposit: 100,
            max_send: 1000,
            max_withdraw: Some(1000),
            max_requests_per_wallet: 2,
        }
        .create(&path)
        .unwrap();
        let reserve = |amount, request| {
            Budget::reserve(
                &path,
                &network,
                &key.pubkey(),
                "owner",
                "withdraw",
                amount,
                request,
            )
        };
        assert!(reserve(0, "withdraw-request-0001").is_err());
        assert!(reserve(1001, "withdraw-request-0001").is_err());
        let first = reserve(1000, "withdraw-request-0001").unwrap();
        first.charge(3).unwrap();
        drop(first);
        let recovered = Budget::recover(
            &path,
            &network,
            &key.pubkey(),
            "owner",
            "withdraw-request-0001",
        )
        .unwrap();
        recovered.charge(7).unwrap();
        assert!(recovered.charge(1).is_err());
        drop(recovered);
        assert!(reserve(1, "withdraw-request-0001").is_err());
        drop(reserve(1, "withdraw-request-0002").unwrap());
        assert!(reserve(1, "withdraw-request-0003").is_err());
        let ledger: Ledger =
            serde_json::from_slice(&fs::read(ledger_path(&path)).unwrap()).unwrap();
        assert_eq!(ledger.reserved, 20);
        assert_eq!(ledger.requests[0].charged, 10);
        assert_eq!(ledger.requests.len(), 2);
    }
    #[test]
    fn reservations_survive_drop_reject_duplicates_concurrency_tampering_and_exhaustion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy");
        let key = Keypair::new();
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([4; 32]).into_string(),
        };
        let p = Policy {
            format: "native-sponsor-policy-v1".into(),
            network: network.clone(),
            sponsor: key.pubkey().to_string(),
            operation_allowance: 10,
            lifetime_allowance: 20,
            max_deposit: 100,
            max_send: 1000,
            max_withdraw: None,
            max_requests_per_wallet: 1,
        };
        // Existing policies omit this field and continue to deny withdrawals.
        assert!(serde_json::to_value(&p)
            .unwrap()
            .get("max_withdraw")
            .is_none());
        p.create(&path).unwrap();
        let reserve =
            |who, id| Budget::reserve(&path, &network, &key.pubkey(), who, "deposit", 100, id);
        assert!(Budget::reserve(
            &path,
            &network,
            &Keypair::new().pubkey(),
            "a",
            "deposit",
            100,
            "request-00000001"
        )
        .is_err());
        assert!(Budget::reserve(
            &path,
            &network,
            &key.pubkey(),
            "a",
            "withdraw",
            1,
            "request-00000001"
        )
        .is_err());
        let first = reserve("a", "request-00000001").unwrap();
        assert!(reserve("b", "request-00000002").is_err());
        first.charge(7).unwrap();
        assert!(first.charge(4).is_err());
        drop(first);
        assert!(Budget::recover(
            &path,
            &network,
            &key.pubkey(),
            "wrong-wallet",
            "request-00000001"
        )
        .is_err());
        let recovery =
            Budget::recover(&path, &network, &key.pubkey(), "a", "request-00000001").unwrap();
        assert!(recovery.charge(4).is_err());
        recovery.charge(3).unwrap();
        drop(recovery);
        assert!(reserve("b", "request-00000001").is_err());
        assert!(reserve("a", "request-00000002").is_err());
        drop(reserve("b", "request-00000002").unwrap());
        assert!(reserve("c", "request-00000003").is_err());
        fs::remove_file(ledger_path(&path)).unwrap();
        assert!(reserve("c", "request-00000003").is_err());
        assert!(p.create(&path).is_err());
    }
}
