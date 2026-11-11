//! Construction and verification of the existing signed admission proof.
//! Field layout, domain separation and expiry checks remain shared by both
//! the wallet request path and the durable admission authority.

use super::{digest, now, Policy, Proof};
use crate::{keys::WalletKey, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;

impl Proof {
    fn message(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "native-invited-access-v1",
            &self.purpose,
            &self.network,
            &self.audience,
            &self.fee_address,
            self.issued_at,
            self.expires_at,
            &self.nonce,
            &self.body_digest,
        ))?)
    }
    pub fn signed(wallet: &WalletKey, audience: &str, purpose: &str, body: &[u8]) -> Result<Self> {
        Self::signed_at(wallet, audience, purpose, body, now()?)
    }
    pub(super) fn signed_at(
        wallet: &WalletKey,
        audience: &str,
        purpose: &str,
        body: &[u8],
        time: u64,
    ) -> Result<Self> {
        let mut proof = Self {
            purpose: purpose.into(),
            network: wallet.network.clone(),
            audience: audience.into(),
            fee_address: wallet.fee_keypair().pubkey().to_string(),
            issued_at: time,
            expires_at: time.checked_add(600).ok_or("clock overflow")?,
            nonce: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>()),
            body_digest: digest(body),
            signature: String::new(),
        };
        proof.signature = wallet
            .fee_keypair()
            .sign_message(&proof.message()?)
            .to_string();
        Ok(proof)
    }
    pub(super) fn verify(
        &self,
        policy: &Policy,
        purpose: &str,
        body: &[u8],
        time: u64,
    ) -> Result<()> {
        let audience = if purpose == "rpc" {
            &policy.rpc_audience
        } else {
            &policy.faucet_audience
        };
        if self.network != policy.network
            || self.purpose != purpose
            || &self.audience != audience
            || self.nonce.len() != 32
            || self.body_digest != digest(body)
            || self.expires_at != self.issued_at.checked_add(600).ok_or("clock overflow")?
            || self.issued_at > time.saturating_add(30)
            || self.expires_at <= time
        {
            return Err("access proof invalid or expired".into());
        }
        let key: Pubkey = self.fee_address.parse()?;
        if !key.is_on_curve()
            || !self
                .signature
                .parse::<Signature>()?
                .verify(key.as_ref(), &self.message()?)
        {
            return Err("access proof signature invalid".into());
        }
        Ok(())
    }
    pub fn header(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?))
    }
}
