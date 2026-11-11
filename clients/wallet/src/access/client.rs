//! Wallet-side requests to the configured admission service.
//! These operations construct proofs and validate receipts. Durable membership
//! and quota decisions belong to the authority in the parent module.

use super::{join_body, Join, Proof, Status};
use crate::{connection::TesterProfile, faucet::Claim, keys::WalletKey, Result};
use serde_json::Value;
use solana_signer::Signer;
use std::time::Duration;

fn post(profile: &TesterProfile, suffix: &str, body: Vec<u8>) -> Result<Value> {
    profile.validate()?;
    let endpoint = profile.faucet.as_ref().ok_or("no admission endpoint")?;
    let mut client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20));
    if let Some(pem) = &profile.local_tls_ca_pem {
        client = client.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?);
    }
    let response = client
        .build()?
        .post(format!("{}{suffix}", endpoint.url.trim_end_matches('/')))
        .header("Content-Type", "application/json")
        .body(body)
        .send()?;
    if !response.status().is_success() {
        return Err(match response.status().as_u16(){403=>"Invitation or access is invalid, expired, revoked or already bound to another wallet.",429=>"Testnet request limit reached. Wait before checking the same wallet again.",409=>"Testnet admission capacity reached. An existing grant is preserved.",_=>"Testnet access service unavailable. Your original wallet and grant remain saved."}.into());
    }
    use std::io::Read;
    let mut data = Vec::new();
    response.take(4097).read_to_end(&mut data)?;
    if data.len() > 4096 {
        return Err("admission response exceeds limit".into());
    }
    Ok(serde_json::from_slice(&data)?)
}
pub fn request_join(
    profile: &TesterProfile,
    wallet: &WalletKey,
    invitation: Option<String>,
) -> Result<Value> {
    profile.validate()?;
    let claim = Claim::signed(wallet)?;
    let proof = Proof::signed(
        wallet,
        profile.faucet_audience()?,
        "join",
        &join_body(&claim, invitation.as_deref())?,
    )?;
    let value = post(
        profile,
        "/join",
        serde_json::to_vec(&Join {
            claim: claim.clone(),
            invitation,
            proof,
        })?,
    )?;
    if value["claim_id"] != claim.id() || value["admitted"] != true {
        return Err("invalid admission receipt".into());
    }
    Ok(value)
}
pub fn request_status(profile: &TesterProfile, wallet: &WalletKey) -> Result<Value> {
    profile.validate()?;
    let value = post(
        profile,
        "/status",
        serde_json::to_vec(&Status {
            proof: Proof::signed(wallet, profile.faucet_audience()?, "status", b"")?,
        })?,
    )?;
    if !value["admitted"].is_boolean()
        || value["fee_address"] != wallet.fee_keypair().pubkey().to_string()
    {
        return Err("invalid membership response".into());
    }
    Ok(value)
}
