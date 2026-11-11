//! Wallet-side test-grant request and receipt validation.

use super::Claim;
use crate::{connection::TesterProfile, keys::WalletKey, Result};
use serde_json::Value;
use std::time::Duration;

pub fn request(profile: &TesterProfile, wallet: &WalletKey) -> Result<Value> {
    profile.validate()?;
    if profile.invite_required {
        return crate::access::request_join(profile, wallet, None);
    }
    let endpoint = profile
        .faucet
        .as_ref()
        .ok_or("this profile has no test faucet")?;
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let reply = client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&Claim::signed(wallet)?)?)
        .send()?;
    if reply.status().as_u16() == 409 {
        return Err(
            "the test faucet has no grants left; an existing claim can still be checked".into(),
        );
    }
    if reply.status().as_u16() == 429 {
        return Err("please check the same test claim again in a moment".into());
    }
    if !reply.status().is_success() {
        return Err(format!(
            "test faucet unavailable (HTTP {}); checking again reuses the same claim",
            reply.status()
        )
        .into());
    }
    use std::io::Read;
    let mut body = Vec::new();
    reply.take(4097).read_to_end(&mut body)?;
    if body.len() > 4096 {
        return Err("faucet response exceeds limit".into());
    }
    let response: Value = serde_json::from_slice(&body)?;
    if response["claim_id"] != Claim::signed(wallet)?.id()
        || !matches!(
            response["state"].as_str(),
            Some("queued" | "funding" | "ready" | "needs_attention")
        )
    {
        return Err("invalid faucet receipt".into());
    }
    Ok(response)
}
