//! Existing invited test access, signed inside the opaque local vault.
//! RPC headers are a ten-minute capability over an empty body, exactly as in
//! the native client. They are not private payment authorization or anonymity.
#[cfg(target_arch = "wasm32")]
use crate::error::BrowserError;
use crate::{error::Result, vault::BrowserVault};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::Signer;
use native_wallet_seed::Network;
use serde::Serialize;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct Proof {
    purpose: String,
    network: Network,
    audience: String,
    fee_address: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
    body_digest: String,
    signature: String,
}
#[derive(Serialize)]
struct Claim {
    format: &'static str,
    network: Network,
    private_address: String,
    fee_address: String,
    signature: String,
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| "cannot encode access request".into())
}
fn check_audience(value: &str) -> Result<()> {
    let host = value
        .strip_prefix("https://")
        .ok_or("invited audience must be explicit HTTPS")?;
    if host.is_empty()
        || value.len() > 2048
        || host.starts_with('/')
        || value
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b"@\\?#".contains(&b))
    {
        return Err("invalid invited audience".into());
    }
    Ok(())
}
impl BrowserVault {
    pub fn admission_claim_id(&self) -> Result<String> {
        Ok(blake2b_simd::Params::new()
            .hash_length(32)
            .hash(self.identity()?.fee_address.as_bytes())
            .to_hex()
            .to_string())
    }
    fn access_proof(&self, audience: &str, purpose: &str, body: &[u8], now: u64) -> Result<Proof> {
        check_audience(audience)?;
        let signer = self.fee_authority()?;
        let fee_address = bs58::encode(signer.verifying_key().to_bytes()).into_string();
        let mut proof = Proof {
            purpose: purpose.into(),
            network: self.network().clone(),
            audience: audience.into(),
            fee_address,
            issued_at: now,
            expires_at: now.checked_add(600).ok_or("clock overflow")?,
            nonce: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>()),
            body_digest: blake2b_simd::Params::new()
                .hash_length(32)
                .hash(body)
                .to_hex()
                .to_string(),
            signature: String::new(),
        };
        let message = encode(&(
            "native-invited-access-v1",
            &proof.purpose,
            &proof.network,
            &proof.audience,
            &proof.fee_address,
            proof.issued_at,
            proof.expires_at,
            &proof.nonce,
            &proof.body_digest,
        ))?;
        proof.signature = bs58::encode(signer.sign(&message).to_bytes()).into_string();
        Ok(proof)
    }
    pub fn rpc_header(&self, audience: &str, now: u64) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(encode(&self.access_proof(audience, "rpc", b"", now)?)?))
    }
    pub fn admission_request(
        &self,
        audience: &str,
        invitation: Option<String>,
        now: u64,
    ) -> Result<String> {
        if invitation
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 512 || v.chars().any(char::is_control))
        {
            return Err("invalid invitation length".into());
        }
        let identity = self.identity()?;
        let mut claim = Claim {
            format: "native-test-grant-v1",
            network: self.network().clone(),
            private_address: identity.private_address,
            fee_address: identity.fee_address,
            signature: String::new(),
        };
        let message = encode(&(
            "native-test-grant-v1",
            &claim.network,
            &claim.private_address,
            &claim.fee_address,
        ))?;
        claim.signature =
            bs58::encode(self.fee_authority()?.sign(&message).to_bytes()).into_string();
        let body = encode(&(&claim, invitation.as_deref()))?;
        let proof = self.access_proof(audience, "join", &body, now)?;
        #[derive(Serialize)]
        struct Join {
            claim: Claim,
            invitation: Option<String>,
            proof: Proof,
        }
        String::from_utf8(encode(&Join {
            claim,
            invitation,
            proof,
        })?)
        .map_err(|_| "invalid JSON encoding".into())
    }
    pub fn admission_status(&self, audience: &str, now: u64) -> Result<String> {
        #[derive(Serialize)]
        struct Status {
            proof: Proof,
        }
        String::from_utf8(encode(&Status {
            proof: self.access_proof(audience, "status", b"", now)?,
        })?)
        .map_err(|_| "invalid JSON encoding".into())
    }
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl BrowserVault {
    #[wasm_bindgen(js_name=admission_claim_id)]
    pub fn js_admission_claim_id(&self) -> std::result::Result<String, JsValue> {
        self.admission_claim_id().map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=rpc_header)]
    pub fn js_rpc_header(&self, audience: &str, now: u64) -> std::result::Result<String, JsValue> {
        self.rpc_header(audience, now)
            .map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=admission_request)]
    pub fn js_admission_request(
        &self,
        audience: &str,
        invitation: Option<String>,
        now: u64,
    ) -> std::result::Result<String, JsValue> {
        self.admission_request(audience, invitation, now)
            .map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name=admission_status)]
    pub fn js_admission_status(
        &self,
        audience: &str,
        now: u64,
    ) -> std::result::Result<String, JsValue> {
        self.admission_status(audience, now)
            .map_err(BrowserError::into_js)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    fn wallet() -> BrowserVault {
        BrowserVault::create(
            &serde_json::json!({"network":vec![7u8;32],"genesis_hash":"1".repeat(32)}).to_string(),
            b"disposable browser access password".to_vec(),
        )
        .unwrap()
    }
    fn verify(proof: &serde_json::Value, body: &[u8]) {
        assert_eq!(
            proof["body_digest"],
            blake2b_simd::Params::new()
                .hash_length(32)
                .hash(body)
                .to_hex()
                .to_string()
        );
        let network: Network = serde_json::from_value(proof["network"].clone()).unwrap();
        let bytes = serde_json::to_vec(&(
            "native-invited-access-v1",
            &proof["purpose"],
            &network,
            &proof["audience"],
            &proof["fee_address"],
            &proof["issued_at"],
            &proof["expires_at"],
            &proof["nonce"],
            &proof["body_digest"],
        ))
        .unwrap();
        let key: [u8; 32] = bs58::decode(proof["fee_address"].as_str().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let sig: [u8; 64] = bs58::decode(proof["signature"].as_str().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&key)
            .unwrap()
            .verify(&bytes, &Signature::from_bytes(&sig))
            .unwrap();
    }
    #[test]
    fn signed_requests_bind_existing_native_shapes_and_fail_locked() {
        let mut w = wallet();
        let rpc = w.rpc_header("https://127.0.0.1:39443", 100).unwrap();
        let p: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(rpc).unwrap()).unwrap();
        verify(&p, b"");
        assert_eq!(p["expires_at"], 700);
        let j: serde_json::Value = serde_json::from_str(
            &w.admission_request(
                "https://127.0.0.1:39444",
                Some("disposable-invite".into()),
                100,
            )
            .unwrap(),
        )
        .unwrap();
        // Recreate native Claim's explicit field order; JSON Value map sorting
        // is not an equivalent authorization encoding.
        let c = &j["claim"];
        let claim = Claim {
            format: "native-test-grant-v1",
            network: w.network().clone(),
            private_address: c["private_address"].as_str().unwrap().into(),
            fee_address: c["fee_address"].as_str().unwrap().into(),
            signature: c["signature"].as_str().unwrap().into(),
        };
        verify(
            &j["proof"],
            &encode(&(&claim, Some("disposable-invite"))).unwrap(),
        );
        w.lock();
        assert!(w.rpc_header("https://127.0.0.1:39443", 100).is_err());
        assert!(w.admission_status("https://127.0.0.1:39444", 100).is_err());
    }
    #[test]
    fn invalid_audience_and_clock_refused() {
        let w = wallet();
        for a in [
            "http://example.org",
            "https://a@b",
            "https://a/?x=1",
            "https://",
            "https:///a",
        ] {
            assert!(w.rpc_header(a, 1).is_err());
        }
        assert!(w.rpc_header("https://example.org", u64::MAX).is_err());
    }
}
