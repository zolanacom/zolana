//! Explicit public tester configuration. No operator keys or automatic discovery.
use crate::{keys::Network, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub transport: String,
    pub url: String,
}

impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        if self.url.len() > 2048
            || self
                .url
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err("invalid RPC endpoint".into());
        }
        let url = reqwest::Url::parse(&self.url)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.url.contains('@')
            || self.url.contains('\\')
            || url.port() == Some(0)
        {
            return Err(
                "RPC endpoint must not contain credentials, query, fragment or ambiguous authority"
                    .into(),
            );
        }
        match self.transport.as_str() {
            "loopback-http" => {
                let port: u16 = self
                    .url
                    .strip_prefix("http://127.0.0.1:")
                    .ok_or("loopback RPC must use http://127.0.0.1:<port>")?
                    .parse()?;
                if port == 0 {
                    return Err("RPC port must be nonzero".into());
                }
            }
            "https" if url.scheme() == "https" && url.host_str().is_some() => {}
            _ => return Err("remote RPC requires explicit HTTPS transport".into()),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TesterProfile {
    pub format: String,
    pub label: String,
    pub key_mode: String,
    pub network: [u8; 32],
    pub genesis_hash: String,
    pub program: String,
    pub pool: String,
    pub pool_format: String,
    pub recipient_withdrawals: bool,
    pub rpc: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet: Option<Endpoint>,
}

impl TesterProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() > 8192 {
            return Err("tester profile exceeds 8 KiB".into());
        }
        let profile: Self = serde_json::from_slice(&bytes)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn network(&self) -> Network {
        Network {
            network: self.network,
            genesis_hash: self.genesis_hash.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != "native-wallet-profile-v1"
            || self.key_mode != "user-wallet-v1"
            || self.label.is_empty()
            || self.label.len() > 64
            || !self
                .label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " ._-".contains(c))
            || self.pool_format != "NPOOL003"
            || self.program != native_payment_program::id().to_string()
            || self.pool != native_payment_program::pool_address().to_string()
            || !self.recipient_withdrawals
        {
            return Err("invalid or incompatible tester profile".into());
        }
        self.network().validate()?;
        self.rpc.validate()?;
        if let Some(endpoint) = &self.faucet {
            endpoint.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_rejects_unknown_fields_wrong_protocol_and_invalid_domain() {
        let profile = TesterProfile {
            format: "native-wallet-profile-v1".into(),
            label: "Invited testers".into(),
            key_mode: "user-wallet-v1".into(),
            network: [7; 32],
            genesis_hash: "11111111111111111111111111111111".into(),
            program: native_payment_program::id().to_string(),
            pool: native_payment_program::pool_address().to_string(),
            pool_format: "NPOOL003".into(),
            recipient_withdrawals: true,
            faucet: None,
            rpc: Endpoint {
                transport: "https".into(),
                url: "https://rpc.example.invalid".into(),
            },
        };
        profile.validate().unwrap();
        let mut value = serde_json::to_value(&profile).unwrap();
        value["sponsor"] = "unwanted operator".into();
        assert!(serde_json::from_value::<TesterProfile>(value).is_err());
        for invalid in [
            TesterProfile {
                network: [0; 32],
                ..profile.clone()
            },
            TesterProfile {
                pool_format: "NPOOL002".into(),
                ..profile.clone()
            },
            TesterProfile {
                program: profile.pool.clone(),
                ..profile.clone()
            },
            TesterProfile {
                recipient_withdrawals: false,
                ..profile.clone()
            },
            TesterProfile {
                faucet: Some(Endpoint {
                    transport: "https".into(),
                    url: "http://untrusted.invalid".into(),
                }),
                ..profile.clone()
            },
            TesterProfile {
                label: "<script>untrusted</script>".into(),
                ..profile.clone()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
        let duplicate =
            serde_json::to_string(&profile)
                .unwrap()
                .replacen('{', "{\"label\":\"Other\",", 1);
        assert!(serde_json::from_str::<TesterProfile>(&duplicate).is_err());
    }

    #[test]
    fn rejects_transport_downgrades_credentials_and_ambiguous_urls() {
        for (transport, url) in [
            ("https", "http://example.invalid"),
            ("http", "http://example.invalid"),
            (
                "https",
                concat!("https://user:secret", "@", "example.invalid"),
            ),
            ("https", "https://example.invalid?api-key=secret"),
            ("https", "https://example.invalid/#fragment"),
            ("https", "https://example.invalid:0"),
            ("https", "https://example.invalid\\@elsewhere.invalid"),
            ("https", " https://example.invalid"),
            ("loopback-http", "http://localhost:18899"),
            ("loopback-http", "http://127.0.0.1:18899/"),
            ("loopback-http", "http://127.0.0.1:0"),
            (
                "loopback-http",
                concat!("http://127.0.0.1:18899", "@", "evil.invalid"),
            ),
        ] {
            assert!(
                Endpoint {
                    transport: transport.into(),
                    url: url.into()
                }
                .validate()
                .is_err(),
                "{url}"
            );
        }
        for (transport, url) in [
            ("https", "https://rpc.example.invalid/native"),
            ("loopback-http", "http://127.0.0.1:18899"),
        ] {
            Endpoint {
                transport: transport.into(),
                url: url.into(),
            }
            .validate()
            .unwrap();
        }
    }
}
