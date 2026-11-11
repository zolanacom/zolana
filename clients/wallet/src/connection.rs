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

/// Explicit client transport migration; signed audiences remain authority-bound.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessAudiences {
    pub format: String,
    pub network: [u8; 32],
    pub genesis_hash: String,
    pub rpc: String,
    pub faucet: String,
}

fn explicit_access_audiences<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<AccessAudiences>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Omission preserves legacy behavior; an explicit null is not a fallback.
    AccessAudiences::deserialize(deserializer).map(Some)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_send_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_history_format: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "explicit_access_audiences"
    )]
    pub access_audiences: Option<AccessAudiences>,
    pub recipient_withdrawals: bool,
    pub rpc: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet: Option<Endpoint>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invite_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_tls_ca_pem: Option<String>,
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

    pub fn rpc_audience(&self) -> &str {
        self.access_audiences
            .as_ref()
            .map_or(self.rpc.url.as_str(), |value| value.rpc.as_str())
    }

    pub fn faucet_audience(&self) -> Result<&str> {
        let endpoint = self.faucet.as_ref().ok_or("no admission endpoint")?;
        Ok(self
            .access_audiences
            .as_ref()
            .map_or(endpoint.url.as_str(), |value| value.faucet.as_str()))
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
            || !matches!(self.pool_format.as_str(), "NPOOL003" | "NPOOL004")
            || self.program != native_payment_program::id().to_string()
            || self.pool != native_payment_program::pool_address().to_string()
            || !self.recipient_withdrawals
        {
            return Err("invalid or incompatible tester profile".into());
        }
        if self
            .private_send_transport
            .as_deref()
            .is_some_and(|transport| {
                transport != "native-inline-v1"
                    || self.pool_format != "NPOOL004"
                    || !self.invite_required
                    || self.rpc.transport != "https"
            })
        {
            return Err(
                "native private sends require explicit NPOOL004 and an invited HTTPS gateway"
                    .into(),
            );
        }
        if self.invite_required && self.faucet.is_none() {
            return Err("invited profile requires a pinned admission endpoint".into());
        }
        if let Some(audiences) = &self.access_audiences {
            if audiences.format != "native-access-audiences-v1"
                || audiences.network != self.network
                || audiences.genesis_hash != self.genesis_hash
                || !self.invite_required
                || self.rpc.transport != "https"
                || self
                    .faucet
                    .as_ref()
                    .is_none_or(|endpoint| endpoint.transport != "https")
                || self.local_tls_ca_pem.is_some()
            {
                return Err("access audience aliases require the exact network and invited HTTPS transports without a local test CA".into());
            }
            for url in [&audiences.rpc, &audiences.faucet] {
                Endpoint {
                    transport: "https".into(),
                    url: url.to_string(),
                }
                .validate()?;
            }
        }
        if self
            .retained_history_format
            .as_deref()
            .is_some_and(|format| {
                format != "compact-v2" || !self.invite_required || self.rpc.transport != "https"
            })
        {
            return Err(
                "compact retained history requires an explicitly invited HTTPS profile".into(),
            );
        }
        if let Some(pem) = &self.local_tls_ca_pem {
            if pem.len() > 8192 || pem.contains("PRIVATE KEY") {
                return Err("invalid local TLS trust certificate".into());
            }
            for endpoint in std::iter::once(&self.rpc).chain(self.faucet.iter()) {
                let url = reqwest::Url::parse(&endpoint.url)?;
                if endpoint.transport != "https" || url.host_str() != Some("127.0.0.1") {
                    return Err("local test CA requires HTTPS endpoints on 127.0.0.1".into());
                }
            }
            reqwest::Certificate::from_pem(pem.as_bytes())?;
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

    fn profile() -> TesterProfile {
        TesterProfile {
            format: "native-wallet-profile-v1".into(),
            label: "Invited testers".into(),
            key_mode: "user-wallet-v1".into(),
            network: [7; 32],
            genesis_hash: "11111111111111111111111111111111".into(),
            program: native_payment_program::id().to_string(),
            pool: native_payment_program::pool_address().to_string(),
            pool_format: "NPOOL003".into(),
            private_send_transport: None,
            retained_history_format: None,
            access_audiences: None,
            recipient_withdrawals: true,
            invite_required: false,
            local_tls_ca_pem: None,
            faucet: None,
            rpc: Endpoint {
                transport: "https".into(),
                url: "https://rpc.example.invalid".into(),
            },
        }
    }

    fn aliased_profile() -> TesterProfile {
        let mut value = profile();
        value.invite_required = true;
        value.rpc.url = "https://pilot.example.invalid/rpc".into();
        value.faucet = Some(Endpoint {
            transport: "https".into(),
            url: "https://pilot.example.invalid:8444".into(),
        });
        value.access_audiences = Some(AccessAudiences {
            format: "native-access-audiences-v1".into(),
            network: value.network,
            genesis_hash: value.genesis_hash.clone(),
            rpc: "https://127.0.0.1:39443".into(),
            faucet: "https://127.0.0.1:39444".into(),
        });
        value
    }

    #[test]
    fn access_audience_aliases_preserve_legacy_and_explicit_roundtrip() {
        let legacy = profile();
        assert_eq!(legacy.rpc_audience(), legacy.rpc.url);
        assert!(serde_json::to_value(&legacy)
            .unwrap()
            .get("access_audiences")
            .is_none());
        let alias = aliased_profile();
        alias.validate().unwrap();
        let encoded = serde_json::to_value(&alias).unwrap();
        let decoded: TesterProfile = serde_json::from_value(encoded.clone()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), encoded);
        assert_eq!(decoded.rpc_audience(), "https://127.0.0.1:39443");
        assert_eq!(
            decoded.faucet_audience().unwrap(),
            "https://127.0.0.1:39444"
        );
        assert_eq!(decoded.rpc.url, "https://pilot.example.invalid/rpc");
    }

    #[test]
    fn access_audience_aliases_reject_null_unknown_or_partial_schema_without_fallback() {
        let encoded = serde_json::to_value(aliased_profile()).unwrap();
        let mut null = encoded.clone();
        null["access_audiences"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<TesterProfile>(null).is_err());
        let mut unknown = encoded.clone();
        unknown["access_audiences"]["automatic"] = true.into();
        assert!(serde_json::from_value::<TesterProfile>(unknown).is_err());
        for key in ["format", "network", "genesis_hash", "rpc", "faucet"] {
            let mut missing = encoded.clone();
            missing["access_audiences"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                serde_json::from_value::<TesterProfile>(missing).is_err(),
                "{key}"
            );
        }
        let mut version = aliased_profile();
        version.access_audiences.as_mut().unwrap().format = "native-access-audiences-v2".into();
        assert!(version.validate().is_err());
    }

    #[test]
    fn access_audience_aliases_reject_network_substitution_and_transport_downgrades() {
        let original = aliased_profile();
        let mut network = original.clone();
        network.access_audiences.as_mut().unwrap().network = [8; 32];
        assert!(network.validate().is_err());
        let mut genesis = original.clone();
        genesis.access_audiences.as_mut().unwrap().genesis_hash =
            bs58::encode([8; 32]).into_string();
        assert!(genesis.validate().is_err());
        let mut rpc = original.clone();
        rpc.rpc = Endpoint {
            transport: "loopback-http".into(),
            url: "http://127.0.0.1:39443".into(),
        };
        assert!(rpc.validate().is_err());
        let mut faucet = original.clone();
        faucet.faucet = Some(Endpoint {
            transport: "loopback-http".into(),
            url: "http://127.0.0.1:39444".into(),
        });
        assert!(faucet.validate().is_err());
        let mut ca = original.clone();
        ca.local_tls_ca_pem = Some("not accepted for public alias transport".into());
        assert!(ca.validate().is_err());
        let mut uninvited = original;
        uninvited.invite_required = false;
        assert!(uninvited.validate().is_err());
    }

    #[test]
    fn access_audience_aliases_validate_both_logical_https_urls() {
        for bad in [
            "http://127.0.0.1:39443",
            "https://user@host.invalid",
            "https://host.invalid?key=x",
            "https://host.invalid/#fragment",
            "https://host.invalid:0",
            "https://host.invalid\\@evil.invalid",
        ] {
            for rpc in [true, false] {
                let mut value = aliased_profile();
                let aliases = value.access_audiences.as_mut().unwrap();
                if rpc {
                    aliases.rpc = bad.into();
                } else {
                    aliases.faucet = bad.into();
                }
                assert!(value.validate().is_err(), "{rpc}: {bad}");
            }
        }
    }

    #[test]
    fn profile_rejects_unknown_fields_wrong_protocol_and_invalid_domain() {
        let profile = profile();
        profile.validate().unwrap();
        let mut v4 = profile.clone();
        v4.pool_format = "NPOOL004".into();
        v4.validate().unwrap();
        let mut native = v4.clone();
        native.private_send_transport = Some("native-inline-v1".into());
        assert!(native.validate().is_err());
        native.invite_required = true;
        native.faucet = Some(native.rpc.clone());
        native.validate().unwrap();
        let mut downgraded = native.clone();
        downgraded.pool_format = "NPOOL003".into();
        assert!(downgraded.validate().is_err());
        downgraded = native.clone();
        downgraded.private_send_transport = Some("automatic".into());
        assert!(downgraded.validate().is_err());
        downgraded = native;
        downgraded.rpc.transport = "loopback-http".into();
        downgraded.rpc.url = "http://127.0.0.1:18899".into();
        assert!(downgraded.validate().is_err());
        let mut value = serde_json::to_value(&profile).unwrap();
        value["sponsor"] = "unwanted operator".into();
        let mut local = profile.clone();
        local.local_tls_ca_pem = Some("not a certificate".into());
        assert!(local.validate().is_err());
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
    fn compact_history_requires_explicit_supported_invited_https_profile() {
        let legacy = profile();
        let encoded = serde_json::to_value(&legacy).unwrap();
        assert!(encoded.get("retained_history_format").is_none());
        let decoded: TesterProfile = serde_json::from_value(encoded).unwrap();
        assert!(decoded.retained_history_format.is_none());
        decoded.validate().unwrap();

        let mut compact = legacy;
        compact.retained_history_format = Some("compact-v2".into());
        assert!(compact.validate().is_err());
        compact.invite_required = true;
        compact.faucet = Some(compact.rpc.clone());
        compact.validate().unwrap();
        let roundtrip: TesterProfile =
            serde_json::from_value(serde_json::to_value(&compact).unwrap()).unwrap();
        assert_eq!(
            roundtrip.retained_history_format.as_deref(),
            Some("compact-v2")
        );
        roundtrip.validate().unwrap();
        for format in ["", "automatic", "compact-v1", "compact-v3"] {
            let mut invalid = compact.clone();
            invalid.retained_history_format = Some(format.into());
            assert!(invalid.validate().is_err(), "{format}");
        }
        let mut downgraded = compact;
        downgraded.rpc.transport = "loopback-http".into();
        downgraded.rpc.url = "http://127.0.0.1:18899".into();
        assert!(downgraded.validate().is_err());
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
