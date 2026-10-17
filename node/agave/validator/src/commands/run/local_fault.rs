//! Explicitly enabled loopback-fixture fault control; absent in normal startup.
use {
    solana_core::validator::ValidatorConfig,
    std::{
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    },
};

fn validate(
    ledger: &Path,
    file: &Path,
    config: &ValidatorConfig,
    local_network: bool,
) -> Result<(), String> {
    let parent = ledger
        .parent()
        .ok_or("missing fixture directory")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if !local_network
        || file.parent().and_then(|p| p.canonicalize().ok()).as_ref() != Some(&parent)
        || !config
            .rpc_addrs
            .is_some_and(|(rpc, pubsub)| rpc.ip().is_loopback() && pubsub.ip().is_loopback())
    {
        return Err("local fault control requires a fixture-local file and loopback RPC".into());
    }
    let network: serde_json::Value =
        serde_json::from_slice(&fs::read(parent.join("network.json")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if network["fixture_keys_are_public"] != true
        || network["pool_format"] != "NPOOL002"
        || config.expected_genesis_hash.is_none()
        || config
            .expected_genesis_hash
            .map(|h| h.to_string())
            .as_deref()
            != network["genesis_hash"].as_str()
    {
        return Err("local fault control requires an authenticated disposable genesis".into());
    }
    Ok(())
}

pub(super) fn enable(
    ledger: &Path,
    config: &ValidatorConfig,
    local_network: bool,
) -> Result<(), String> {
    let Some(file) = std::env::var_os("NATIVE_LOCAL_SHRED_FAULT") else {
        return Ok(());
    };
    let file = PathBuf::from(file);
    validate(ledger, &file, config, local_network)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let exiting = stopped.clone();
    config
        .validator_exit
        .write()
        .unwrap()
        .register_exit(Box::new(move || exiting.store(true, Ordering::Relaxed)));
    let disabled = config.turbine_disabled.clone();
    thread::Builder::new()
        .name("localShredFault".into())
        .spawn(move || {
            let mut last = None;
            while !stopped.load(Ordering::Relaxed) {
                let active = fs::read(&file)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .is_some_and(|v| v["drop_shreds"] == true);
                disabled.store(active, Ordering::Relaxed);
                if last != Some(active) {
                    let ack = serde_json::json!({"pid":std::process::id(),"drop_shreds":active});
                    let _ = fs::write(file.with_extension("ack.json"), ack.to_string());
                    log::warn!("Local fixture shred fault active={active}; UDP/QUIC turbine and repair delivery gated");
                    last = Some(active);
                }
                thread::sleep(Duration::from_millis(50));
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_hash::Hash;

    #[test]
    fn only_authenticated_loopback_fixtures_can_enable_faults() {
        let root = tempfile::tempdir().unwrap();
        let ledger = root.path().join("ledger-0");
        let file = root.path().join("fault-0.json");
        let hash = Hash::new_unique();
        fs::write(
            root.path().join("network.json"),
            serde_json::json!({"fixture_keys_are_public":true,"pool_format":"NPOOL002","genesis_hash":hash.to_string()}).to_string(),
        ).unwrap();
        let mut config = ValidatorConfig {
            rpc_addrs: Some((
                "127.0.0.1:18899".parse().unwrap(),
                "127.0.0.1:18900".parse().unwrap(),
            )),
            expected_genesis_hash: Some(hash),
            ..ValidatorConfig::default_for_test()
        };
        assert!(validate(&ledger, &file, &config, true).is_ok());
        assert!(validate(&ledger, &file, &config, false).is_err());
        assert!(validate(
            &ledger,
            &root.path().parent().unwrap().join("outside.json"),
            &config,
            true
        )
        .is_err());
        config.expected_genesis_hash = None;
        assert!(validate(&ledger, &file, &config, true).is_err());
        config.expected_genesis_hash = Some(hash);
        config.rpc_addrs = Some((
            "0.0.0.0:18899".parse().unwrap(),
            "127.0.0.1:18900".parse().unwrap(),
        ));
        assert!(validate(&ledger, &file, &config, true).is_err());
    }
}
