//! Separate opt-in entrypoint: existing wallets and fee modes are unchanged.
use native_wallet::{
    connection::TesterProfile,
    keys::{
        read_password, read_password_input, read_private, write_private_new, Network, WalletKey,
    },
    operation::WalletOperation,
    rpc::Chain,
    shielded::{self, Packet},
    Result,
};
use solana_signer::Signer;
use std::{collections::BTreeMap, path::Path};

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or("expected send|resolve|relay")?;
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if ![
            "--network",
            "--wallet",
            "--password-file",
            "--amount",
            "--to",
            "--max-shielded-fee",
            "--rpc",
            "--rpc-access-file",
            "--payer",
            "--job",
            "--gross-cap",
            "--fee",
        ]
        .contains(&key.as_str())
        {
            return Err("unknown shielded option".into());
        }
        if options
            .insert(key, args.next().ok_or("missing option value")?)
            .is_some()
        {
            return Err("duplicate option".into());
        }
    }
    let get = |name: &str| -> Result<&str> {
        options
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {name}").into())
    };
    let network_file = Path::new(get("--network")?);
    let network = Network::load(network_file)?;
    let value = if command == "relay" {
        // Operator-only fixed paths. No spending/viewing keys from a user.
        let job = Path::new(get("--job")?);
        let packet: Packet =
            serde_json::from_slice(&read_private(&job.join("packet.json"), 20000)?)?;
        if packet.network != network {
            return Err("relay packet network mismatch".into());
        }
        let bytes = packet.bytes()?;
        let payer = solana_keypair::Keypair::try_from(
            serde_json::from_slice::<Vec<u8>>(&read_private(Path::new(get("--payer")?), 4096)?)?
                .as_slice(),
        )?;
        let decoded = native_payments::wire::decode(network.network, &bytes)?;
        if decoded.context.sponsor != payer.pubkey().to_bytes()
            || decoded.context.shielded_fee != Some(get("--fee")?.parse()?)
        {
            return Err("relay fee/payee mismatch".into());
        }
        let operation = WalletOperation::acquire(&job.join("relay"))?
            .with_durable_receipt(&job.join("outcome.json"));
        let connect = || -> Result<Chain> {
            if let Some(path) = options.get("--rpc-access-file") {
                Chain::connect_operator(get("--rpc")?, network.clone(), Path::new(path))
            } else {
                Chain::connect(get("--rpc")?, network.clone())
            }
        };
        // An ephemeral observer can authenticate canonical history without any
        // user's viewing key. Its decrypted balance is irrelevant to the relay.
        let observer = WalletKey::generate(network.clone())?;
        let chain = connect()?;
        let limit = if operation.has_staging() {
            chain
                .recovery_user_limit(&operation, payer.pubkey())?
                .ok_or("relay original cap missing")?
        } else {
            get("--gross-cap")?.parse()?
        };
        let chain = chain.with_user_fees(payer.pubkey(), limit, &operation)?;
        if operation.has_pending() {
            let result = chain.resolve(&observer, &operation)?;
            if operation.has_staging() {
                chain.reclaim(&payer, &operation)?;
            }
            result
        } else if job.join("outcome.json").exists() {
            if operation.has_staging() {
                chain.reclaim(&payer, &operation)?;
            }
            serde_json::from_slice(&read_private(&job.join("outcome.json"), 4096)?)?
        } else if job.join("attempted").exists() {
            if operation.has_staging() {
                chain.reclaim(&payer, &operation)?;
            }
            // No pending finalization means the durable-before-broadcast rule
            // proves this worker cannot have submitted a value-changing tx.
            let aborted = serde_json::json!({"accepted":false,"aborted":true});
            write_private_new(&job.join("outcome.json"), &serde_json::to_vec(&aborted)?)?;
            aborted
        } else {
            chain.validate_shielded_payload(&bytes)?;
            write_private_new(&job.join("attempted"), b"one bounded relay attempt\n")?;
            serde_json::to_value(chain.submit(&payer, &bytes, &operation)?)?
        }
    } else {
        if options.keys().any(|k| {
            [
                "--payer",
                "--job",
                "--gross-cap",
                "--fee",
                "--rpc-access-file",
            ]
            .contains(&k.as_str())
        }) {
            return Err("operator options forbidden in user mode".into());
        }
        let password = if get("--password-file")? == "-" {
            read_password_input(std::io::stdin().lock())?
        } else {
            read_password(Path::new(get("--password-file")?))?
        };
        let path = Path::new(get("--wallet")?);
        let operation = WalletOperation::acquire(path)?;
        let wallet = WalletKey::open(path, &password, &network)?;
        let config: serde_json::Value = serde_json::from_slice(&std::fs::read(network_file)?)?;
        let chain = if config["format"] == "native-wallet-profile-v1" {
            if options.contains_key("--rpc") {
                return Err("tester endpoint cannot be overridden".into());
            }
            let profile = TesterProfile::load(network_file)?;
            if profile.invite_required {
                Chain::connect_invited(&profile, &wallet)?
            } else {
                Chain::connect_profile(&profile)?
            }
        } else {
            Chain::connect(get("--rpc")?, network)?
        };
        match command.as_str() {
            "send" => shielded::send(
                &chain,
                &wallet,
                &operation,
                get("--amount")?.parse()?,
                get("--to")?,
                get("--max-shielded-fee")?.parse()?,
            )?,
            "resolve" => shielded::recover(&chain, &wallet, &operation, false)?,
            _ => return Err("expected send|resolve|relay".into()),
        }
    };
    println!("{}", value);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Shielded payment: {error}");
        std::process::exit(1);
    }
}
