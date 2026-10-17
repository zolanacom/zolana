use native_wallet::{
    keys::{read_password, read_password_input, read_private, Network, WalletKey},
    operation::WalletOperation,
    payments::{self, Payment},
    rpc::Chain,
    Result,
};
use serde_json::json;
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::{collections::BTreeMap, path::Path};

fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_else(|| "--help".to_owned());
    if matches!(command.as_str(), "--help" | "-h") {
        println!(
            "native-wallet init|restore|address|balance|deposit|send|withdraw|resolve|reclaim|archive"
        );
        println!("Required: --network <network.json> --wallet <encrypted-seed.json> --password-file <private-file|->; '-' reads a bounded password from stdin");
        println!("init/restore: --backup <encrypted-seed-backup.json>");
        println!("balance/deposit/send/withdraw/resolve/reclaim: --rpc http://127.0.0.1:<port>");
        println!("deposit/send/withdraw: --sponsor <private-keypair.json> --amount <native-units>");
        println!("rehearsal deposit/send: --sponsor-password-file <private-operator-file> --sponsor-request-id <unique-id> --amount <native-units>; fixed encrypted sponsor/policy beside network.json");
        println!("rehearsal reclaim: --sponsor-password-file; reuses the saved original reservation for cleanup only. Sponsored withdrawals are disabled.");
        println!("deposit/send: --to <npriv1-address> (deposit defaults to this wallet)");
        println!("Withdrawal pays the signed public sponsor; --to is not supported.");
        println!("reclaim: --rpc and --sponsor; safely close a recorded interrupted upload after resolving any pending payment.");
        println!("Experimental local network only. Keep the encrypted seed backup and password separately.");
        println!("archive: --network --rpc --history <directory>; public collector needs no wallet/password/sponsor");
        println!("balance/deposit/send/withdraw: optional --history <directory> supplies retained verified ciphertext history");
        return Ok(());
    }
    if ![
        "init", "restore", "address", "balance", "deposit", "send", "withdraw", "resolve",
        "reclaim", "archive",
    ]
    .contains(&command.as_str())
    {
        return Err("unknown wallet command; use --help".into());
    }
    let mut args = BTreeMap::new();
    while let Some(flag) = arguments.next() {
        if ![
            "--network",
            "--wallet",
            "--password-file",
            "--backup",
            "--rpc",
            "--sponsor",
            "--amount",
            "--to",
            "--history",
            "--sponsor-password-file",
            "--sponsor-request-id",
        ]
        .contains(&flag.as_str())
        {
            return Err(format!("unknown option {flag}").into());
        }
        let value = arguments.next().ok_or("option is missing its value")?;
        if args.insert(flag, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    if command == "withdraw" && args.contains_key("--to") {
        return Err("withdrawal pays the signed sponsor; --to is not supported".into());
    }
    let required = |name: &str| -> Result<&str> {
        args.get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {name}").into())
    };
    let network = Network::load(Path::new(required("--network")?))?;
    let configuration: serde_json::Value =
        serde_json::from_slice(&std::fs::read(required("--network")?)?)?;
    let private_setup = configuration["key_mode"] == "local-testnet-rehearsal-v1";
    if !private_setup && configuration["fixture_keys_are_public"] != true {
        return Err(
            "network must explicitly select disposable fixture or guarded rehearsal keys".into(),
        );
    }
    if private_setup && args.contains_key("--sponsor") {
        return Err("rehearsal network requires its encrypted sponsor and durable policy; plaintext sponsor override is forbidden".into());
    }
    if command == "archive" {
        let chain = Chain::connect(required("--rpc")?, network)?;
        println!(
            "{}",
            chain.export_history(Path::new(required("--history")?))?
        );
        return Ok(());
    }
    if args.contains_key("--history")
        && !["balance", "deposit", "send", "withdraw"].contains(&command.as_str())
    {
        return Err("--history is only for balance/payment reconstruction; unknown-payment resolution requires canonical full RPC history".into());
    }
    let password = if required("--password-file")? == "-" {
        read_password_input(std::io::stdin().lock())?
    } else {
        read_password(Path::new(required("--password-file")?))?
    };
    let path = Path::new(required("--wallet")?);
    if command == "init" {
        let backup = Path::new(required("--backup")?);
        if path.exists() || backup.exists() || path == backup {
            return Err("wallet and backup must be distinct new files".into());
        }
        let wallet = WalletKey::generate(network)?;
        wallet.save(backup, &password)?;
        wallet.save(path, &password)?;
        println!(
            "{}",
            json!({"address":wallet.address_text(),"encrypted_seed_backup_created":true})
        );
        return Ok(());
    }
    let wallet = if command == "restore" {
        if path.exists() {
            return Err("restore requires a new wallet path".into());
        }
        let wallet = WalletKey::open(Path::new(required("--backup")?), &password, &network)?;
        wallet.save(path, &password)?;
        wallet
    } else {
        WalletKey::open(path, &password, &network)?
    };
    if command == "address" || command == "restore" {
        println!(
            "{}",
            json!({"address":wallet.address_text(),"restored_seed_only":command=="restore"})
        );
        return Ok(());
    }
    // Hold the OS lock from before sync/proving until all submission/recovery work ends.
    let operation = WalletOperation::acquire(path)?;
    let mut chain = Chain::connect(required("--rpc")?, network.clone())?;
    if command == "resolve" {
        println!("{}", chain.resolve(&wallet, &operation)?);
        return Ok(());
    }
    if command == "reclaim" {
        let sponsor = sponsor_for(&args, private_setup, &network)?;
        if private_setup {
            let staged: serde_json::Value = serde_json::from_slice(&read_private(
                Path::new(&format!("{}.staging.json", path.display())),
                4096,
            )?)?;
            let request = staged["sponsor_request_id"]
                .as_str()
                .ok_or("staging journal has no original sponsor reservation")?;
            let root = Path::new(required("--network")?)
                .parent()
                .unwrap_or(Path::new("."));
            chain = chain.with_sponsor_budget(native_wallet::sponsor::Budget::recover(
                &root.join("sponsor-policy.json"),
                &network,
                &sponsor.pubkey(),
                &wallet.address_text(),
                request,
            )?);
        }
        println!("{}", chain.reclaim(&sponsor, &operation)?);
        return Ok(());
    }
    if command != "balance" {
        operation.ensure_resolved()?;
    }
    let synced = if let Some(history) = args.get("--history") {
        chain.sync_cached_with_history(&wallet, &operation, Path::new(history))?
    } else {
        chain.sync_cached(&wallet, &operation)?
    };
    if command == "balance" {
        println!(
            "{}",
            json!({"balance":synced.state.balance()?,"max_single_payment":synced.state.max_payment()?,"unspent_notes":synced.state.unspent().len(),"finalized_slot":synced.slot,"commitments":synced.state.pool.note_count(),"sync":synced.scan})
        );
        return Ok(());
    }
    let sponsor = sponsor_for(&args, private_setup, &network)?;
    let amount = required("--amount")?.parse::<u64>()?;
    let own_address = wallet.address_text();
    let payment = match command.as_str() {
        "deposit" => Payment::Deposit {
            amount,
            recipient: args.get("--to").map(String::as_str).unwrap_or(&own_address),
        },
        "send" => Payment::Send {
            amount,
            recipient: required("--to")?,
        },
        "withdraw" => Payment::Withdraw { amount },
        _ => return Err("unknown wallet command; use --help".into()),
    };
    // Managed withdrawals are denied by policy even if the wallet has no funds.
    if command != "withdraw" {
        payments::validate(&wallet, &synced.state, &payment)?;
    }
    if private_setup {
        chain = chain.with_sponsor_budget(reserve_sponsor(
            &args,
            &network,
            &sponsor,
            &wallet.address_text(),
            &command,
            amount,
        )?);
    }
    let bytes = payments::build(
        &wallet,
        &synced.state,
        sponsor.pubkey().to_bytes(),
        chain.expiry()?,
        payment,
    )?;
    let submitted = chain.submit(&sponsor, &bytes, &operation)?;
    println!("{}", serde_json::to_string(&submitted)?);
    Ok(())
}

fn load_sponsor(path: &Path) -> Result<Keypair> {
    let raw = read_private(path, 4096)?;
    let secret: zeroize::Zeroizing<Vec<u8>> =
        zeroize::Zeroizing::new(serde_json::from_slice(&raw)?);
    Ok(Keypair::try_from(secret.as_slice())?)
}

fn sponsor_for(
    args: &BTreeMap<String, String>,
    private: bool,
    network: &Network,
) -> Result<Keypair> {
    if !private {
        if args.contains_key("--sponsor-password-file") || args.contains_key("--sponsor-request-id")
        {
            return Err("guarded sponsor options require a rehearsal network".into());
        }
        return load_sponsor(Path::new(args.get("--sponsor").ok_or("missing --sponsor")?));
    }
    let password_path = args
        .get("--sponsor-password-file")
        .ok_or("missing --sponsor-password-file")?;
    if password_path == "-" {
        return Err("sponsor password needs a separate owner-only operator file".into());
    }
    let password = read_password(Path::new(password_path))?;
    let root = Path::new(args.get("--network").ok_or("missing --network")?)
        .parent()
        .unwrap_or(Path::new("."));
    let mut keys =
        native_wallet::operator::open(&root.join("sponsor.enc.json"), network, &password)?;
    if keys.len() != 1 {
        return Err("hot sponsor vault must contain only the sponsor".into());
    }
    keys.remove("sponsor")
        .ok_or_else(|| "hot sponsor role missing".into())
}

fn reserve_sponsor(
    args: &BTreeMap<String, String>,
    network: &Network,
    sponsor: &Keypair,
    wallet: &str,
    kind: &str,
    amount: u64,
) -> Result<native_wallet::sponsor::Budget> {
    let root = Path::new(args.get("--network").ok_or("missing --network")?)
        .parent()
        .unwrap_or(Path::new("."));
    native_wallet::sponsor::Budget::reserve(
        &root.join("sponsor-policy.json"),
        network,
        &sponsor.pubkey(),
        wallet,
        kind,
        amount,
        args.get("--sponsor-request-id")
            .ok_or("missing --sponsor-request-id")?,
    )
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Wallet error: {error}");
        std::process::exit(1);
    }
}
