use native_wallet::{
    keys::{read_password, read_private, Network, WalletKey},
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
        println!("native-wallet init|restore|address|balance|deposit|send|withdraw|resolve");
        println!("Required: --network <network.json> --wallet <encrypted-seed.json> --password-file <private-file>");
        println!("init/restore: --backup <encrypted-seed-backup.json>");
        println!("balance/deposit/send/withdraw: --rpc http://127.0.0.1:<port>");
        println!("deposit/send/withdraw: --sponsor <private-keypair.json> --amount <native-units>");
        println!("deposit/send: --to <npriv1-address> (deposit defaults to this wallet)");
        println!("Withdrawal pays the signed public sponsor; --to is not supported.");
        println!("Experimental local network only. Keep the encrypted seed backup and password separately.");
        return Ok(());
    }
    if ![
        "init", "restore", "address", "balance", "deposit", "send", "withdraw", "resolve",
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
    let password = read_password(Path::new(required("--password-file")?))?;
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
    let chain = Chain::connect(required("--rpc")?, network)?;
    let pending = std::path::PathBuf::from(format!("{}.pending.json", path.display()));
    if command == "resolve" {
        println!("{}", chain.resolve(&wallet, &pending)?);
        return Ok(());
    }
    if command != "balance" && pending.exists() {
        return Err("an unresolved payment exists; run resolve before sending again".into());
    }
    let synced = chain.sync(&wallet)?;
    if command == "balance" {
        println!(
            "{}",
            json!({"balance":synced.state.balance()?,"max_single_payment":synced.state.max_payment()?,"unspent_notes":synced.state.unspent().len(),"finalized_slot":synced.slot,"commitments":synced.state.pool.note_count()})
        );
        return Ok(());
    }
    let raw = read_private(Path::new(required("--sponsor")?), 4096)?;
    let secret: zeroize::Zeroizing<Vec<u8>> =
        zeroize::Zeroizing::new(serde_json::from_slice(&raw)?);
    let sponsor = Keypair::try_from(secret.as_slice())?;
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
    let bytes = payments::build(
        &wallet,
        &synced.state,
        sponsor.pubkey().to_bytes(),
        chain.expiry()?,
        payment,
    )?;
    let submitted = chain.submit(&sponsor, &bytes, &pending)?;
    println!("{}", serde_json::to_string(&submitted)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Wallet error: {error}");
        std::process::exit(1);
    }
}
