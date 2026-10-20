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
use std::{collections::BTreeMap, path::Path, time::Instant};

fn run() -> Result<()> {
    let command_started = Instant::now();
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_else(|| "--help".to_owned());
    if matches!(command.as_str(), "--help" | "-h") {
        println!(
            "native-wallet init|restore|address|balance|fees|deposit|send|withdraw|resolve|reclaim|archive|check|profile|test-coins|join|access-status"
        );
        println!("Required: --network <network.json> --wallet <encrypted-seed.json> --password-file <private-file|->; '-' reads a bounded password from stdin");
        println!("init/restore: --backup <encrypted-seed-backup.json>");
        println!("balance/deposit/send/withdraw/resolve/reclaim: --rpc http://127.0.0.1:<port>");
        println!("Tester mode: --network <wallet-profile.json> pins the RPC; omit --rpc. Remote profiles require HTTPS. check needs only --network (and --rpc for fixtures), no wallet/password.");
        println!("deposit/send/withdraw: --sponsor <private-keypair.json> --amount <native-units>");
        println!("rehearsal deposit/send/withdraw: --sponsor-password-file <private-operator-file> --sponsor-request-id <unique-id> --amount <native-units>; fixed encrypted sponsor/policy beside network.json");
        println!("rehearsal reclaim: --sponsor-password-file; reuses the saved original reservation for cleanup only.");
        println!("deposit/send: --to <npriv1-address> (deposit defaults to this wallet)");
        println!("withdraw: --to <public-address> (defaults to your seed-recoverable public account on this chain); fee sponsor receives no withdrawal value.");
        println!("fees: show the user fee address, refundable rent, gross-debit quote and funding shortfall; no sponsor needed.");
        println!("send/withdraw --fee-payer user --max-fee-debit <native-units>: sign with your seed-derived fee authority; never loads operator keys. Fund its public fee address first.");
        println!("fees --payment send|withdraw: quote the exact payment shape; default withdraw for compatibility.");
        println!("withdraw-legacy: disposable fixture compatibility only; credits the sponsor. Never enabled for guarded rehearsal keys.");
        println!("reclaim: --rpc and --sponsor; safely close a recorded interrupted upload after resolving any pending payment.");
        println!("test-coins: request/check the same signed one-time private test-coin and public-gas grant through a pinned profile faucet; no sponsor options.");
        println!("join: invited profiles only; --invitation-file <owner-only code/export file> admits this seed-derived fee authority once and queues its fixed grant. access-status checks the same wallet's durable admission.");
        println!("Invited check validates only the public genesis handshake. Unlock an admitted wallet for authenticated pool/history access. RPC access proofs expire after ten minutes; a new command signs a fresh proof.");
        println!("Operator fixtures only: --rpc-access-file <owner-only-file> authenticates protected loopback raw RPC. Tester profiles reject operator credentials; local HTTPS profiles can include an explicit public local test CA.");
        println!("Experimental local network only. Keep the encrypted seed backup and password separately.");
        println!("archive: --network --rpc --history <directory>; public collector needs no wallet/password/sponsor");
        println!("balance/deposit/send/withdraw: optional --history <directory> supplies retained verified ciphertext history");
        return Ok(());
    }
    if ![
        "init",
        "restore",
        "address",
        "balance",
        "fees",
        "deposit",
        "send",
        "withdraw",
        "resolve",
        "reclaim",
        "archive",
        "check",
        "profile",
        "test-coins",
        "join",
        "access-status",
        "withdraw-legacy",
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
            "--fee-payer",
            "--max-fee-debit",
            "--payment",
            "--invitation-file",
            "--rpc-access-file",
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
    let user_paid = match args.get("--fee-payer").map(String::as_str) {
        None | Some("sponsor") => false,
        Some("user") if matches!(command.as_str(), "send" | "withdraw") => true,
        _ => return Err("--fee-payer must select user or sponsor for send/withdraw".into()),
    };
    if args.contains_key("--fee-payer") && !matches!(command.as_str(), "send" | "withdraw") {
        return Err(
            "fee selection is only for send/withdraw; reclaim uses the original recorded payer"
                .into(),
        );
    }
    if user_paid
        && [
            "--sponsor",
            "--sponsor-password-file",
            "--sponsor-request-id",
        ]
        .iter()
        .any(|flag| args.contains_key(*flag))
    {
        return Err("user-paid fees cannot be combined with operator sponsor options".into());
    }
    if args.contains_key("--max-fee-debit") && !user_paid {
        return Err("--max-fee-debit requires user-paid send/withdraw fees".into());
    }
    let quote_payment = match args.get("--payment").map(String::as_str) {
        None => "withdraw",
        Some(value @ ("send" | "withdraw")) if command == "fees" => value,
        _ => return Err("--payment send|withdraw is only supported for fees".into()),
    };
    if command == "withdraw-legacy" && args.contains_key("--to") {
        return Err("legacy fixture withdrawal pays the sponsor; no destination override".into());
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
    let tester = if configuration["key_mode"] == "user-wallet-v1" {
        let profile =
            native_wallet::connection::TesterProfile::load(Path::new(required("--network")?))?;
        if args.contains_key("--rpc") {
            return Err("tester profile pins the RPC; --rpc override is forbidden".into());
        }
        if [
            "--sponsor",
            "--sponsor-password-file",
            "--sponsor-request-id",
            "--rpc-access-file",
        ]
        .iter()
        .any(|flag| args.contains_key(*flag))
            || matches!(command.as_str(), "deposit" | "withdraw-legacy")
            || (matches!(command.as_str(), "send" | "withdraw") && !user_paid)
        {
            return Err(
                "tester profile permits no operator sponsorship; use user-paid sends/withdrawals"
                    .into(),
            );
        }
        Some(profile)
    } else {
        None
    };
    if command == "withdraw-legacy" && configuration["fixture_keys_are_public"] != true {
        return Err("legacy sponsor withdrawals are restricted to disposable fixtures".into());
    }
    if tester.is_none() && !private_setup && configuration["fixture_keys_are_public"] != true {
        return Err(
            "network must explicitly select disposable fixture or guarded rehearsal keys".into(),
        );
    }
    if private_setup && args.contains_key("--sponsor") {
        return Err("rehearsal network requires its encrypted sponsor and durable policy; plaintext sponsor override is forbidden".into());
    }
    let connect = || match &tester {
        Some(profile) => Chain::connect_profile(profile),
        None if args.contains_key("--rpc-access-file") => Chain::connect_operator(
            required("--rpc")?,
            network.clone(),
            Path::new(required("--rpc-access-file")?),
        ),
        None => Chain::connect(required("--rpc")?, network.clone()),
    };
    if command == "profile" {
        println!(
            "{}",
            serde_json::to_string(
                tester
                    .as_ref()
                    .ok_or("profile requires a public tester configuration")?
            )?
        );
        return Ok(());
    }
    if args.contains_key("--invitation-file") && command != "join" {
        return Err("invitation input is only supported for join".into());
    }
    if command == "check" && tester.as_ref().is_some_and(|p| p.invite_required) {
        let _gateway = connect()?;
        println!(
            "{}",
            json!({"invite_required":true,"wallet_unlock_required":true,"genesis_hash":network.genesis_hash})
        );
        return Ok(());
    }
    if command == "archive" && tester.as_ref().is_some_and(|p| p.invite_required) {
        return Err("use an operator archive profile or an invited wallet balance scan".into());
    }
    if command == "check" {
        println!("{}", connect()?.health()?);
        return Ok(());
    }
    if command == "archive" {
        let chain = connect()?;
        println!(
            "{}",
            chain.export_history(Path::new(required("--history")?))?
        );
        return Ok(());
    }
    if args.contains_key("--history")
        && !["balance", "deposit", "send", "withdraw", "withdraw-legacy"]
            .contains(&command.as_str())
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
        let wallet = WalletKey::generate(network.clone())?;
        wallet.save(backup, &password)?;
        wallet.save(path, &password)?;
        println!(
            "{}",
            json!({"address":wallet.address_text(),"public_address":wallet.public_keypair().pubkey().to_string(),"fee_address":wallet.fee_keypair().pubkey().to_string(),"encrypted_seed_backup_created":true})
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
            json!({"address":wallet.address_text(),"public_address":wallet.public_keypair().pubkey().to_string(),"fee_address":wallet.fee_keypair().pubkey().to_string(),"restored_seed_only":command=="restore"})
        );
        return Ok(());
    }
    if matches!(command.as_str(), "join" | "access-status") {
        let profile = tester.as_ref().ok_or("invited public profile required")?;
        if !profile.invite_required {
            return Err("this profile does not require an invitation".into());
        }
        let result = if command == "join" {
            let raw = read_private(Path::new(required("--invitation-file")?), 512)?;
            let token = if raw.first() == Some(&b'{') {
                serde_json::from_slice::<serde_json::Value>(&raw)?["invitation"]
                    .as_str()
                    .ok_or("invalid invitation file")?
                    .to_owned()
            } else {
                std::str::from_utf8(&raw)?.trim().to_owned()
            };
            if token.len() != 51 || !token.starts_with("invite1_") {
                return Err("enter a valid invitation code".into());
            }
            native_wallet::access::request_join(profile, &wallet, Some(token))?
        } else {
            native_wallet::access::request_status(profile, &wallet)?
        };
        println!("{}", result);
        return Ok(());
    }
    if command == "test-coins" {
        let profile = tester
            .as_ref()
            .ok_or("test-coins requires a pinned tester profile")?;
        println!("{}", native_wallet::faucet::request(profile, &wallet)?);
        return Ok(());
    }
    // Hold the OS lock from before sync/proving until all submission/recovery work ends.
    let operation = WalletOperation::acquire(path)?;
    let mut chain = match &tester {
        Some(profile) if profile.invite_required => Chain::connect_invited(profile, &wallet)?,
        _ => connect()?,
    };
    if command == "resolve" {
        println!("{}", chain.resolve(&wallet, &operation)?);
        return Ok(());
    }
    if command == "fees" {
        let quote = if quote_payment == "send" {
            chain.private_send_fee_quote(wallet.fee_keypair().pubkey())?
        } else {
            chain.withdrawal_fee_quote(
                wallet.fee_keypair().pubkey(),
                wallet.public_keypair().pubkey(),
            )?
        };
        println!("{}", serde_json::to_string(&quote)?);
        return Ok(());
    }
    if command == "reclaim" {
        let payer = wallet.fee_keypair();
        if let Some(limit) = chain.recovery_user_limit(&operation, payer.pubkey())? {
            if [
                "--sponsor",
                "--sponsor-password-file",
                "--sponsor-request-id",
            ]
            .iter()
            .any(|flag| args.contains_key(*flag))
            {
                return Err("user-paid recovery never accepts operator sponsor options".into());
            }
            chain = chain.with_user_fees(payer.pubkey(), limit, &operation)?;
            println!("{}", chain.reclaim(&payer, &operation)?);
            return Ok(());
        }
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
    let sync_started = Instant::now();
    let synced = if let Some(history) = args.get("--history") {
        chain.sync_cached_with_history(&wallet, &operation, Path::new(history))?
    } else {
        chain.sync_cached(&wallet, &operation)?
    };
    let sync_ms = sync_started.elapsed().as_millis();
    if command == "balance" {
        let public = wallet.public_keypair().pubkey();
        println!(
            "{}",
            json!({"balance":synced.state.balance()?,"max_single_payment":synced.state.max_payment()?,"unspent_notes":synced.state.unspent().len(),"finalized_slot":synced.slot,"commitments":synced.state.pool.note_count(),"sync":synced.scan,"public_address":public.to_string(),"public_balance":chain.public_balance(public)?,"minimum_public_withdrawal":chain.minimum_withdrawal(public)?,"fee_address":wallet.fee_keypair().pubkey().to_string(),"fee_balance":chain.public_balance(wallet.fee_keypair().pubkey())?})
        );
        return Ok(());
    }
    let sponsor = if user_paid {
        wallet.fee_keypair()
    } else {
        sponsor_for(&args, private_setup, &network)?
    };
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
        "withdraw-legacy" => Payment::Withdraw { amount },
        "withdraw" => {
            let recipient = match args.get("--to") {
                Some(value) => value
                    .parse::<solana_pubkey::Pubkey>()
                    .map_err(|_| "withdrawal needs a public address on this chain")?,
                None => wallet.public_keypair().pubkey(),
            };
            if recipient == sponsor.pubkey()
                || configuration["roles"].as_object().is_some_and(|roles| {
                    roles
                        .values()
                        .any(|key| key == &serde_json::Value::String(recipient.to_string()))
                })
            {
                return Err(
                    "choose a user public address, not an operator authority or fee sponsor".into(),
                );
            }
            chain.check_withdrawal(recipient, amount)?;
            Payment::WithdrawTo {
                amount,
                recipient: recipient.to_bytes(),
            }
        }
        _ => return Err("unknown wallet command; use --help".into()),
    };
    payments::validate(&wallet, &synced.state, &payment)?;
    if user_paid {
        let maximum = required("--max-fee-debit")?.parse::<u64>()?;
        let quote = match payment {
            Payment::Send { .. } => chain.private_send_fee_quote(sponsor.pubkey())?,
            Payment::WithdrawTo { recipient, .. } => chain.withdrawal_fee_quote(
                sponsor.pubkey(),
                solana_pubkey::Pubkey::new_from_array(recipient),
            )?,
            _ => {
                return Err(
                    "user fee mode only supports private sends and recipient-bound withdrawals"
                        .into(),
                )
            }
        };
        if maximum < quote.maximum_gross_debit {
            return Err(format!(
                "user fee debit cap is below the current {} quote",
                quote.payment
            )
            .into());
        }
        if quote.public_balance
            < maximum
                .checked_add(quote.minimum_remaining_balance)
                .ok_or("fee funding overflow")?
        {
            return Err(format!("fund user fee address {} with enough public native coins: cap plus minimum requires {}", quote.fee_address, maximum + quote.minimum_remaining_balance).into());
        }
        chain = chain.with_user_fees(sponsor.pubkey(), maximum, &operation)?;
    } else if private_setup {
        chain = chain.with_sponsor_budget(reserve_sponsor(
            &args,
            &network,
            &sponsor,
            &wallet.address_text(),
            &command,
            amount,
        )?);
    }
    let expiry = chain.expiry()?;
    let preparation_ms = command_started.elapsed().as_millis().saturating_sub(sync_ms);
    let (bytes, proof_timings) = payments::build_with_timings(
        &wallet,
        &synced.state,
        sponsor.pubkey().to_bytes(),
        expiry,
        payment,
    )?;
    let submit_started = Instant::now();
    let submitted = chain.submit(&sponsor, &bytes, &operation)?;
    let mut result = serde_json::to_value(&submitted)?;
    result["timings"] = json!({
        "preparation_ms": preparation_ms,
        "sync_ms": sync_ms,
        "proof_key_ms": proof_timings.proof_key_ms,
        "proof_build_ms": proof_timings.proof_build_ms,
        "submit_ms": submit_started.elapsed().as_millis(),
        "total_ms": command_started.elapsed().as_millis(),
    });
    println!("{}", result);
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
