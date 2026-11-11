mod cli;

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

fn run_with_arguments(
    arguments: impl Iterator<Item = String>,
    password_input: Option<&[u8]>,
) -> Result<()> {
    let command_started = Instant::now();
    let Some(cli::Arguments {
        command,
        args,
        mut shielded_paid,
        user_paid,
        quote_payment,
    }) = cli::parse_arguments(arguments)?
    else {
        return Ok(());
    };
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
        let native = profile.private_send_transport.as_deref() == Some("native-inline-v1");
        if command == "send" && native {
            if args
                .get("--fee-payer")
                .is_some_and(|mode| mode != "shielded")
            {
                return Err("this explicit native profile uses shielded private-send fees".into());
            }
            shielded_paid = true;
        }
        if shielded_paid && !native {
            return Err(
                "shielded native sends require an explicit native-inline-v1 tester profile".into(),
            );
        }
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
            || (matches!(command.as_str(), "send" | "withdraw") && !user_paid && !shielded_paid)
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
    if shielded_paid
        && tester.as_ref().is_none_or(|profile| {
            profile.private_send_transport.as_deref() != Some("native-inline-v1")
        })
    {
        return Err("shielded sends require an explicit native tester profile".into());
    }
    if args.contains_key("--max-shielded-fee") && !(shielded_paid && command == "send") {
        return Err("--max-shielded-fee only authorizes a native shielded send".into());
    }
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
    let connect = || -> Result<Chain> {
        (match &tester {
            Some(profile) => Chain::connect_profile(profile),
            None if args.contains_key("--rpc-access-file") => Chain::connect_operator(
                required("--rpc")?,
                network.clone(),
                Path::new(required("--rpc-access-file")?),
            ),
            None => Chain::connect(required("--rpc")?, network.clone()),
        })?
        .with_pool_format(configuration["pool_format"].as_str().unwrap_or("NPOOL003"))
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
    // Only fixed public circuit material is prepared here. The worker receives
    // no password, wallet, connection or payment, and is joined on early errors.
    // Recovery commands never start a prover or construct a replacement proof.
    let mut preparation = if matches!(
        command.as_str(),
        "deposit" | "send" | "withdraw" | "withdraw-legacy"
    ) {
        native_wallet::progress::report("key");
        Some(payments::ProverPreparation::start()?)
    } else {
        None
    };
    let password = if let Some(input) = password_input {
        if required("--password-file")? != "-" {
            return Err("wallet sessions only accept the bounded password pipe".into());
        }
        read_password_input(input)?
    } else if required("--password-file")? == "-" {
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
        WalletKey::restore(Path::new(required("--backup")?), path, &password, &network)?
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
    }
    .with_retained_history_format(
        tester
            .as_ref()
            .and_then(|profile| profile.retained_history_format.as_deref()),
    )?;
    if command == "resolve" {
        let outcome = if operation.has_shielded() {
            native_wallet::shielded::recover(&chain, &wallet, &operation, false)?
        } else {
            chain.resolve(&wallet, &operation)?
        };
        println!("{}", outcome);
        return Ok(());
    }
    if command == "fees" {
        if quote_payment == "send"
            && tester.as_ref().is_some_and(|profile| {
                profile.private_send_transport.as_deref() == Some("native-inline-v1")
            })
        {
            println!(
                "{}",
                native_wallet::shielded::native::quote(&chain, &wallet.network)?
            );
            return Ok(());
        }
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
    if command == "send" && shielded_paid {
        if args.contains_key("--history") {
            return Err(
                "native send recovery uses canonical gateway history; --history is unsupported"
                    .into(),
            );
        }
        let outcome = native_wallet::shielded::native::send_with_preparation(
            chain,
            &wallet,
            &operation,
            required("--amount")?.parse()?,
            required("--to")?,
            required("--max-shielded-fee")?.parse()?,
            preparation.take(),
        )?;
        println!("{}", outcome);
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
    let prepared = preparation
        .take()
        .map(|worker| worker.finish())
        .transpose()?;
    let (prover, proof_key_ms, proof_key_wait_ms, proof_key_cached) = match prepared {
        Some((prover, timing)) => (
            Some(prover),
            timing.proof_key_ms,
            timing.proof_key_wait_ms,
            timing.proof_key_cached,
        ),
        None => (None, 0, 0, false),
    };
    if let Some(prover) = &prover {
        chain = chain.with_payment_prover(prover);
    } else if let Some(prover) = payments::cached_prover() {
        // A wallet session retains only public circuit material. A balance
        // scan can reuse its VK and still verifies every canonical payment.
        chain = chain.with_payment_prover(&prover);
    }
    let sync_started = Instant::now();
    if command != "balance" {
        native_wallet::progress::report("sync");
    }
    let synced = if let Some(history) = args.get("--history") {
        chain.sync_cached_with_history(&wallet, &operation, Path::new(history))?
    } else {
        chain.sync_cached(&wallet, &operation)?
    };
    let sync_ms = sync_started.elapsed().as_millis();
    if command == "balance" {
        let unspent = synced.state.unspent();
        for note in &unspent {
            synced.state.witness(note.position)?;
        }
        let public = wallet.public_keypair().pubkey();
        let fee = wallet.fee_keypair().pubkey();
        let balances = chain.balance_inputs(public, fee)?;
        println!(
            "{}",
            json!({"balance":synced.state.balance()?,"max_single_payment":synced.state.max_payment()?,"unspent_notes":unspent.len(),"witnesses_verified":unspent.len(),"finalized_slot":synced.slot,"commitments":synced.state.pool.note_count(),"sync":synced.scan,"public_address":public.to_string(),"public_balance":balances.public_balance,"minimum_public_withdrawal":balances.minimum_withdrawal,"fee_address":fee.to_string(),"fee_balance":balances.fee_balance})
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
    let preparation_ms = command_started
        .elapsed()
        .as_millis()
        .saturating_sub(sync_ms)
        .saturating_sub(proof_key_wait_ms);
    let proof_started = Instant::now();
    native_wallet::progress::report("prove");
    let bytes = prover.as_ref().ok_or("payment prover unavailable")?.build(
        &wallet,
        &synced.state,
        sponsor.pubkey().to_bytes(),
        expiry,
        payment,
    )?;
    let proof_build_ms = proof_started.elapsed().as_millis();
    let submit_started = Instant::now();
    native_wallet::progress::report("upload");
    let submitted = chain.submit(&sponsor, &bytes, &operation)?;
    let mut result = serde_json::to_value(&submitted)?;
    result["timings"] = json!({
        "preparation_ms": preparation_ms,
        "sync_ms": sync_ms,
        "proof_key_ms": proof_key_ms,
        "proof_key_wait_ms": proof_key_wait_ms,
        "proof_key_cached": proof_key_cached,
        "proof_build_ms": proof_build_ms,
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
    let mut args = std::env::args().skip(1);
    let result = if args.next().as_deref() == Some("command-session") {
        let values = args.collect::<Vec<_>>();
        if values.len() != 4 || values[0] != "--network" || values[2] != "--wallet" {
            Err("command-session requires fixed --network and --wallet paths".into())
        } else {
            native_wallet::command_session::serve(
                Path::new(&values[1]),
                Path::new(&values[3]),
                |args, password| run_with_arguments(args.into_iter(), password),
            )
        }
    } else {
        run_with_arguments(std::env::args().skip(1), None)
    };
    if let Err(error) = result {
        eprintln!("Wallet error: {error}");
        std::process::exit(1);
    }
}
