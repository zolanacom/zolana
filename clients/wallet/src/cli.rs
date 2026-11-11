//! Parse and validate CLI options before opening wallet or network state.
use native_wallet::Result;
use std::collections::BTreeMap;

pub(crate) struct Arguments {
    pub command: String,
    pub args: BTreeMap<String, String>,
    pub shielded_paid: bool,
    pub user_paid: bool,
    pub quote_payment: &'static str,
}

pub(crate) fn parse_arguments(
    mut arguments: impl Iterator<Item = String>,
) -> Result<Option<Arguments>> {
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
        println!("fees --payment send|withdraw: quote the exact payment shape; explicit native profiles quote shielded send fees.");
        println!("Native profiles: send --fee-payer shielded --max-shielded-fee <cap>; no public user gas key. resolve retains the original proof until canonical recovery.");
        println!("withdraw-legacy: disposable fixture compatibility only; credits the sponsor. Never enabled for guarded rehearsal keys.");
        println!("reclaim: --rpc and --sponsor; safely close a recorded interrupted upload after resolving any pending payment.");
        println!("test-coins: request/check the same signed one-time private test-coin and public-gas grant through a pinned profile faucet; no sponsor options.");
        println!("join: invited profiles only; --invitation-file <owner-only code/export file> admits this seed-derived fee authority once and queues its fixed grant. access-status checks the same wallet's durable admission.");
        println!("Invited check validates only the public genesis handshake. Unlock an admitted wallet for authenticated pool/history access. RPC access proofs expire after ten minutes; a new command signs a fresh proof.");
        println!("Operator fixtures only: --rpc-access-file <owner-only-file> authenticates protected loopback raw RPC. Tester profiles reject operator credentials; local HTTPS profiles can include an explicit public local test CA.");
        println!("Experimental local network only. Keep the encrypted seed backup and password separately.");
        println!("archive: --network --rpc --history <directory>; public collector needs no wallet/password/sponsor");
        println!("balance/deposit/send/withdraw: optional --history <directory> supplies retained verified ciphertext history");
        return Ok(None);
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
            "--max-shielded-fee",
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
    let shielded_paid = args
        .get("--fee-payer")
        .is_some_and(|mode| mode == "shielded");
    let user_paid = match args.get("--fee-payer").map(String::as_str) {
        None | Some("sponsor") => false,
        Some("user") if matches!(command.as_str(), "send" | "withdraw") => true,
        Some("shielded") if command == "send" => false,
        _ => return Err(
            "--fee-payer must select user/sponsor for send/withdraw or shielded for native sends"
                .into(),
        ),
    };
    if args.contains_key("--fee-payer") && !matches!(command.as_str(), "send" | "withdraw") {
        return Err(
            "fee selection is only for send/withdraw; reclaim uses the original recorded payer"
                .into(),
        );
    }
    if (user_paid || shielded_paid)
        && [
            "--sponsor",
            "--sponsor-password-file",
            "--sponsor-request-id",
        ]
        .iter()
        .any(|flag| args.contains_key(*flag))
    {
        return Err("user/shielded fees cannot be combined with operator sponsor options".into());
    }
    if args.contains_key("--max-fee-debit") && !user_paid {
        return Err("--max-fee-debit requires user-paid send/withdraw fees".into());
    }
    let quote_payment = match args.get("--payment").map(String::as_str) {
        None => "withdraw",
        Some("send") if command == "fees" => "send",
        Some("withdraw") if command == "fees" => "withdraw",
        _ => return Err("--payment send|withdraw is only supported for fees".into()),
    };
    if command == "withdraw-legacy" && args.contains_key("--to") {
        return Err("legacy fixture withdrawal pays the sponsor; no destination override".into());
    }
    Ok(Some(Arguments {
        command,
        args,
        shielded_paid,
        user_paid,
        quote_payment,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Option<Arguments>> {
        parse_arguments(values.iter().map(|value| (*value).to_owned()))
    }

    fn rejected(values: &[&str], expected: &str) {
        let error = parse(values).err().expect("arguments must be rejected");
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn help_and_command_validation_preserve_cli_behavior() {
        assert!(parse(&[]).unwrap().is_none());
        assert!(parse(&["--help", "--unknown"]).unwrap().is_none());
        rejected(&["unknown"], "unknown wallet command; use --help");
        rejected(&["send", "--unknown"], "unknown option --unknown");
        rejected(&["send", "--amount"], "option is missing its value");
        rejected(
            &["send", "--amount", "1", "--amount", "2"],
            "duplicate option",
        );
    }

    #[test]
    fn fee_modes_and_quote_shape_are_validated_before_state_access() {
        let send = parse(&[
            "send",
            "--fee-payer",
            "shielded",
            "--max-shielded-fee",
            "3000000",
        ])
        .unwrap()
        .unwrap();
        assert!(send.shielded_paid);
        assert!(!send.user_paid);
        assert_eq!(send.args["--max-shielded-fee"], "3000000");
        let withdrawal = parse(&["withdraw", "--fee-payer", "user", "--max-fee-debit", "10"])
            .unwrap()
            .unwrap();
        assert!(withdrawal.user_paid);
        assert_eq!(
            parse(&["fees", "--payment", "send"])
                .unwrap()
                .unwrap()
                .quote_payment,
            "send"
        );
        rejected(
            &["balance", "--fee-payer", "sponsor"],
            "fee selection is only for send/withdraw; reclaim uses the original recorded payer",
        );
        rejected(
            &["send", "--fee-payer", "user", "--sponsor", "unused"],
            "user/shielded fees cannot be combined with operator sponsor options",
        );
        rejected(
            &["send", "--max-fee-debit", "10"],
            "--max-fee-debit requires user-paid send/withdraw fees",
        );
        rejected(
            &["send", "--payment", "send"],
            "--payment send|withdraw is only supported for fees",
        );
        rejected(
            &["withdraw-legacy", "--to", "unused"],
            "legacy fixture withdrawal pays the sponsor; no destination override",
        );
    }
}
