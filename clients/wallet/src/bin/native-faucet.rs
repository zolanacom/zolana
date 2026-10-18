use native_wallet::{
    access, faucet,
    keys::{read_password, read_password_input},
    Result,
};
use std::{collections::BTreeMap, path::Path};
fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or("expected init|accept|tick")?;
    let mut options = BTreeMap::new();
    while let Some(flag) = args.next() {
        if ![
            "--root",
            "--profile",
            "--password-file",
            "--max-claims",
            "--request-file",
            "--rpc-access-file",
            "--output",
            "--expires-in",
            "--bind-fee",
            "--invite-id",
            "--daily-admissions",
            "--rpc-limit",
            "--channel",
            "--peer",
            "--units",
        ]
        .contains(&flag.as_str())
        {
            return Err("unknown faucet option".into());
        }
        if options
            .insert(flag, args.next().ok_or("missing option value")?)
            .is_some()
        {
            return Err("duplicate faucet option".into());
        }
    }
    let get = |name: &str| -> Result<&str> {
        options
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {name}").into())
    };
    let root = Path::new(get("--root")?);
    let result = match command.as_str() {
        "access-init" => access::initialize(
            root,
            Path::new(get("--profile")?),
            get("--daily-admissions")?.parse()?,
            get("--rpc-limit")?.parse()?,
        )?,
        "access-info" => access::info(root)?,
        "invite-issue" => access::issue(
            root,
            Path::new(get("--output")?),
            get("--expires-in")?.parse()?,
            options.get("--bind-fee").cloned(),
        )?,
        "invite-revoke" => access::revoke(root, get("--invite-id")?)?,
        "edge" => access::edge(root, get("--channel")?, get("--peer")?)?,
        "accept" | "join" | "access-status" | "authorize" => {
            let raw = std::fs::read(get("--request-file")?)?;
            if raw.len() > 4096 {
                return Err("access request exceeds limit".into());
            }
            match command.as_str() {
                "accept" => faucet::accept(root, serde_json::from_slice(&raw)?)?,
                "join" => access::join(root, serde_json::from_slice(&raw)?)?,
                "access-status" => {
                    access::status(root, serde_json::from_slice::<access::Status>(&raw)?.proof)?
                }
                _ => access::authorize_units(
                    root,
                    serde_json::from_slice(&raw)?,
                    options
                        .get("--units")
                        .map(|s| s.parse())
                        .transpose()?
                        .unwrap_or(1),
                )?,
            }
        }
        "init" | "tick" => {
            let p = if get("--password-file")? == "-" {
                read_password_input(std::io::stdin().lock())?
            } else {
                read_password(Path::new(get("--password-file")?))?
            };
            if command == "init" {
                faucet::initialize_with_rpc(
                    root,
                    Path::new(get("--profile")?),
                    &p,
                    get("--max-claims")?.parse()?,
                    options.get("--rpc-access-file").map(Path::new),
                )?
            } else {
                faucet::tick(root, &p)?
            }
        }
        _ => return Err("unknown faucet command".into()),
    };
    println!("{}", result);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Faucet error: {e}");
        std::process::exit(1);
    }
}
