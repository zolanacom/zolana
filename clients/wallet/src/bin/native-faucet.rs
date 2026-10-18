use native_wallet::{
    faucet,
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
    let result = if command == "accept" {
        let raw = std::fs::read(get("--request-file")?)?;
        if raw.len() > 2048 {
            return Err("claim exceeds limit".into());
        }
        faucet::accept(root, serde_json::from_slice(&raw)?)?
    } else {
        let p = if get("--password-file")? == "-" {
            read_password_input(std::io::stdin().lock())?
        } else {
            read_password(Path::new(get("--password-file")?))?
        };
        match command.as_str() {
            "init" => faucet::initialize(
                root,
                Path::new(get("--profile")?),
                &p,
                get("--max-claims")?.parse()?,
            )?,
            "tick" => faucet::tick(root, &p)?,
            _ => return Err("unknown faucet command".into()),
        }
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
