use native_wallet::{
    access, faucet,
    keys::{read_password, read_password_input},
    Result,
};
use std::{collections::BTreeMap, path::Path};
fn history_for_tick<'a>(
    command: &str,
    options: &'a BTreeMap<String, String>,
) -> Result<Option<&'a Path>> {
    match options.get("--history") {
        None => Ok(None),
        Some(path) if matches!(command, "tick" | "continue-grant-once" | "warm-grant-history") && !path.is_empty() => Ok(Some(Path::new(path))),
        Some(_) => Err("retained history is only supported for tick, warm-grant-history or continue-grant-once with a nonempty path".into()),
    }
}

fn operator_mode_options(command: &str, options: &BTreeMap<String, String>) -> Result<()> {
    if matches!(command, "continue-grant-once" | "warm-grant-history") {
        let allowed = if command == "continue-grant-once" {
            vec![
                "--root",
                "--password-file",
                "--history",
                "--claim-id",
                "--progress-sha256",
            ]
        } else {
            vec!["--root", "--password-file", "--history"]
        };
        if options.len() != allowed.len()
            || allowed
                .iter()
                .any(|name| options.get(*name).is_none_or(|value| value.is_empty()))
            || options.get("--password-file").map(String::as_str) != Some("-")
        {
            return Err(
                "operator history modes require exact explicit options and password stdin".into(),
            );
        }
        if command == "continue-grant-once"
            && ["--claim-id", "--progress-sha256"].iter().any(|name| {
                let value = &options[*name];
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("explicit lowercase claim ID and progress SHA-256 required".into());
        }
    } else if options.contains_key("--claim-id") || options.contains_key("--progress-sha256") {
        return Err("claim continuation pins are only supported for continue-grant-once".into());
    }
    Ok(())
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or("expected init|init-native|accept|tick|warm-grant-history|continue-grant-once")?;
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
            "--history",
            "--claim-id",
            "--progress-sha256",
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
    let history = history_for_tick(&command, &options)?;
    operator_mode_options(&command, &options)?;
    if command != "authorize-many" && options.contains_key("--units") {
        return Err("authorization units are only supported for authorize-many".into());
    }
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
        "accept" | "join" | "access-status" | "authorize" | "authorize-many" => {
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
                "authorize-many" => access::authorize_many(
                    root,
                    serde_json::from_slice(&raw)?,
                    get("--units")?.parse()?,
                )?,
                _ => access::authorize(root, serde_json::from_slice(&raw)?)?,
            }
        }
        "init" | "init-native" | "tick" | "continue-grant-once" | "warm-grant-history" => {
            let p = if get("--password-file")? == "-" {
                read_password_input(std::io::stdin().lock())?
            } else {
                read_password(Path::new(get("--password-file")?))?
            };
            if command == "init-native" {
                faucet::initialize_native(
                    root,
                    Path::new(get("--profile")?),
                    &p,
                    get("--max-claims")?.parse()?,
                    options.get("--rpc-access-file").map(Path::new),
                )?
            } else if command == "init" {
                faucet::initialize_with_rpc(
                    root,
                    Path::new(get("--profile")?),
                    &p,
                    get("--max-claims")?.parse()?,
                    options.get("--rpc-access-file").map(Path::new),
                )?
            } else if command == "continue-grant-once" {
                faucet::continue_grant_once(
                    root,
                    &p,
                    get("--claim-id")?,
                    get("--progress-sha256")?,
                    history.ok_or("explicit retained history required")?,
                )?
            } else if command == "warm-grant-history" {
                faucet::warm_grant_history(
                    root,
                    &p,
                    history.ok_or("explicit retained history required")?,
                )?
            } else {
                faucet::tick_with_history(root, &p, history)?
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

#[cfg(test)]
mod history_cli_tests {
    use super::*;

    #[test]
    fn retained_history_is_explicit_worker_only_and_never_an_init_option() {
        let options = BTreeMap::from([("--history".into(), "/verified/archive".into())]);
        assert_eq!(
            history_for_tick("tick", &options).unwrap(),
            Some(Path::new("/verified/archive"))
        );
        for command in [
            "init",
            "init-native",
            "accept",
            "join",
            "invite-issue",
            "access-init",
            "authorize",
        ] {
            assert!(history_for_tick(command, &options).is_err(), "{command}");
        }
    }

    #[test]
    fn operator_modes_require_exact_options_history_and_password_stdin() {
        let warm = BTreeMap::from([
            ("--root".into(), "/owned/faucet".into()),
            ("--password-file".into(), "-".into()),
            ("--history".into(), "/verified/archive".into()),
        ]);
        assert!(operator_mode_options("warm-grant-history", &warm).is_ok());
        assert!(history_for_tick("warm-grant-history", &warm)
            .unwrap()
            .is_some());
        let mut once = warm.clone();
        once.insert("--claim-id".into(), "1".repeat(64));
        once.insert("--progress-sha256".into(), "2".repeat(64));
        assert!(operator_mode_options("continue-grant-once", &once).is_ok());
        assert!(history_for_tick("continue-grant-once", &once)
            .unwrap()
            .is_some());
        assert!(operator_mode_options("tick", &once).is_err());
        let mut invalid = once.clone();
        invalid.insert("--progress-sha256".into(), "not-a-pin".into());
        assert!(operator_mode_options("continue-grant-once", &invalid).is_err());
        for command in ["continue-grant-once", "warm-grant-history"] {
            let valid = if command == "continue-grant-once" {
                &once
            } else {
                &warm
            };
            let mut missing = valid.clone();
            missing.remove("--history");
            assert!(operator_mode_options(command, &missing).is_err());
            let mut file = valid.clone();
            file.insert("--password-file".into(), "/secret/file".into());
            assert!(operator_mode_options(command, &file).is_err());
            let mut extra = valid.clone();
            extra.insert("--profile".into(), "/replacement".into());
            assert!(operator_mode_options(command, &extra).is_err());
        }
    }

    #[test]
    fn absent_history_preserves_existing_commands_and_empty_path_is_rejected() {
        let absent = BTreeMap::new();
        for command in ["tick", "init", "init-native", "join"] {
            assert!(history_for_tick(command, &absent).unwrap().is_none());
        }
        let empty = BTreeMap::from([("--history".into(), String::new())]);
        assert!(history_for_tick("tick", &empty).is_err());
    }
}
