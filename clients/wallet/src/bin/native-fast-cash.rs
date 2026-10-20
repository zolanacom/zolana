//! Isolated synthetic fixture CLI, not an update to an existing wallet app.
use native_wallet::{
    keys::read_password,
    rpc::fast::{relay_init, Session},
    Result,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{BufRead, Read, Write},
    path::Path,
};

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or("expected relay-init|serve")?;
    let mut options = BTreeMap::new();
    let mut resume = false;
    while let Some(key) = args.next() {
        if key == "--resume" {
            resume = true;
            continue;
        }
        if !["--output", "--profile", "--directory", "--password-file"].contains(&key.as_str()) {
            return Err("unknown native fixture option".into());
        }
        if options
            .insert(key, args.next().ok_or("missing option value")?)
            .is_some()
        {
            return Err("duplicate fixture option".into());
        }
    }
    let get = |key: &str| -> Result<&str> {
        options
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {key}").into())
    };
    if command == "relay-init" {
        if resume || options.len() != 1 {
            return Err("relay-init takes only --output NEW_PRIVATE_KEY".into());
        }
        println!("{}", relay_init(Path::new(get("--output")?))?);
        return Ok(());
    }
    if command != "serve" || options.len() != 3 || options.contains_key("--output") {
        return Err(
            "serve --profile FILE --directory FRESH_FIXTURE --password-file FILE [--resume]".into(),
        );
    }
    let password = read_password(Path::new(get("--password-file")?))?;
    let mut session = Session::open(
        Path::new(get("--profile")?),
        Path::new(get("--directory")?),
        &password,
        resume,
    )?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut raw = Vec::new();
        let read = (&mut input).take(32_769).read_until(b'\n', &mut raw)?;
        if read == 0 {
            break;
        }
        if raw.len() > 32_768 || raw.last() != Some(&b'\n') {
            return Err("bounded newline-delimited fixture request required".into());
        }
        let request: Value = serde_json::from_slice(&raw)?;
        let result = match session.request(&request) {
            Ok(value) => json!({"id": request["id"], "result": value}),
            Err(error) => json!({"id": request["id"], "error": error.to_string()}),
        };
        serde_json::to_writer(&mut output, &result)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Native fixture: {error}");
        std::process::exit(1);
    }
}
