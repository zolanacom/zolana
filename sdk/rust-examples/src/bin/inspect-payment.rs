//! Print what a payment's bytes say and prove.
//!
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --bin inspect-payment -- sdk/fixtures/shielded-send.hex
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --bin inspect-payment -- --json <file | hex | base64 | ->
//!
//! Offline: no RPC and no ledger. The input is a payment or an inline envelope,
//! as raw bytes, hex or base64, in a file, as the argument itself, or on
//! standard input (`-`). `--network <64 hex digits>` refuses any other network.
//!
//! Exit status: 0 when the signatures and the proof are valid, 1 when the
//! bytes decode but do not verify, 2 when they cannot be read or decoded.
use std::{io::Read, process::ExitCode};
use zolana_sdk_examples::inspect::{inspect, parse_input, verifying_key};

fn main() -> ExitCode {
    match run() {
        Ok(verified) => ExitCode::from(u8::from(!verified)),
        Err(error) => {
            eprintln!("inspect-payment: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let (mut json, mut network, mut source) = (false, None, None);
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--json" => json = true,
            "--network" => {
                let text = arguments.next().ok_or("--network needs 64 hex digits")?;
                let bytes = parse_input(text.as_bytes())?;
                network =
                    Some(<[u8; 32]>::try_from(bytes).map_err(|_| "--network needs 64 hex digits")?);
            }
            _ if source.is_none() => source = Some(argument),
            _ => {
                return Err(
                    "usage: inspect-payment [--json] [--network <hex>] <file | hex | base64 | ->"
                        .into(),
                )
            }
        }
    }
    let source = source
        .ok_or("usage: inspect-payment [--json] [--network <hex>] <file | hex | base64 | ->")?;
    let input = if source == "-" {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes)?;
        bytes
    } else if std::path::Path::new(&source).is_file() {
        std::fs::read(&source)?
    } else {
        source.into_bytes()
    };
    let bytes = parse_input(&input)?;
    // Building the verifying key is the slow part of a run.
    let report = inspect(&bytes, network, &verifying_key())
        .map_err(|error| format!("these bytes are not a payment this code decodes: {error}"))?;
    if json {
        println!("{}", report.json());
    } else {
        print!("{}", report.text());
    }
    Ok(report.verification.is_ok())
}
