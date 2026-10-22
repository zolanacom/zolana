//! Network-free verifier for public disposable browser proof packets.
use std::io::{Read, Write};
fn main() {
    let result = (|| -> Result<(), String> {
        if std::env::args_os().len() != 1 {
            return Err("this verifier accepts only a bounded public fixture on stdin".into());
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take((browser_core::MAX_FIXTURE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let raw = std::str::from_utf8(&bytes).map_err(|_| "fixture must be UTF-8")?;
        let report = browser_core::check_public_fixture(raw)?;
        let output = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
        std::io::stdout()
            .write_all(&output)
            .map_err(|e| e.to_string())?;
        println!();
        Ok(())
    })();
    if result.is_err() {
        eprintln!("Synthetic browser proof verification failed; no network or wallet operation was performed.");
        std::process::exit(1);
    }
}
