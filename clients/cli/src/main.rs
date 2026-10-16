use payment_lab::proof_smoke;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("proof-smoke") => {
            println!("Offline synthetic payment fixture; no network, ledger or real funds.");
            let fixture = proof_smoke::build_fixture()?;
            let report = fixture.check()?;
            println!("Real Orchard proof, spend signatures and binding signature: verified");
            println!("Receiver decrypted the payment and sender recovered change.");
            println!(
                "Staged payload: {} bytes in {} chunks",
                report.payload_bytes, report.chunks
            );
            println!(
                "Fixture construction: {} ms; validation: {} ms",
                report.build_ms, report.verify_ms
            );
            println!("Native Agave integration and supply accounting remain pending.");
        }
        None | Some("--help") | Some("-h") => {
            println!("Usage: payment-lab proof-smoke");
            println!("Runs an offline cryptographic fixture, not a deployed-chain payment.");
        }
        Some(_) => return Err("Unknown command; use --help".into()),
    }
    Ok(())
}
