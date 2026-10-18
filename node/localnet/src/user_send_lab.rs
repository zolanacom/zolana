//! Bounded duplicate-proof probe for local private rehearsals only.
use super::*;
use native_wallet::{
    keys::{read_password, Network, WalletKey},
    operation::WalletOperation,
    rpc::Chain,
};

pub fn replay(root: &Path, args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err("expected encrypted replay wallet, user password file and loopback RPC".into());
    }
    let config: Value = serde_json::from_slice(&fs::read(root.join("network.json"))?)?;
    if config["key_mode"] != "local-testnet-rehearsal-v1"
        || config["fixture_keys_are_public"] != false
        || root.is_symlink()
        || root.metadata()?.permissions().mode() & 0o077 != 0
    {
        return Err("duplicate probe requires an owner-only private local rehearsal".into());
    }
    let wallet_path = Path::new(&args[0]);
    if wallet_path.parent() != Some(root.join("wallets").as_path())
        || !wallet_path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with("-replay.wallet.json"))
    {
        return Err(
            "duplicate probe requires a separate restored replay wallet in this fixture".into(),
        );
    }
    let network = Network::load(&root.join("network.json"))?;
    let wallet = WalletKey::open(wallet_path, &read_password(Path::new(&args[1]))?, &network)?;
    let payer = wallet.fee_keypair();
    let bytes = fs::read(root.join("restart-spent-payment.bin"))?;
    let payment = wire::decode(network.network, &bytes)?;
    if payment.context.public_value_balance != 0
        || payment.context.withdrawal_recipient.is_some()
        || payment.context.sponsor != payer.pubkey().to_bytes()
    {
        return Err(
            "duplicate probe requires this user's already accepted private-send proof".into(),
        );
    }
    let rpc = client(&args[2], &config)?;
    let before = pool(&rpc)?.0;
    let markers = marker_receipt(&rpc, network.network, &[&bytes])?;
    for action in payment.bundle.actions().iter() {
        let key = nullifiers::address(&action.nullifier().to_bytes());
        if rpc.get_account(&key)?.owner != id() {
            return Err("proof is not already spent".into());
        }
    }
    let operation = WalletOperation::acquire(wallet_path)?;
    let chain = Chain::connect(&args[2], network)?.with_user_fees(
        payer.pubkey(),
        150_000_000,
        &operation,
    )?;
    // Restage exact public proof bytes under a new buffer with the ordinary
    // durable cap. The finalizer must reject permanent spent-note accounts.
    let error = match chain.submit(&payer, &bytes, &operation) {
        Ok(_) => return Err("already spent private-send proof was accepted".into()),
        Err(error) => error.to_string(),
    };
    if !error.contains("Instruction 1: invalid instruction data") {
        return Err(format!("duplicate proof failed for an unexpected reason: {error}").into());
    }
    if pool(&rpc)?.0 != before {
        return Err("duplicate proof changed the native pool".into());
    }
    check_markers(&rpc, &markers)?;
    println!(
        "{}",
        json!({"spent_proof_rejected":true,"original_nullifiers_unchanged":true,
        "gross_debit_cap":150_000_000,
        "pending_retained":PathBuf::from(format!("{}.pending.json",wallet_path.display())).exists(),
        "staging_retained":PathBuf::from(format!("{}.staging.json",wallet_path.display())).exists()})
    );
    Ok(())
}
