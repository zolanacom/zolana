//! Sign-only bounded ten-tester allocation. Broadcast/recovery belongs to the
//! caller's durable journal; this module never sends a transaction.
use super::*;
use bincode::Options;
use native_wallet::keys::{read_password, read_private, Network, WalletKey};

const AMOUNT: u64 = 6_000_300_000;

fn validate(tx: &Transaction, treasury: Pubkey, recipient: Pubkey) -> Result<()> {
    if treasury == recipient {
        return Err("treasury recipient must be a separate faucet authority".into());
    }
    tx.verify()?;
    let mut expected = Transaction::new_with_payer(
        &[system::transfer(&treasury, &recipient, AMOUNT)],
        Some(&treasury),
    );
    expected.message.recent_blockhash = tx.message.recent_blockhash;
    if tx.message != expected.message || tx.signatures.len() != 1 {
        return Err("only the exact ten-tester treasury allocation may be signed".into());
    }
    Ok(())
}

pub(super) fn run(command: &str, root: &Path, args: &[String]) -> Result<()> {
    // check: wallet, password, saved-signature.json; sign: wallet, password, cold, RPC
    let signing = command == "pilot-treasury-sign";
    if args.len() != if signing { 4 } else { 3 } {
        return Err("invalid treasury arguments".into());
    }
    let config: Value = serde_json::from_slice(&read_private(&root.join("network.json"), 32768)?)?;
    if config["key_mode"] != "local-testnet-rehearsal-v1"
        || config["fixture_keys_are_public"] != false
        || config["raw_rpc_host_isolation"] != true
    {
        return Err("treasury signing requires a private isolated test network".into());
    }
    let network = Network::load(&root.join("network.json"))?;
    let wallet = WalletKey::open(
        Path::new(&args[0]),
        &read_password(Path::new(&args[1]))?,
        &network,
    )?;
    let recipient = wallet.fee_keypair().pubkey();
    let treasury: Pubkey = config["roles"]["treasury"]
        .as_str()
        .ok_or("missing treasury")?
        .parse()?;
    let value = if signing {
        let rpc = native_wallet::rpc::Chain::operator_client(
            &args[3],
            network.clone(),
            &root.join("rpc-access.key"),
        )?;
        if rpc
            .get_balance_with_commitment(&recipient, CommitmentConfig::finalized())?
            .value
            != 0
        {
            return Err(
                "initial treasury destination already funded; preserve original allocation".into(),
            );
        }
        let cold = read_password(Path::new(&args[2]))?;
        let mut roles = native_wallet::operator::open(
            &root.join("operator-recovery.enc.json"),
            &network,
            &cold,
        )?;
        let key = roles.remove("treasury").ok_or("missing treasury role")?;
        if key.pubkey() != treasury {
            return Err("treasury recovery authority changed".into());
        }
        let (hash, height) =
            rpc.get_latest_blockhash_with_commitment(CommitmentConfig::finalized())?;
        let tx = Transaction::new_signed_with_payer(
            &[system::transfer(&treasury, &recipient, AMOUNT)],
            Some(&treasury),
            &[&key],
            hash,
        );
        validate(&tx, treasury, recipient)?;
        let fee = rpc.get_fee_for_message(&tx.message)?;
        if fee > 10_000 {
            return Err("treasury transaction exceeds separate fee cap".into());
        }
        json!({"format":"zolana-pilot-treasury-signature-v1", "genesis_hash":network.genesis_hash,
               "treasury":treasury.to_string(), "recipient":recipient.to_string(), "amount":AMOUNT,
               "fee":fee,"last_valid_block_height":height,"signature":tx.signatures[0].to_string(),
               "transaction":bincode::serialize(&tx)?,"broadcast":false})
    } else {
        let value: Value = serde_json::from_slice(&read_private(Path::new(&args[2]), 16384)?)?;
        let raw = serde_json::from_value::<Vec<u8>>(value["transaction"].clone())?;
        if raw.len() > 1232 {
            return Err("saved treasury transaction exceeds the packet limit".into());
        }
        let tx: Transaction = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(1232)
            .reject_trailing_bytes()
            .deserialize(&raw)?;
        validate(&tx, treasury, recipient)?;
        if value.as_object().ok_or("invalid signature record")?.len() != 10
            || value["format"] != "zolana-pilot-treasury-signature-v1"
            || value["genesis_hash"] != network.genesis_hash
            || value["treasury"] != treasury.to_string()
            || value["recipient"] != recipient.to_string()
            || value["amount"] != AMOUNT
            || value["fee"].as_u64().is_none_or(|v| v > 10_000)
            || value["last_valid_block_height"].as_u64().is_none()
            || value["broadcast"] != false
            || value["signature"] != tx.signatures[0].to_string()
        {
            return Err("saved treasury signature contract changed".into());
        }
        value
    };
    println!("{}", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_amount_destination_authority_and_signature_are_required() {
        let key = Keypair::new();
        let to = Pubkey::new_unique();
        let tx = Transaction::new_signed_with_payer(
            &[system::transfer(&key.pubkey(), &to, AMOUNT)],
            Some(&key.pubkey()),
            &[&key],
            solana_hash::Hash::new_unique(),
        );
        validate(&tx, key.pubkey(), to).unwrap();
        assert!(validate(&tx, key.pubkey(), Pubkey::new_unique()).is_err());
        assert!(validate(&tx, Pubkey::new_unique(), to).is_err());
        let other = Transaction::new_signed_with_payer(
            &[system::transfer(&key.pubkey(), &to, AMOUNT + 1)],
            Some(&key.pubkey()),
            &[&key],
            tx.message.recent_blockhash,
        );
        assert!(validate(&other, key.pubkey(), to).is_err());
        let mut broken = tx;
        broken.message.recent_blockhash = solana_hash::Hash::new_unique();
        assert!(validate(&broken, key.pubkey(), to).is_err());
    }
}
