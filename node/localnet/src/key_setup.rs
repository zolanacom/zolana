//! Local-only rehearsal ceremony; development economics are not launch parameters.
use super::*;
use native_wallet::{
    keys::{read_password, read_password_input, write_private_new, Network},
    operator::{self, Roles},
    sponsor::Policy,
};
use solana_account::ReadableAccount;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn passwords(args: &[String], names: &[&str]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    if args.len() != names.len() * 2 {
        return Err("expected explicit operator password file options".into());
    }
    let mut stdin_used = false;
    names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            if args[index * 2] != *name {
                return Err(format!("expected {name}").into());
            }
            let path = &args[index * 2 + 1];
            if path == "-" {
                if stdin_used {
                    return Err("only one password can use stdin".into());
                }
                stdin_used = true;
                Ok(read_password_input(std::io::stdin().lock())?)
            } else {
                Ok(read_password(Path::new(path))?)
            }
        })
        .collect()
}
pub(super) fn initialize_private(root: &Path, args: &[String]) -> Result<()> {
    let p = passwords(args, &["--cold-password-file", "--sponsor-password-file"])?;
    if p[0] == p[1] {
        return Err("cold and sponsor passwords must differ".into());
    }
    initialize(root, Some((&p[0], &p[1])))
}
// There are fourteen independent CSPRNG keys. Only identity/voter keys are hot.
#[allow(clippy::too_many_arguments)]
pub(super) fn save(
    root: &Path,
    network: &Network,
    nodes: &[ValidatorVoteKeypairs; 2],
    voters: &[Keypair; 2],
    withdrawers: &[Keypair; 2],
    stake_controls: &[Keypair; 2],
    treasury: &Keypair,
    sponsor: &Keypair,
    cold_password: &[u8],
    sponsor_password: &[u8],
) -> Result<BTreeMap<String, String>> {
    let copy = |key: &Keypair| Keypair::try_from(key.to_bytes().as_slice()).expect("valid keypair");
    let mut roles = Roles::new();
    for (index, node) in nodes.iter().enumerate() {
        for (name, key) in [
            ("identity", &node.node_keypair),
            ("vote-account", &node.vote_keypair),
            ("stake-account", &node.stake_keypair),
            ("voter", &voters[index]),
            ("vote-withdrawer", &withdrawers[index]),
            ("stake-control", &stake_controls[index]),
        ] {
            roles.insert(format!("{name}-{index}"), copy(key));
        }
    }
    roles.insert("treasury".into(), copy(treasury));
    roles.insert("sponsor".into(), copy(sponsor));
    let public = operator::public_roles(&roles);
    operator::save(
        &root.join("operator-recovery.enc.json"),
        network,
        &roles,
        cold_password,
    )?;
    let hot = Roles::from([("sponsor".into(), copy(sponsor))]);
    operator::save(
        &root.join("sponsor.enc.json"),
        network,
        &hot,
        sponsor_password,
    )?;
    // Read back and authenticate both files before publishing usable config.
    if operator::public_roles(&operator::open(
        &root.join("operator-recovery.enc.json"),
        network,
        cold_password,
    )?) != public
        || operator::public_roles(&operator::open(
            &root.join("sponsor.enc.json"),
            network,
            sponsor_password,
        )?) != operator::public_roles(&hot)
    {
        return Err("encrypted operator backup read-back failed".into());
    }
    Policy {
        format: "native-sponsor-policy-v1".into(),
        network: network.clone(),
        sponsor: sponsor.pubkey().to_string(),
        operation_allowance: 150_000_000,
        lifetime_allowance: 900_000_000,
        max_deposit: 100,
        max_send: 1_000_000_000,
        max_requests_per_wallet: 3,
    }
    .create(&root.join("sponsor-policy.json"))?;
    fs::File::open(root)?.sync_all()?;
    Ok(public)
}
fn verified_recovery(root: &Path, password: &[u8]) -> Result<(Network, Roles)> {
    let network = Network::load(&root.join("network.json"))?;
    let config: Value = serde_json::from_slice(&fs::read(root.join("network.json"))?)?;
    let roles = operator::open(&root.join("operator-recovery.enc.json"), &network, password)?;
    let genesis = solana_genesis_config::GenesisConfig::load(&root.join("ledger-0"))?;
    if config["key_mode"] != "local-testnet-rehearsal-v1"
        || config["roles"] != serde_json::to_value(operator::public_roles(&roles))?
        || genesis.hash().to_string() != network.genesis_hash
        || roles.len() != 14
    {
        return Err("operator recovery manifest/genesis mismatch".into());
    }
    let unique: std::collections::BTreeSet<_> = roles.values().map(|key| key.pubkey()).collect();
    if unique.len() != 14 {
        return Err("operator roles must use distinct keys".into());
    }
    let key = |name: &str| -> Result<Pubkey> {
        Ok(roles.get(name).ok_or("missing recovery role")?.pubkey())
    };
    for index in 0..2 {
        let identity = key(&format!("identity-{index}"))?;
        let vote_address = key(&format!("vote-account-{index}"))?;
        if config["identities"][index] != identity.to_string()
            || config["vote_accounts"][index] != vote_address.to_string()
        {
            return Err("validator role/config mismatch".into());
        }
        let original_vote = genesis
            .accounts
            .get(&vote_address)
            .ok_or("vote account missing in genesis")?;
        let vote = solana_vote_program::vote_state::create_account_with_authorized(
            &identity,
            &key(&format!("voter-{index}"))?,
            &key(&format!("vote-withdrawer-{index}"))?,
            0,
            original_vote.lamports,
        );
        let original_stake = genesis
            .accounts
            .get(&key(&format!("stake-account-{index}"))?)
            .ok_or("stake account missing in genesis")?;
        let stake = solana_stake_program::stake_state::create_account(
            &key(&format!("stake-control-{index}"))?,
            &vote_address,
            &vote,
            &genesis.rent,
            original_stake.lamports,
        );
        if original_vote.data != vote.data() || original_stake.data != stake.data() {
            return Err("genesis vote/stake authorities differ from recovery roles".into());
        }
    }
    for role in ["treasury", "sponsor"] {
        if genesis
            .accounts
            .get(&key(role)?)
            .is_none_or(|account| account.owner != solana_sdk_ids::system_program::id())
        {
            return Err("genesis funding role mismatch".into());
        }
    }
    Ok((network, roles))
}
pub(super) fn restore_hot(root: &Path, args: &[String]) -> Result<()> {
    let p = passwords(args, &["--cold-password-file"])?;
    let (network, roles) = verified_recovery(root, &p[0])?;
    // Validate every existing target before writing any missing file.
    let mut missing = vec![];
    for index in 0..2 {
        for role in ["identity", "voter"] {
            let name = format!("{role}-{index}");
            let key = roles.get(&name).ok_or("missing hot recovery role")?;
            let path = root.join(format!("{name}.keypair.json"));
            if path.symlink_metadata().is_ok() {
                let bytes = Zeroizing::new(serde_json::from_slice::<Vec<u8>>(
                    &native_wallet::keys::read_private(&path, 4096)?,
                )?);
                if Keypair::try_from(bytes.as_slice())?.pubkey() != key.pubkey() {
                    return Err("existing hot key differs; refusing replacement".into());
                }
            } else {
                missing.push((path, key));
            }
        }
    }
    let count = missing.len();
    for (path, key) in missing {
        let raw = Zeroizing::new(serde_json::to_vec(&key.to_bytes().as_slice())?);
        write_private_new(&path, &raw)?;
    }
    fs::File::open(root)?.sync_all()?;
    println!(
        "{}",
        json!({"restored_hot_files":count,"cold_roles_exported":false,"genesis_hash":network.genesis_hash})
    );
    Ok(())
}
pub(super) fn restore_sponsor(root: &Path, args: &[String]) -> Result<()> {
    let p = passwords(args, &["--cold-password-file", "--sponsor-password-file"])?;
    if p[0] == p[1] {
        return Err("cold and sponsor passwords must differ".into());
    }
    let (network, mut roles) = verified_recovery(root, &p[0])?;
    let sponsor = roles.remove("sponsor").ok_or("missing sponsor role")?;
    // Restore only encrypted hot material; never recreate/reset the policy ledger.
    let policy: Value = serde_json::from_slice(&native_wallet::keys::read_private(
        &root.join("sponsor-policy.json"),
        4096,
    )?)?;
    if policy["sponsor"] != sponsor.pubkey().to_string()
        || !root.join("sponsor-policy.json.reservations.json").is_file()
    {
        return Err("original sponsor policy/ledger required for restoration".into());
    }
    operator::save(
        &root.join("sponsor.enc.json"),
        &network,
        &Roles::from([("sponsor".into(), sponsor)]),
        &p[1],
    )?;
    fs::File::open(root)?.sync_all()?;
    println!(
        "{}",
        json!({"encrypted_sponsor_restored":true,"policy_reset":false,"genesis_hash":network.genesis_hash})
    );
    Ok(())
}
