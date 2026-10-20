//! Disposable local-network tooling. Fixture spending keys are intentionally public.
mod fault_lab;
mod key_setup;
mod load_lab;
mod pilot_treasury;
mod user_send_lab;
// Exercise the exact validator fault guard in a first-party workspace target.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../agave/validator/src/commands/run/local_fault.rs"]
mod local_fault_guard_tests;
use native_payment_program::{
    id, instructions, nullifiers, pool_address, staging::ACCOUNT_BYTES, ACTIVATION_ID,
};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::{PoolState, STATE_BYTES},
    wire,
};
use payment_lab::proof_smoke::{build_fixture_for_network, withdrawal_fixture};
use serde_json::{json, Value};
use solana_account::AccountSharedData;
use solana_cluster_type::ClusterType;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_epoch_schedule::EpochSchedule;
use solana_fee_calculator::FeeRateGovernor;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::{read_keypair_file, write_keypair_file, Keypair};
use solana_ledger::{
    blockstore::{create_new_ledger, Blockstore},
    blockstore_options::LedgerColumnOptions,
};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_runtime::genesis_utils::{
    activate_feature, create_genesis_config_with_leader_ex_no_features, ValidatorVoteKeypairs,
};
use solana_signer::Signer;
use solana_system_interface::instruction as system;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

mod tail_diagnostic;

mod restart_tail;

// Primary RocksDB access rejects inspection while a validator owns the ledger.
// No slots, hashes, or tower lockouts are altered by this inspection.
fn restart_state(root: &Path, index: usize, name: &str, replay_plan: bool) -> Result<()> {
    use solana_core::consensus::{tower_storage::FileTowerStorage, Tower};
    if index > 1
        || !name.starts_with("ledger-")
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("invalid local validator or ledger".into());
    }
    let identity = read_keypair_file(root.join(format!("identity-{index}.keypair.json")))?;
    let genesis = solana_genesis_config::GenesisConfig::load(&root.join(name))?;
    let tower = Tower::restore(
        &FileTowerStorage::new(root.join(format!("consensus-{index}"))),
        &identity.pubkey(),
    )?;
    let blockstore = Blockstore::open(&root.join(name))?;
    let highest_stored_slot = blockstore.highest_slot()?.ok_or("empty restart ledger")?;
    let (vote_slot, vote_hash) = tower.last_voted_slot_hash().ok_or("empty voting tower")?;
    if blockstore.get_bank_hash(vote_slot) != Some(vote_hash) {
        return Err("signed tower vote does not match retained bank hash".into());
    }
    let floor = tower.root().max(blockstore.max_root());
    let mut nodes = std::collections::BTreeMap::new();
    for (slot, meta) in blockstore.slot_meta_iterator(floor)? {
        nodes.insert(
            slot,
            restart_tail::Meta {
                parent: meta.parent_slot,
                full: meta.is_full(),
                frozen: blockstore.get_bank_hash(slot).is_some(),
                dead: blockstore.is_dead(slot),
                duplicate: blockstore.has_duplicate_shreds_in_slot(slot),
            },
        );
        if nodes.len() > 4096 {
            return Err("unrooted restart inventory exceeds limit".into());
        }
    }
    let tail = restart_tail::plan(&nodes, vote_slot, floor)?;
    let mut vote_data_slot = vote_slot;
    let mut vote_ancestry_complete = true;
    while vote_data_slot > floor {
        let node = nodes
            .get(&vote_data_slot)
            .ok_or("missing signed-vote data ancestry")?;
        vote_ancestry_complete &= node.full;
        vote_data_slot = node.parent.ok_or("missing signed-vote data parent")?;
    }
    let slot = tail.checkpoint;
    let complete_tail = tail.complete_child;
    // Unfrozen records stay in place for normal post-barrier verification.
    // Managed launches MUST use --native-restart-checkpoint, which enforces
    // this frozen bank before gossip coordination and original tower restore.
    let _ = replay_plan;
    let bank_hash = blockstore
        .get_bank_hash(slot)
        .ok_or("restart tip has no adjacent frozen checkpoint; refusing rollback")?;
    if blockstore.is_dead(slot) || blockstore.has_duplicate_shreds_in_slot(slot) {
        return Err("restart checkpoint is dead or has duplicate shreds".into());
    }
    if tower.root() >= slot || blockstore.max_root() >= slot {
        return Err(
            "tower is ahead of checkpoint or checkpoint would discard tower restoration".into(),
        );
    }
    let (vote_slot, vote_hash) = tower.last_voted_slot_hash().ok_or("empty voting tower")?;
    if blockstore.get_bank_hash(vote_slot) != Some(vote_hash) {
        return Err("signed tower vote does not match retained bank hash".into());
    }
    let mut ancestor = slot.max(vote_slot);
    let lower = slot.min(vote_slot);
    while ancestor > lower {
        let parent = blockstore
            .meta(ancestor)?
            .and_then(|meta| meta.parent_slot)
            .ok_or("checkpoint has incomplete ancestry")?;
        if parent >= ancestor {
            return Err("invalid checkpoint ancestry".into());
        }
        ancestor = parent;
    }
    if ancestor != lower {
        return Err("checkpoint and signed tower vote are not on the same branch".into());
    }
    let mut hashes = serde_json::Map::new();
    let mut restart_ancestors = serde_json::Map::new();
    let mut current = slot;
    for _ in 0..4096 {
        let Some(meta) = blockstore.meta(current)? else {
            break;
        };
        let Some(hash) = blockstore.get_bank_hash(current) else {
            break;
        };
        if !meta.is_full()
            || blockstore.is_dead(current)
            || blockstore.has_duplicate_shreds_in_slot(current)
        {
            break;
        }
        restart_ancestors.insert(current.to_string(),json!({"bank_hash":hash.to_string(),"epoch":genesis.epoch_schedule.get_epoch(current),"leader_schedule_epoch":genesis.epoch_schedule.get_leader_schedule_epoch(current)}));
        if current == 0 {
            break;
        }
        let Some(parent) = meta.parent_slot else {
            break;
        };
        if parent >= current {
            return Err("invalid retained restart ancestor".into());
        }
        current = parent;
    }
    let mut shreds = serde_json::Map::new();
    let mut dead_slots = Vec::new();
    let mut duplicate_slots = Vec::new();
    for (stored_slot, _) in blockstore.slot_meta_iterator(0)? {
        if blockstore.is_dead(stored_slot) {
            dead_slots.push(stored_slot);
        }
        if blockstore.has_duplicate_shreds_in_slot(stored_slot) {
            duplicate_slots.push(stored_slot);
        }
        if let Some(hash) = blockstore.get_bank_hash(stored_slot) {
            hashes.insert(stored_slot.to_string(), json!(hash.to_string()));
        }
        for (kind, values) in [
            (
                "data",
                blockstore
                    .slot_data_iterator(stored_slot, 0)?
                    .collect::<Vec<_>>(),
            ),
            (
                "coding",
                blockstore
                    .slot_coding_iterator(stored_slot, 0)?
                    .collect::<Vec<_>>(),
            ),
        ] {
            for ((_, index), bytes) in values {
                let digest = blake2b_simd::Params::new().hash_length(32).hash(&bytes);
                shreds.insert(
                    format!("{stored_slot}/{kind}/{index}"),
                    json!(digest.to_hex().as_str()),
                );
            }
        }
    }
    println!(
        "{}",
        json!({
            "slot": slot, "bank_hash": bank_hash.to_string(), "tower_root": tower.root(),
            "highest_stored_slot": highest_stored_slot,
            "complete_tail_replay_slot": complete_tail,
            "complete_tail_replay_epoch":complete_tail.map(|slot|genesis.epoch_schedule.get_epoch(slot)),
            "root_epoch":genesis.epoch_schedule.get_epoch(floor),
            "root_leader_schedule_epoch":genesis.epoch_schedule.get_leader_schedule_epoch(floor),
            "restart_ancestors":restart_ancestors,
            "retained_partial_slots":tail.partial,"retained_competing_slots":tail.competing,
            "retained_rejected_slots":tail.rejected,
            "retained_complete_slots":tail.complete,
            "startup_replay_checkpoint":slot,
            "retained_future_tower_vote":(vote_slot>slot).then_some(vote_slot),
            "blockstore_root": blockstore.max_root(),
            "frozen_hashes": hashes, "shred_digests": shreds,
            "dead_slots":dead_slots,"duplicate_slots":duplicate_slots,
            "last_vote": tower.last_voted_slot(), "identity": identity.pubkey().to_string(),
            "last_vote_data_complete":nodes.get(&vote_slot).is_some_and(|node|node.full),
            "last_vote_ancestry_complete":vote_ancestry_complete,
            "genesis_hash": genesis.hash().to_string(),
            "shred_version": solana_shred_version::compute_shred_version(&genesis.hash(), None)
        })
    );
    Ok(())
}

fn save_key(root: &Path, name: &str, key: &Keypair) -> Result<()> {
    let path = root.join(name);
    let raw = zeroize::Zeroizing::new(serde_json::to_vec(&key.to_bytes().as_slice())?);
    native_wallet::keys::write_private_new(&path, &raw)
}

fn initialize(root: &Path, passwords: Option<(&[u8], &[u8])>) -> Result<()> {
    if root.exists() {
        return Err("refusing to replace an existing local network".into());
    }
    use std::os::unix::fs::DirBuilderExt;
    if let Some(parent) = root.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let sponsor = Keypair::new();
    let poor = Keypair::new();
    if passwords.is_none() {
        save_key(root, "sponsor.keypair.json", &sponsor)?;
    }
    if passwords.is_none() {
        save_key(root, "unfunded.keypair.json", &poor)?;
    }
    let nodes = [
        ValidatorVoteKeypairs::new_rand(),
        ValidatorVoteKeypairs::new_rand(),
    ];
    let network = Keypair::new().pubkey().to_bytes();
    let private = passwords.is_some();
    let treasury = Keypair::new();
    let voters = [Keypair::new(), Keypair::new()];
    let withdrawers = [Keypair::new(), Keypair::new()];
    let stake_controls = [Keypair::new(), Keypair::new()];
    let mint = if private {
        treasury.pubkey()
    } else {
        sponsor.pubkey()
    };
    let rent = Rent::default();
    let floor = rent.minimum_balance(STATE_BYTES);
    let mut pool = AccountSharedData::new(floor, STATE_BYTES, &id());
    pool.set_data_from_slice(&PoolState::new(network, floor)?.encode());
    let mut genesis = create_genesis_config_with_leader_ex_no_features(
        10_000_000_000,
        &mint,
        &nodes[0].node_keypair.pubkey(),
        &nodes[0].vote_keypair.pubkey(),
        &nodes[0].stake_keypair.pubkey(),
        80_000_000_000,
        10_000_000_000,
        FeeRateGovernor::new(5000, 10000),
        rent.clone(),
        ClusterType::Development,
        vec![
            (pool_address(), pool),
            (
                poor.pubkey(),
                AccountSharedData::new(50, 0, &solana_sdk_ids::system_program::id()),
            ),
        ],
    );
    let second = create_genesis_config_with_leader_ex_no_features(
        10_000_000_000,
        &mint,
        &nodes[1].node_keypair.pubkey(),
        &nodes[1].vote_keypair.pubkey(),
        &nodes[1].stake_keypair.pubkey(),
        20_000_000_000,
        10_000_000_000,
        FeeRateGovernor::new(5000, 10000),
        rent,
        ClusterType::Development,
        vec![],
    );
    for address in [
        nodes[1].node_keypair.pubkey(),
        nodes[1].vote_keypair.pubkey(),
        nodes[1].stake_keypair.pubkey(),
    ] {
        genesis
            .accounts
            .insert(address, second.accounts[&address].clone());
    }
    if private {
        genesis.accounts.insert(
            sponsor.pubkey(),
            AccountSharedData::new(1_000_000_000, 0, &solana_sdk_ids::system_program::id()).into(),
        );
        for (index, node) in nodes.iter().enumerate() {
            let stake = if index == 0 {
                80_000_000_000
            } else {
                20_000_000_000
            };
            let vote = solana_vote_program::vote_state::create_account_with_authorized(
                &node.node_keypair.pubkey(),
                &voters[index].pubkey(),
                &withdrawers[index].pubkey(),
                0,
                stake,
            );
            let staked = solana_stake_program::stake_state::create_account(
                &stake_controls[index].pubkey(),
                &node.vote_keypair.pubkey(),
                &vote,
                &genesis.rent,
                stake,
            );
            genesis
                .accounts
                .insert(node.vote_keypair.pubkey(), vote.into());
            genesis
                .accounts
                .insert(node.stake_keypair.pubkey(), staked.into());
            genesis
                .accounts
                .get_mut(&node.node_keypair.pubkey())
                .ok_or("missing identity")?
                .lamports = 100_000_000;
        }
    }
    activate_feature(&mut genesis, ACTIVATION_ID);
    activate_feature(
        &mut genesis,
        native_payment_program::WITHDRAWAL_ACTIVATION_ID,
    );
    activate_feature(
        &mut genesis,
        native_payment_program::SHIELDED_FEE_ACTIVATION_ID,
    );
    genesis.poh_config.hashes_per_tick = None;
    genesis.epoch_schedule = EpochSchedule::custom(128, 128, false);
    let mut identities = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        save_key(
            root,
            &format!("identity-{index}.keypair.json"),
            &node.node_keypair,
        )?;
        if !private {
            save_key(
                root,
                &format!("vote-{index}.keypair.json"),
                &node.vote_keypair,
            )?;
        }
        if !private {
            save_key(
                root,
                &format!("stake-{index}.keypair.json"),
                &node.stake_keypair,
            )?;
        }
        if private {
            save_key(root, &format!("voter-{index}.keypair.json"), &voters[index])?;
        }
        create_new_ledger(
            &root.join(format!("ledger-{index}")),
            &genesis,
            64 * 1024 * 1024,
            LedgerColumnOptions::default(),
        )?;
        identities.push(node.node_keypair.pubkey().to_string());
    }
    let network_config = native_wallet::keys::Network {
        network,
        genesis_hash: genesis.hash().to_string(),
    };
    let roles = if let Some((cold_password, sponsor_password)) = passwords {
        Some(key_setup::save(
            root,
            &network_config,
            &nodes,
            &voters,
            &withdrawers,
            &stake_controls,
            &treasury,
            &sponsor,
            cold_password,
            sponsor_password,
        )?)
    } else {
        None
    };
    native_wallet::keys::write_private_new(
        &root.join("network.json"),
        &serde_json::to_vec_pretty(&json!({
            "network": network, "genesis_hash": genesis.hash().to_string(), "identities": identities,
            "pool": pool_address().to_string(), "program": id().to_string(),
            "pool_format": "NPOOL003",
            "recipient_withdrawals": true,
            "faucet_amount": if private {5_000_000} else {100},
            "fixture_keys_are_public": !private,
            "key_mode": if private {"local-testnet-rehearsal-v1"} else {"disposable-fixture"},
            "roles": roles,
            "vote_accounts": nodes.iter().map(|node|node.vote_keypair.pubkey().to_string()).collect::<Vec<_>>()
        }))?,
    )?;
    fs::File::open(root)?.sync_all()?;
    println!(
        "{}",
        json!({"genesis_hash":genesis.hash().to_string(),"pool":pool_address().to_string()})
    );
    Ok(())
}

fn client(url: &str, config: &Value) -> Result<RpcClient> {
    let parsed = url
        .strip_prefix("http://127.0.0.1:")
        .ok_or("RPC must use loopback HTTP")?;
    parsed.parse::<u16>()?;
    let rpc = RpcClient::new_with_timeout_and_commitment(
        url.to_owned(),
        Duration::from_secs(10),
        CommitmentConfig::confirmed(),
    );
    if rpc.get_genesis_hash()?.to_string()
        != config["genesis_hash"].as_str().ok_or("missing genesis")?
    {
        return Err("RPC genesis does not match this disposable network".into());
    }
    Ok(rpc)
}

fn send(rpc: &RpcClient, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) -> Result<()> {
    let mut signers = vec![payer];
    for key in extra {
        if key.pubkey() != payer.pubkey() {
            signers.push(key);
        }
    }
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        &signers,
        rpc.get_latest_blockhash()?,
    );
    // This fixture has fewer than 128 signatures, so the compact length uses one byte.
    if 1 + tx.signatures.len() * 64 + tx.message_data().len() > 1232 {
        return Err("signed transaction exceeds the network packet limit".into());
    }
    let signature = rpc.send_transaction_with_config(
        &tx,
        RpcSendTransactionConfig {
            skip_preflight: true,
            max_retries: Some(3),
            ..RpcSendTransactionConfig::default()
        },
    )?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(45) {
        if let Some(status) =
            rpc.get_signature_status_with_commitment(&signature, CommitmentConfig::confirmed())?
        {
            return status.map_err(|error| Box::new(error) as Box<dyn Error>);
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err("transaction did not acquire a confirmed execution status".into())
}

fn stage(
    rpc: &RpcClient,
    payer: &Keypair,
    sponsor: &Keypair,
    bytes: &[u8],
    expiry: u64,
) -> Result<Pubkey> {
    let buffer = Keypair::new();
    send(
        rpc,
        payer,
        &[
            system::create_account(
                &payer.pubkey(),
                &buffer.pubkey(),
                rpc.get_minimum_balance_for_rent_exemption(ACCOUNT_BYTES)?,
                ACCOUNT_BYTES as u64,
                &id(),
            ),
            instructions::initialize(
                buffer.pubkey(),
                sponsor.pubkey(),
                bytes.len() as u32,
                payload_digest(bytes),
                expiry,
            ),
        ],
        &[&buffer, sponsor],
    )?;
    for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        send(
            rpc,
            payer,
            &[instructions::write(
                buffer.pubkey(),
                sponsor.pubkey(),
                (index * MAX_CHUNK_BYTES) as u32,
                chunk,
            )],
            &[sponsor],
        )?;
    }
    send(
        rpc,
        payer,
        &[instructions::seal(buffer.pubkey(), sponsor.pubkey())],
        &[sponsor],
    )?;
    Ok(buffer.pubkey())
}

fn finalize(
    rpc: &RpcClient,
    payer: &Keypair,
    sponsor: &Keypair,
    buffer: Pubkey,
    fail_after: bool,
) -> Result<()> {
    let network = pool(rpc)?.1.network;
    let account = rpc.get_account(&buffer)?;
    let staged = native_payment_program::staging::Buffer::decode(&account.data)?;
    let payment = wire::decode(network, staged.payload()?)?;
    let nullifiers = std::array::from_fn(|index| {
        payment
            .bundle
            .actions()
            .get(index)
            .unwrap()
            .nullifier()
            .to_bytes()
    });
    let mut ixs = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        instructions::finalize(buffer, sponsor.pubkey(), nullifiers),
    ];
    if fail_after {
        let mut fail = instructions::seal(buffer, sponsor.pubkey());
        fail.data = vec![255];
        ixs.push(fail);
    }
    send(rpc, payer, &ixs, &[sponsor])
}

fn rejected(result: Result<()>, label: &str, index: u8, expected: InstructionError) -> Result<()> {
    match result {
        Ok(()) => Err(format!("{label} was accepted").into()),
        Err(error)
            if error.downcast_ref::<TransactionError>()
                == Some(&TransactionError::InstructionError(index, expected)) =>
        {
            Ok(())
        }
        Err(error) => {
            Err(format!("{label} did not reach a conclusive instruction failure: {error}").into())
        }
    }
}

fn pool(rpc: &RpcClient) -> Result<(solana_account::Account, PoolState)> {
    let account = rpc.get_account(&pool_address())?;
    if account.owner != id() {
        return Err("pool owner mismatch".into());
    }
    let state = PoolState::decode(&account.data)?;
    if account.lamports != state.rent_floor + state.backing {
        return Err("backing differs from actual native balance".into());
    }
    Ok((account, state))
}

fn equal_pool(rpc: &RpcClient, peer: &RpcClient) -> Result<()> {
    let expected = pool(rpc)?.0;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(45) {
        if pool(peer).is_ok_and(|(actual, _)| actual == expected) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(300));
    }
    Err("peer did not converge to the exact pool account".into())
}

fn marker_keys(network: [u8; 32], bytes: &[u8]) -> Result<Vec<Pubkey>> {
    Ok(wire::decode(network, bytes)?
        .bundle
        .actions()
        .iter()
        .map(|action| nullifiers::address(&action.nullifier().to_bytes()))
        .collect())
}

fn marker_receipt(rpc: &RpcClient, network: [u8; 32], payloads: &[&[u8]]) -> Result<Value> {
    let mut markers = Vec::new();
    for bytes in payloads {
        for action in wire::decode(network, bytes)?.bundle.actions().iter() {
            let nf = action.nullifier().to_bytes();
            let key = nullifiers::address(&nf);
            let account = rpc.get_account(&key)?;
            if account.owner != id()
                || account.data != nullifiers::encode(&nf)
                || account.lamports
                    < rpc
                        .get_minimum_balance_for_rent_exemption(nullifiers::MARKER_BYTES)?
                        .max(1)
            {
                return Err("incorrect permanent nullifier marker".into());
            }
            markers.push(json!({"nullifier":nf,"lamports":account.lamports}));
        }
    }
    Ok(Value::Array(markers))
}

fn check_markers(rpc: &RpcClient, expected: &Value) -> Result<()> {
    let deadline = Instant::now();
    loop {
        let result = (|| -> Result<()> {
            for marker in expected.as_array().ok_or("invalid marker receipt")? {
                let nf: [u8; 32] = serde_json::from_value(marker["nullifier"].clone())?;
                let account = rpc.get_account(&nullifiers::address(&nf))?;
                if account.owner != id()
                    || account.data != nullifiers::encode(&nf)
                    || Some(account.lamports) != marker["lamports"].as_u64()
                {
                    return Err("permanent nullifier account mismatch".into());
                }
            }
            Ok(())
        })();
        if result.is_ok() || deadline.elapsed() > Duration::from_secs(45) {
            return result;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn exercise(root: &Path, rpc: &RpcClient, peer: &RpcClient, config: &Value) -> Result<()> {
    let payer = read_keypair_file(root.join("sponsor.keypair.json"))?;
    let poor = read_keypair_file(root.join("unfunded.keypair.json"))?;
    let network: [u8; 32] = serde_json::from_value::<Vec<u8>>(config["network"].clone())?
        .try_into()
        .map_err(|_| "network length")?;
    if pool(rpc)?.1.note_count() != 0 {
        return Err("exercise requires a fresh disposable pool".into());
    }
    let slot = rpc.get_slot()?;
    let expiry = slot + 1000;
    let unpaid = build_fixture_for_network(poor.pubkey().to_bytes(), network, slot, expiry)?;
    let bytes = wire::encode(network, &unpaid.funding_context, &unpaid.funding)?;
    let buffer = stage(rpc, &payer, &poor, &bytes, expiry)?;
    let before = pool(rpc)?.0;
    rejected(
        finalize(rpc, &payer, &poor, buffer, false),
        "unfunded deposit",
        1,
        InstructionError::Custom(1),
    )?;
    if pool(rpc)?.0 != before {
        return Err("unfunded deposit changed pool".into());
    }
    let slot = rpc.get_slot()?;
    let fixture = build_fixture_for_network(payer.pubkey().to_bytes(), network, slot, slot + 1000)?;
    let expiry = fixture.context.expires_at;
    let funding = wire::encode(network, &fixture.funding_context, &fixture.funding)?;
    let buffer = stage(rpc, &payer, &payer, &funding, expiry)?;
    let funding_markers = marker_keys(network, &funding)?;
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(nullifiers::MARKER_BYTES)?
        .max(1);
    send(
        rpc,
        &payer,
        &[system::transfer(
            &payer.pubkey(),
            &funding_markers[0],
            rent + 7,
        )],
        &[],
    )?;
    let markers_before = rpc.get_multiple_accounts(&funding_markers)?;
    let before_deposit = pool(rpc)?.0;
    let staged_before = rpc.get_account(&buffer)?;
    rejected(
        finalize(rpc, &payer, &payer, buffer, true),
        "rolled-back funded deposit",
        2,
        InstructionError::InvalidInstructionData,
    )?;
    if pool(rpc)?.0 != before_deposit
        || rpc.get_account(&buffer)? != staged_before
        || rpc.get_multiple_accounts(&funding_markers)? != markers_before
    {
        return Err("failed deposit did not roll back backing, staging and markers".into());
    }
    finalize(rpc, &payer, &payer, buffer, false)?;
    if pool(rpc)?.1.backing != 100 {
        return Err("deposit not backed".into());
    }
    if rpc.get_account(&funding_markers[0])?.lamports != rent + 7 {
        return Err("pre-funded marker allocation lost its donation".into());
    }
    let payment = wire::encode(network, &fixture.context, &fixture.bundle)?;
    fs::write(root.join("spent-payment.bin"), &payment)?;
    fs::write(root.join("payment-expiry.json"), expiry.to_string())?;
    let mut corrupt = payment.clone();
    let index = corrupt.len() - 65;
    corrupt[index] ^= 1;
    let bad = stage(rpc, &payer, &payer, &corrupt, expiry)?;
    let before = pool(rpc)?.0;
    rejected(
        finalize(rpc, &payer, &payer, bad, false),
        "invalid proof",
        1,
        InstructionError::InvalidInstructionData,
    )?;
    if pool(rpc)?.0 != before {
        return Err("invalid proof changed pool".into());
    }
    let buffer = stage(rpc, &payer, &payer, &payment, expiry)?;
    let staged_before = rpc.get_account(&buffer)?;
    let private_markers = marker_keys(network, &payment)?;
    let markers_before = rpc.get_multiple_accounts(&private_markers)?;
    rejected(
        finalize(rpc, &payer, &payer, buffer, true),
        "post-finalization failure",
        2,
        InstructionError::InvalidInstructionData,
    )?;
    if pool(rpc)?.0 != before
        || rpc.get_account(&buffer)? != staged_before
        || rpc.get_multiple_accounts(&private_markers)? != markers_before
    {
        return Err("failed transaction did not roll back permanent markers".into());
    }
    finalize(rpc, &payer, &payer, buffer, false)?;
    let (withdrawal, context) = withdrawal_fixture(&fixture)?;
    let bytes = wire::encode(network, &context, &withdrawal)?;
    let buffer = stage(rpc, &payer, &payer, &bytes, expiry)?;
    finalize(rpc, &payer, &payer, buffer, false)?;
    let (account, state) = pool(rpc)?;
    if state.backing != 60 || state.note_count() != 6 {
        return Err("incorrect final payment state".into());
    }
    equal_pool(rpc, peer)?;
    let markers = marker_receipt(rpc, network, &[&funding, &payment, &bytes])?;
    check_markers(peer, &markers)?;
    fs::write(
        root.join("expected-markers.json"),
        serde_json::to_vec_pretty(&markers)?,
    )?;
    fs::write(root.join("expected-pool.bin"), &account.data)?;
    fs::write(
        root.join("payment-result.json"),
        serde_json::to_vec_pretty(&json!({
            "slot":rpc.get_slot()?,"backing":state.backing,"note_count":state.note_count(),
            "actual_pool_lamports":account.lamports,"expiry":expiry,
            "marker_count":markers.as_array().unwrap().len(),"marker_bytes":nullifiers::MARKER_BYTES,"marker_rent":rent,
            "checks":["funded_deposit","private_transfer","withdrawal","unfunded_rejected","invalid_proof_rejected","failed_transaction_atomic","peer_account_equal","prefunded_marker_allocation","permanent_markers_rollback","peer_markers_equal"]
        }))?,
    )?;
    recovery_check(root, rpc, peer)?;
    println!("RPC payment checks passed; backing=60, notes=6");
    Ok(())
}

fn recovery_check(root: &Path, rpc: &RpcClient, peer: &RpcClient) -> Result<()> {
    let expected = fs::read(root.join("expected-pool.bin"))?;
    let readiness = Instant::now();
    while pool(rpc)?.0.data != expected {
        if readiness.elapsed() > Duration::from_secs(45) {
            return Err("recovery did not converge to the persisted pool".into());
        }
        thread::sleep(Duration::from_millis(250));
    }
    while rpc.get_slot()?.saturating_add(12) < peer.get_slot()? {
        if readiness.elapsed() > Duration::from_secs(45) {
            return Err("recovered validator did not catch up to its peer".into());
        }
        thread::sleep(Duration::from_millis(250));
    }
    equal_pool(rpc, peer)?;
    let markers: Value = serde_json::from_slice(&fs::read(root.join("expected-markers.json"))?)?;
    check_markers(rpc, &markers)?;
    check_markers(peer, &markers)?;
    let bytes = fs::read(root.join("spent-payment.bin"))?;
    let expiry: u64 = fs::read_to_string(root.join("payment-expiry.json"))?.parse()?;
    let slot = rpc.get_slot()?;
    if expiry <= slot || expiry - slot > 1024 {
        return Err(
            "spent-proof expiry prevents a meaningful replay check; run a fresh experiment".into(),
        );
    }
    let payer = read_keypair_file(root.join("sponsor.keypair.json"))?;
    let buffer = stage(rpc, &payer, &payer, &bytes, expiry)?;
    let before = pool(rpc)?.0;
    rejected(
        finalize(rpc, &payer, &payer, buffer, false),
        "spent payment after recovery",
        1,
        InstructionError::InvalidInstructionData,
    )?;
    if pool(rpc)?.0 != before {
        return Err("replayed spend changed pool".into());
    }
    println!(
        "Recovery check passed; exact pool, permanent markers and spent-note rejection retained at slot {slot}"
    );
    Ok(())
}

fn replay_check(root: &Path, rpc: &RpcClient, peer: &RpcClient) -> Result<()> {
    let bytes = fs::read(root.join("restart-spent-payment.bin"))?;
    let before = pool(rpc)?.0;
    let payment = wire::decode(pool(rpc)?.1.network, &bytes)?;
    let expiry = payment.context.expires_at;
    let slot = rpc.get_slot()?;
    if expiry <= slot || expiry - slot > 1024 {
        return Err("spent proof is not within its live expiry window".into());
    }
    let payer = read_keypair_file(root.join("sponsor.keypair.json"))?;
    if payer.pubkey().to_bytes() != payment.context.sponsor {
        return Err("spent proof sponsor differs".into());
    }
    let markers = marker_receipt(rpc, pool(rpc)?.1.network, &[&bytes])?;
    let buffer = stage(rpc, &payer, &payer, &bytes, expiry)?;
    rejected(
        finalize(rpc, &payer, &payer, buffer, false),
        "spent proof after coordinated restart",
        1,
        InstructionError::InvalidInstructionData,
    )?;
    if pool(rpc)?.0 != before {
        return Err("replayed payment changed pool".into());
    }
    check_markers(rpc, &markers)?;
    check_markers(peer, &markers)?;
    send(
        rpc,
        &payer,
        &[instructions::close(buffer, payer.pubkey())],
        &[],
    )?;
    equal_pool(rpc, peer)?;
    println!(
        "Live spent proof rejected after coordinated restart; exact pool and markers retained"
    );
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or("expected init, exercise or recovery-check")?;
    let root = PathBuf::from(args.next().ok_or("expected disposable network directory")?);
    if matches!(
        command.as_str(),
        "pilot-treasury-sign" | "pilot-treasury-check"
    ) {
        return pilot_treasury::run(&command, &root, &args.collect::<Vec<_>>());
    }
    if command == "replay-user-send-check" {
        return user_send_lab::replay(&root, &args.collect::<Vec<_>>());
    }
    if matches!(
        command.as_str(),
        "fund-user-fee-check" | "fund-faucet-check"
    ) {
        let grant = if command == "fund-faucet-check" {
            1_000_000_000
        } else {
            300_000_000
        };
        let wallet_path = PathBuf::from(args.next().ok_or("expected encrypted wallet")?);
        let password_path = PathBuf::from(args.next().ok_or("expected user password file")?);
        let cold_path = PathBuf::from(args.next().ok_or("expected cold rehearsal password file")?);
        let url = args.next().ok_or("expected local RPC")?;
        if args.next().is_some() {
            return Err("unexpected funding option".into());
        }
        let network = native_wallet::keys::Network::load(&root.join("network.json"))?;
        let config: Value = serde_json::from_slice(&fs::read(root.join("network.json"))?)?;
        if config["key_mode"] != "local-testnet-rehearsal-v1" {
            return Err("funding acceptance requires a private local rehearsal".into());
        }
        let rpc = if config["raw_rpc_isolation"] == true {
            native_wallet::rpc::Chain::operator_client(
                &url,
                network.clone(),
                &root.join("rpc-access.key"),
            )?
        } else {
            client(&url, &config)?
        };
        let user_password = native_wallet::keys::read_password(&password_path)?;
        let wallet = native_wallet::keys::WalletKey::open(&wallet_path, &user_password, &network)?;
        let recipient = wallet.fee_keypair().pubkey();
        if rpc.get_balance(&recipient)? != 0 {
            return Err("fee acceptance account is already funded; never repeat funding".into());
        }
        let cold_password = native_wallet::keys::read_password(&cold_path)?;
        let mut roles = native_wallet::operator::open(
            &root.join("operator-recovery.enc.json"),
            &network,
            &cold_password,
        )?;
        let treasury = roles.remove("treasury").ok_or("missing treasury")?;
        let tx = Transaction::new_signed_with_payer(
            &[system::transfer(&treasury.pubkey(), &recipient, grant)],
            Some(&treasury.pubkey()),
            &[&treasury],
            rpc.get_latest_blockhash()?,
        );
        let signature = rpc.send_transaction_with_config(
            &tx,
            RpcSendTransactionConfig {
                max_retries: Some(0),
                preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                ..Default::default()
            },
        )?;
        println!(
            "{}",
            json!({"signature":signature.to_string(),"fee_address":recipient.to_string(),"amount":grant,"local_test_funding_only":true})
        );
        return Ok(());
    }
    if command == "owner-transfer-check" {
        // Acceptance utility only: one bounded public transfer signed directly
        // by a restored user's seed. No operator keys or retryable wallet flow.
        let wallet_path = PathBuf::from(args.next().ok_or("expected encrypted user wallet")?);
        let password_path = PathBuf::from(args.next().ok_or("expected private password file")?);
        let recipient: Pubkey = args.next().ok_or("expected funded recipient")?.parse()?;
        let amount: u64 = args.next().ok_or("expected amount")?.parse()?;
        let url = args.next().ok_or("expected local RPC")?;
        if args.next().is_some() || amount != 10_000 {
            return Err("owner-control acceptance transfers exactly 10000 test units once".into());
        }
        let network = native_wallet::keys::Network::load(&root.join("network.json"))?;
        let config: Value = serde_json::from_slice(&fs::read(root.join("network.json"))?)?;
        if config["key_mode"] != "local-testnet-rehearsal-v1" {
            return Err("owner-control check requires local rehearsal keys".into());
        }
        let rpc = client(&url, &config)?;
        let password = native_wallet::keys::read_password(&password_path)?;
        let wallet = native_wallet::keys::WalletKey::open(&wallet_path, &password, &network)?;
        let owner = wallet.public_keypair();
        if !recipient.is_on_curve() || rpc.get_balance(&recipient)? == 0 {
            return Err("acceptance recipient must already be a funded user account".into());
        }
        let tx = Transaction::new_signed_with_payer(
            &[system::transfer(&owner.pubkey(), &recipient, amount)],
            Some(&owner.pubkey()),
            &[&owner],
            rpc.get_latest_blockhash()?,
        );
        let signature = rpc.send_transaction_with_config(
            &tx,
            RpcSendTransactionConfig {
                max_retries: Some(0),
                preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                ..Default::default()
            },
        )?;
        println!(
            "{}",
            json!({"signature":signature.to_string(),"owner":owner.pubkey().to_string(),"recipient":recipient.to_string(),"amount":amount,"operator_signed":false})
        );
        return Ok(());
    }
    if command == "load" {
        return load_lab::run(&root, &args.collect::<Vec<_>>());
    }
    if command.starts_with("fault-") {
        return fault_lab::run(&command, &root, &args.collect::<Vec<_>>());
    }
    if command == "init" {
        return initialize(&root, None);
    }
    if command == "init-private" {
        return key_setup::initialize_private(&root, &args.collect::<Vec<_>>());
    }
    if command == "restore-hot" {
        return key_setup::restore_hot(&root, &args.collect::<Vec<_>>());
    }
    if command == "restore-sponsor" {
        return key_setup::restore_sponsor(&root, &args.collect::<Vec<_>>());
    }
    if command == "bootstrap-check" {
        let name = args.next().ok_or("expected ledger name")?;
        if !name.starts_with("ledger-")
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("invalid bootstrap ledger name".into());
        }
        if Blockstore::open(&root.join(name))?
            .highest_slot()?
            .is_some_and(|slot| slot > 0)
        {
            return Err("existing ledger history requires a saved tower".into());
        }
        return Ok(());
    }
    if command == "restart-state" {
        let index = args.next().ok_or("expected validator index")?.parse()?;
        return restart_state(
            &root,
            index,
            &args.next().ok_or("expected ledger name")?,
            false,
        );
    }
    if command == "replay-plan" {
        let index = args.next().ok_or("expected validator index")?.parse()?;
        return restart_state(
            &root,
            index,
            &args.next().ok_or("expected ledger name")?,
            true,
        );
    }
    if command == "diagnose-restart" {
        let index = args.next().ok_or("expected validator index")?.parse()?;
        let name = args.next().ok_or("expected ledger name")?;
        if args.next().is_some() {
            return Err("unexpected diagnostic argument".into());
        }
        return tail_diagnostic::inspect(&root, index, &name);
    }
    if command == "prepare-recovery" {
        let name = args.next().unwrap_or_else(|| "ledger-recovered".to_owned());
        if !name.starts_with("ledger-recovered")
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("invalid recovery ledger name".into());
        }
        let destination = root.join(name);
        if destination.exists() {
            return Err("recovery ledger already exists".into());
        }
        let genesis = solana_genesis_config::GenesisConfig::load(&root.join("ledger-0"))?;
        create_new_ledger(
            &destination,
            &genesis,
            64 * 1024 * 1024,
            LedgerColumnOptions::default(),
        )?;
        return Ok(());
    }
    let config: Value = serde_json::from_slice(&fs::read(root.join("network.json"))?)?;
    let rpc = client(&args.next().ok_or("expected loopback RPC URL")?, &config)?;
    let peer = client(
        &args.next().ok_or("expected peer loopback RPC URL")?,
        &config,
    )?;
    match command.as_str() {
        "exercise" => exercise(&root, &rpc, &peer, &config),
        "recovery-check" => recovery_check(&root, &rpc, &peer),
        "replay-check" => replay_check(&root, &rpc, &peer),
        _ => Err("unknown localnet command".into()),
    }
}
