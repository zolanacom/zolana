//! Synchronized RPC bursts with distinct shielded keys, notes and public sponsors.
use super::*;
use native_wallet::{
    history::WalletState,
    keys::{write_private_new, Network, WalletKey},
    operation::WalletOperation,
    payments::{Payment, PaymentProver},
    rpc::Chain,
};
use std::sync::Barrier;

pub(super) fn run(root: &Path, args: &[String]) -> Result<()> {
    let count: usize = args.first().ok_or("expected burst size")?.parse()?;
    let kind = args.get(1).ok_or("expected deposit or send")?;
    if !(2..=64).contains(&count) || !["deposit", "send", "audit"].contains(&kind.as_str()) {
        return Err("bounded load requires 2..64 clients and deposit or send".into());
    }
    let config: Value = serde_json::from_slice(&fs::read(root.join("network.json"))?)?;
    if config["fixture_keys_are_public"] != true {
        return Err("load requires a disposable local fixture".into());
    }
    let network = Network::load(&root.join("network.json"))?;
    let rpc = client("http://127.0.0.1:18899", &config)?;
    let payer = read_keypair_file(root.join("sponsor.keypair.json"))?;
    let directory = root.join("load-wallets");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let password = b"disposable-load-fixture-only-keep-local";
    if kind == "audit" {
        let started = Instant::now();
        let wallets = (0..count)
            .map(|index| {
                WalletKey::open(
                    &directory.join(format!("wallet-{index}.json")),
                    password,
                    &network,
                )
            })
            .collect::<native_wallet::Result<Vec<_>>>()?;
        let keys: Vec<_> = wallets.iter().collect();
        let mut balances = Vec::new();
        for url in ["http://127.0.0.1:18899", "http://127.0.0.1:19899"] {
            let actual = Chain::connect(url, network.clone())?
                .sync_many(&keys)?
                .into_iter()
                .map(|synced| synced.state.balance())
                .collect::<native_wallet::Result<Vec<_>>>()?;
            let expected: Vec<_> = (0..count)
                .map(|index| 100 - (index as u64 + 1) + ((index + count - 1) % count + 1) as u64)
                .collect();
            if actual != expected {
                return Err("multi-wallet audit balances differ".into());
            }
            balances.push(actual);
        }
        let state = pool(&rpc)?.1;
        if state.backing != count as u64 * 100 || state.note_count() != count as u64 * 4 {
            return Err("audit pool effects differ".into());
        }
        let result = json!({"wallets":count,"validators":2,"elapsed_ms":started.elapsed().as_millis(),"balances":balances,"backing":state.backing,"commitments":state.note_count()});
        fs::write(
            root.join("load-audit.json"),
            serde_json::to_vec_pretty(&result)?,
        )?;
        println!("{result}");
        return Ok(());
    }
    let before = pool(&rpc)?.1;
    let prover_started = Instant::now();
    let prover = PaymentProver::new();
    let key_ms = prover_started.elapsed().as_millis();
    let mut prepared = Vec::new();
    let preparation = Instant::now();
    let existing = if kind == "send" {
        (0..count)
            .map(|index| {
                WalletKey::open(
                    &directory.join(format!("wallet-{index}.json")),
                    password,
                    &network,
                )
            })
            .collect::<native_wallet::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let mut synced = if kind == "send" {
        Chain::connect("http://127.0.0.1:18899", network.clone())?
            .sync_many(&existing.iter().collect::<Vec<_>>())?
            .into_iter()
    } else {
        Vec::new().into_iter()
    };
    for index in 0..count {
        let path = directory.join(format!("wallet-{index}.json"));
        let sponsor_path = directory.join(format!("sponsor-{index}.json"));
        let wallet = if kind == "deposit" {
            let key = WalletKey::generate(network.clone())?;
            key.save(&path, password)?;
            let sponsor = Keypair::new();
            write_keypair_file(&sponsor, &sponsor_path)?;
            fs::set_permissions(&sponsor_path, fs::Permissions::from_mode(0o600))?;
            send(
                &rpc,
                &payer,
                &[system::transfer(
                    &payer.pubkey(),
                    &sponsor.pubkey(),
                    140_000_000,
                )],
                &[],
            )?;
            key
        } else {
            WalletKey::open(&path, password, &network)?
        };
        let sponsor = read_keypair_file(sponsor_path)?;
        let chain = Chain::connect("http://127.0.0.1:18899", network.clone())?;
        let state = if kind == "deposit" {
            let mut state = WalletState::new(&wallet, before.rent_floor)?;
            state.pool = before.clone(); // Deposits need no spend witnesses.
            state
        } else {
            synced.next().ok_or("missing prepared wallet state")?.state
        };
        let recipient = if kind == "deposit" {
            wallet.address_text()
        } else {
            WalletKey::open(
                &directory.join(format!("wallet-{}.json", (index + 1) % count)),
                password,
                &network,
            )?
            .address_text()
        };
        let payment = if kind == "deposit" {
            Payment::Deposit {
                amount: 100,
                recipient: &recipient,
            }
        } else {
            Payment::Send {
                amount: index as u64 + 1,
                recipient: &recipient,
            }
        };
        let proof_started = Instant::now();
        let bytes = prover.build(
            &wallet,
            &state,
            sponsor.pubkey().to_bytes(),
            chain.expiry()?.checked_add(512).ok_or("expiry overflow")?,
            payment,
        )?;
        let proof_ms = proof_started.elapsed().as_millis();
        write_private_new(&directory.join(format!("{kind}-{index}.bin")), &bytes)?;
        prepared.push((index, path, sponsor, bytes, proof_ms));
    }
    let prepare_ms = preparation.elapsed().as_millis();
    eprintln!("prepared {count} {kind} proofs in {prepare_ms}ms");
    let barrier = Barrier::new(count);
    let burst = Instant::now();
    let outcomes = thread::scope(|scope| {
        let handles: Vec<_> = prepared.iter().map(|(index, path, sponsor, bytes, proof_ms)| {
            let barrier = &barrier;
            let network = network.clone();
            scope.spawn(move || {
                let chain = Chain::connect(&format!("http://127.0.0.1:{}", 18899 + (index % 2) * 1000), network);
                barrier.wait();
                let started = Instant::now();
                let result = (|| -> native_wallet::Result<_> {
                    let operation = WalletOperation::acquire(path)?;
                    chain?.submit(sponsor, bytes, &operation)
                })();
                match result {
                    Ok(receipt) => json!({"index":index,"proof_ms":proof_ms,"elapsed_ms":started.elapsed().as_millis(),"receipt":receipt}),
                    Err(error) => json!({"index":index,"proof_ms":proof_ms,"elapsed_ms":started.elapsed().as_millis(),"error":error.to_string()}),
                }
            })
        }).collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("load worker panicked"))
            .collect::<Vec<_>>()
    });
    let burst_ms = burst.elapsed().as_millis();
    let accepted = outcomes
        .iter()
        .filter(|outcome| outcome.get("receipt").is_some())
        .count();
    let after = pool(&rpc)?.1;
    if after.note_count() - before.note_count() != accepted as u64 * 2
        || after.backing - before.backing
            != if kind == "deposit" {
                accepted as u64 * 100
            } else {
                0
            }
    {
        return Err("accepted receipts disagree with native effects".into());
    }
    let result = json!({"kind":kind,"clients":count,"accepted":accepted,"rejected":count-accepted,
        "key_ms":key_ms,"prepare_ms":prepare_ms,"burst_ms":burst_ms,
        "finalized_payments_per_second":accepted as f64 / (burst_ms as f64 / 1000.0),
        "backing":after.backing,"commitments":after.note_count(),"outcomes":outcomes});
    fs::write(
        root.join(format!("load-{kind}.json")),
        serde_json::to_vec_pretty(&result)?,
    )?;
    println!("{result}");
    if accepted == count {
        let payloads: Vec<_> = prepared.iter().map(|entry| entry.3.as_slice()).collect();
        let markers = marker_receipt(&rpc, network.network, &payloads)?;
        let peer = client("http://127.0.0.1:19899", &config)?;
        equal_pool(&rpc, &peer)?;
        check_markers(&peer, &markers)?;
        let (_, _, sponsor, bytes, _) = &prepared[0];
        let decoded = wire::decode(network.network, bytes)?;
        let buffer = stage(&rpc, sponsor, sponsor, bytes, decoded.context.expires_at)?;
        rejected(
            finalize(&rpc, sponsor, sponsor, buffer, false),
            "live duplicate payment",
            1,
            InstructionError::InvalidInstructionData,
        )?;
        send(
            &rpc,
            sponsor,
            &[instructions::close(buffer, sponsor.pubkey())],
            &[],
        )?;
        if pool(&rpc)?.1.encode() != after.encode() {
            return Err("duplicate changed pool".into());
        }
        let wallets = prepared
            .iter()
            .map(|entry| WalletKey::open(&entry.1, password, &network))
            .collect::<native_wallet::Result<Vec<_>>>()?;
        let keys: Vec<_> = wallets.iter().collect();
        for url in ["http://127.0.0.1:18899", "http://127.0.0.1:19899"] {
            for (index, synced) in Chain::connect(url, network.clone())?
                .sync_many(&keys)?
                .into_iter()
                .enumerate()
            {
                let expected = if kind == "deposit" {
                    100
                } else {
                    100 - (index as u64 + 1) + ((index + count - 1) % count + 1) as u64
                };
                if synced.state.balance()? != expected {
                    return Err(format!("wallet {index} balance differs after {kind} burst").into());
                }
            }
        }
        eprintln!(
            "verified balances, backing, both validators' nullifiers and live duplicate rejection"
        );
    }
    Ok(())
}
