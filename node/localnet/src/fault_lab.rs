//! Private-key local fixtures for crash and competing-fork acceptance.
use super::*;
use native_wallet::{
    keys::{read_password, Network, WalletKey},
    payments::{self, Payment},
    rpc::Chain,
};
use std::net::UdpSocket;

pub(super) fn run(command: &str, root: &Path, args: &[String]) -> Result<()> {
    let config: Value = serde_json::from_slice(&fs::read(root.join("network.json"))?)?;
    if config["fixture_keys_are_public"] != true || config["pool_format"] != "NPOOL002" {
        return Err("fault lab requires a disposable native fixture".into());
    }
    let label = args.first().ok_or("expected candidate label")?;
    if !["majority", "minority", "crash"].contains(&label.as_str()) {
        return Err("invalid candidate label".into());
    }
    let payload = root.join(format!("{label}-payment.bin"));
    let staging = root.join(format!("{label}-staging.json"));
    let network: [u8; 32] = serde_json::from_value(config["network"].clone())?;
    let sponsor = read_keypair_file(root.join("sponsor.keypair.json"))?;
    if command == "fault-prepare" {
        let amount = args.get(1).ok_or("expected transfer amount")?.parse()?;
        let net = Network::load(&root.join("network.json"))?;
        let password = read_password(&root.join("wallets/unlock.password"))?;
        let alice = WalletKey::open(&root.join("wallets/alice.wallet.json"), &password, &net)?;
        let bob = WalletKey::open(&root.join("wallets/bob.wallet.json"), &password, &net)?;
        let chain = Chain::connect("http://127.0.0.1:18899", net)?;
        let synced = chain.sync(&alice)?;
        let bytes = payments::build(
            &alice,
            &synced.state,
            sponsor.pubkey().to_bytes(),
            chain.expiry()?,
            Payment::Send {
                amount,
                recipient: &bob.address_text(),
            },
        )?;
        fs::write(&payload, bytes)?;
    }
    let bytes = fs::read(payload)?;
    let payment = wire::decode(network, &bytes)?;
    let expiry = payment.context.expires_at;
    let markers = marker_keys(network, &bytes)?;
    let describe = json!({"expiry":expiry,"markers":markers.iter().map(ToString::to_string).collect::<Vec<_>>(),"public_balance":payment.context.public_value_balance});
    if command == "fault-prepare" || command == "fault-describe" {
        println!("{describe}");
        return Ok(());
    }
    let index: usize = args.get(1).ok_or("expected validator index")?.parse()?;
    if index > 1 {
        return Err("invalid validator index".into());
    }
    let rpc = client(
        &format!("http://127.0.0.1:{}", 18899 + index * 1000),
        &config,
    )?;
    if command == "fault-stage" {
        let buffer = stage(&rpc, &sponsor, &sponsor, &bytes, expiry)?;
        let receipt = json!({"staging_account":buffer.to_string(),"expiry":expiry,"markers":describe["markers"]});
        fs::write(staging, serde_json::to_vec(&receipt)?)?;
        println!("{receipt}");
        return Ok(());
    }
    let saved: Value = serde_json::from_slice(&fs::read(staging)?)?;
    let buffer: Pubkey = saved["staging_account"]
        .as_str()
        .ok_or("missing staging key")?
        .parse()?;
    match command {
        "fault-finalize" => finalize(&rpc, &sponsor, &sponsor, buffer, false)?,
        "fault-reject" => {
            let before = pool(&rpc)?.0;
            rejected(
                finalize(&rpc, &sponsor, &sponsor, buffer, false),
                "conflicting/orphaned candidate",
                1,
                InstructionError::InvalidInstructionData,
            )?;
            if pool(&rpc)?.0 != before {
                return Err("rejected candidate changed pool".into());
            }
        }
        "fault-close" => send(
            &rpc,
            &sponsor,
            &[instructions::close(buffer, sponsor.pubkey())],
            &[],
        )?,
        "fault-direct" => {
            let id: Pubkey = config["identities"][index]
                .as_str()
                .ok_or("missing identity")?
                .parse()?;
            let target = rpc
                .get_cluster_nodes()?
                .into_iter()
                .find(|node| node.pubkey == id.to_string())
                .and_then(|node| node.tpu)
                .ok_or("missing local UDP TPU")?;
            if !target.ip().is_loopback() {
                return Err("direct test TPU must be loopback".into());
            }
            let nfs = std::array::from_fn(|i| {
                payment
                    .bundle
                    .actions()
                    .get(i)
                    .unwrap()
                    .nullifier()
                    .to_bytes()
            });
            let tx = Transaction::new_signed_with_payer(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                    instructions::finalize(buffer, sponsor.pubkey(), nfs),
                ],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                rpc.get_latest_blockhash()?,
            );
            let packet = bincode::serialize(&tx)?;
            if packet.len() > 1232 {
                return Err("oversize direct transaction".into());
            }
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            let until = Instant::now() + Duration::from_secs(25);
            while Instant::now() < until {
                // Direct delivery only: successful packets execute on this
                // validator's active leader bank. The canonical conflicting
                // spend is accepted first, so forwarding cannot win that fork.
                socket.send_to(&packet, target)?;
                if let Some(status) = rpc
                    .get_signature_statuses(&[tx.signatures[0]])?
                    .value
                    .into_iter()
                    .next()
                    .flatten()
                {
                    status
                        .err
                        .map_or(Ok(()), |error| Err(Box::new(error) as Box<dyn Error>))?;
                    println!(
                        "{}",
                        json!({"signature":tx.signatures[0].to_string(),"slot":status.slot,"staging_account":buffer.to_string(),"processed":true})
                    );
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(50));
            }
            return Err(format!("candidate did not execute on isolated local leader; processed_slot={}, identity={id}, UDP_TPU={target}", rpc.get_slot_with_commitment(CommitmentConfig::processed())?).into());
        }
        _ => return Err("unknown fault-lab command".into()),
    }
    println!(
        "{}",
        json!({"ok":true,"staging_account":buffer.to_string()})
    );
    Ok(())
}
