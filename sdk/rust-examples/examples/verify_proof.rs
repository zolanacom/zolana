//! Verify a real shielded payment the way a validator does, then try to cheat.
//!
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example verify_proof
//!
//! Offline. Reuses the public `payment-lab` fixture: Alice deposits 100, then
//! pays Bob 40 and keeps 60 as change. Both transactions carry real proofs.
use native_payments::{
    staging::{payload_digest, StagedPayload, MAX_CHUNK_BYTES},
    wire,
};
use payment_lab::proof_smoke::build_fixture;
use std::collections::BTreeSet;
use zolana_sdk_examples::hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture()?;

    // 1. The payment as bytes: a fixed layout with a tag, the network, the
    //    public fields, two actions, the proof and the binding signature.
    let bytes = wire::encode(fixture.network, &fixture.context, &fixture.bundle)?;
    let tag = std::str::from_utf8(&bytes[..8])?;
    println!("payment: {} bytes, tag {tag}", bytes.len());

    // 2. On the staged path a payment reaches the chain in chunks of at most
    //    768 bytes and is sealed against a digest announced up front.
    let mut staged = StagedPayload::new(bytes.len(), payload_digest(&bytes))?;
    for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        staged.append(index * MAX_CHUNK_BYTES, chunk)?;
    }
    staged.seal()?;
    let payload = staged.into_payload()?;
    let chunks = bytes.len().div_ceil(MAX_CHUNK_BYTES);
    println!(
        "staged in {chunks} chunks, digest {}",
        hex(&payload_digest(&payload))
    );

    // 3. Decode, then verify against a view of chain state: the current slot,
    //    the accepted anchors and the nullifiers already spent. In a validator
    //    that view comes from authenticated state, never from the sender.
    let decoded = wire::decode(fixture.network, &payload)?;
    let (bundle, context) = (&decoded.bundle, &decoded.context);
    let mut spent = BTreeSet::new();
    let verified = fixture
        .verifier
        .verify(bundle, context, &fixture.view(&spent))?;
    println!("verified: signatures, binding signature and proof");
    for index in 0..verified.nullifiers.len() {
        println!("  nullifier  {}", hex(&verified.nullifiers[index]));
        println!("  commitment {}", hex(&verified.commitments[index]));
    }

    // 4. The chain records both nullifiers. The same payment is then refused.
    spent.extend(verified.nullifiers);
    let replayed = fixture
        .verifier
        .verify(bundle, context, &fixture.view(&spent));
    println!("sent a second time: {:?}", replayed.unwrap_err());

    // 5. One flipped bit inside the proof.
    let mut tampered = payload.clone();
    let inside_proof = tampered.len() - 64 - 100;
    tampered[inside_proof] ^= 1;
    let decoded = wire::decode(fixture.network, &tampered)?;
    let fresh = BTreeSet::new();
    let result = fixture
        .verifier
        .verify(&decoded.bundle, &decoded.context, &fixture.view(&fresh));
    println!("one flipped proof bit: {:?}", result.unwrap_err());

    // 6. The bytes name their network. Another network cannot decode them.
    let wrong = wire::decode([9; 32], &payload).err();
    println!(
        "decoded for another network: {:?}",
        wrong.ok_or("accepted")?
    );
    Ok(())
}
