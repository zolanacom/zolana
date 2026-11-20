//! Build a payment, read its wire format field by field, and decode it.
//!
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example wire_message
//!
//! Offline. Builds one real proof. All integers are little-endian.
use native_payments::{envelope, verification::ACTION_COUNT, wire};
use native_wallet_core::{
    history::WalletState,
    payments::{Payment, PaymentProver},
};
use zolana_sdk_examples::{hex, DemoWallet, GENESIS, NETWORK};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = DemoWallet::new(NETWORK, GENESIS, [7; 32]);
    // The prover holds the circuit's proving key. Build it once per process.
    let prover = PaymentProver::new();
    // An empty wallet view of an empty pool (rent floor 1).
    let state = WalletState::with_key(&alice, 1, prover.verifying_key())?;

    // A deposit moves public coins into the pool as a note for `recipient`.
    // The sponsor is the public account that is debited and pays the fees.
    let sponsor = [0x53; 32];
    let payment = Payment::Deposit {
        amount: 25,
        recipient: &alice.address()?,
    };
    let bytes = prover.build(&alice, &state, sponsor, 100, payment)?;
    println!("{} bytes", bytes.len());

    // The fixed 122-byte header (wire::HEADER_BYTES) of a deposit, send or
    // sponsor withdrawal. Its tag is wire::MAGIC.
    assert_eq!(&bytes[..8], wire::MAGIC);
    println!("tag           {}", std::str::from_utf8(&bytes[..8])?);
    println!("network       {}", hex(&bytes[8..40]));
    let expiry = u64::from_le_bytes(bytes[40..48].try_into()?);
    println!("expiry slot   {expiry}");
    // Negative: value enters the pool. Zero: private send. Positive: it leaves.
    let balance = i64::from_le_bytes(bytes[48..56].try_into()?);
    println!("value balance {balance}");
    println!("sponsor       {}", hex(&bytes[56..88]));
    println!("anchor        {}", hex(&bytes[88..120]));
    println!("flags {}, actions {}", bytes[120], bytes[121]);
    // Then: two 884-byte actions, a u32 proof length, the proof, a 64-byte signature.
    let actions_end = wire::HEADER_BYTES + ACTION_COUNT * wire::ACTION_BYTES;
    let proof_bytes = u32::from_le_bytes(bytes[actions_end..][..4].try_into()?);
    println!("proof         {proof_bytes} bytes");
    assert_eq!(bytes.len(), actions_end + 4 + proof_bytes as usize + 64);

    // The decoder checks all of that and returns a typed Orchard bundle.
    // Decoding is not verification: see the verify_proof example.
    let decoded = wire::decode(NETWORK, &bytes)?;
    assert_eq!(decoded.context.expires_at, expiry);
    assert_eq!(decoded.context.public_value_balance, -25);
    assert_eq!(decoded.context.sponsor, sponsor);
    assert_eq!(decoded.bundle.actions().len(), ACTION_COUNT);
    // The encoding is canonical: encoding the decoded payment gives the same bytes.
    assert_eq!(
        wire::encode(NETWORK, &decoded.context, &decoded.bundle)?,
        bytes
    );
    println!("decoded and re-encoded to identical bytes");

    let truncated = wire::decode(NETWORK, &bytes[..bytes.len() - 1]).unwrap_err();
    println!("one byte short: {truncated:?}");
    let unknown_tag = [b"NPAY9999".as_slice(), &bytes[8..]].concat();
    let refused = wire::decode(NETWORK, &unknown_tag).unwrap_err();
    println!("unknown tag: {refused:?}");
    // The single-transaction envelope carries shielded-fee payments only.
    let framed = envelope::encode(NETWORK, &bytes).err();
    println!(
        "deposit in an inline envelope: {:?}",
        framed.ok_or("accepted")?
    );
    Ok(())
}
