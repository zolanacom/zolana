//! Browser-local native payment cryptography and opaque wallet state.
//!
//! Vault APIs keep seeds, note decryption and proof construction inside Rust.
//! Session APIs authenticate signed history and reconcile finalized RPC state;
//! RPC consensus remains trusted. JavaScript owns durable encrypted storage and
//! bounded transport. Separate synthetic fixture APIs perform no live payment.
mod access;
mod error;
mod session;
pub mod vault;
pub use error::{BrowserError, Result as BrowserResult};
use incrementalmerkletree::{Hashable, Level};
use native_payments::{
    envelope,
    state::PoolState,
    verification::{
        authorization_digest, bundle_version, AuthorizationContext, PaymentVerifier, ValidationView,
    },
    wire, Error,
};
use orchard::{
    builder::{Builder, BundleType},
    bundle::Authorized,
    circuit::ProvingKey,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Bundle,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::BTreeSet, sync::Arc};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

// The single-thread artifact does not expose or depend on a thread pool.
// JavaScript must await this export before key preparation or proof creation.
#[cfg(all(target_arch = "wasm32", feature = "browser-multicore"))]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(all(
    target_arch = "wasm32",
    feature = "native-multicore",
    not(feature = "browser-multicore")
))]
compile_error!("use browser-multicore for threaded Wasm, including its initialized worker pool");

pub const FORMAT: &str = "zolana-browser-synthetic-fixture-v1";
pub const MAX_FIXTURE_BYTES: usize = 128 * 1024;
const NETWORK: [u8; 32] = [0xb3; 32];
const SPONSOR: [u8; 32] = [0x53; 32];
const EXPIRY: u64 = 100;

type Result<T> = std::result::Result<T, String>;

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn performance_now() -> f64;
}

struct Timer {
    #[cfg(target_arch = "wasm32")]
    start: f64,
    #[cfg(not(target_arch = "wasm32"))]
    start: std::time::Instant,
}
impl Timer {
    fn start() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            start: performance_now(),
            #[cfg(not(target_arch = "wasm32"))]
            start: std::time::Instant::now(),
        }
    }
    fn ms(&self) -> u64 {
        #[cfg(target_arch = "wasm32")]
        {
            (performance_now() - self.start).max(0.0).round() as u64
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.start.elapsed().as_millis().min(u64::MAX as u128) as u64
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timings {
    funding_proof: u64,
    payment_proof: u64,
    local_verify: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicFixture {
    format: String,
    fixture_only: bool,
    network_hex: String,
    funding_payload_hex: String,
    payment_payload_hex: String,
    envelope_hex: String,
    timings_ms: Timings,
}

#[derive(Serialize)]
pub struct VerificationReport {
    pub ok: bool,
    pub format: &'static str,
    pub fixture_only: bool,
    pub checks: Vec<&'static str>,
    pub payload_bytes: usize,
    pub envelope_bytes: usize,
    pub backing_after: u64,
    pub commitments: u64,
}

struct PrivateFixture {
    bob: FullViewingKey,
    alice: FullViewingKey,
    funding: Bundle<Authorized, i64>,
    payment: Bundle<Authorized, i64>,
    final_root: [u8; 32],
}

struct Engine {
    key: ProvingKey,
    last: Option<PrivateFixture>,
}
thread_local! { static ENGINE: RefCell<Option<Engine>> = const { RefCell::new(None) }; }

fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(raw.len() * 2);
    for byte in raw {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}
fn unhex(raw: &str, maximum: usize) -> Result<Vec<u8>> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) || raw.len() > maximum * 2 {
        return Err("bounded lowercase hex required".into());
    }
    let digit = |v: u8| match v {
        b'0'..=b'9' => Ok(v - b'0'),
        b'a'..=b'f' => Ok(v - b'a' + 10),
        _ => Err("lowercase hex required".to_string()),
    };
    raw.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}
fn fresh_key() -> SpendingKey {
    loop {
        if let Some(key) = Option::from(SpendingKey::from_bytes(rand::random())) {
            return key;
        }
    }
}
fn funding_path(index: usize, bundle: &Bundle<Authorized, i64>) -> MerklePath {
    MerklePath::from_parts(
        index as u32,
        std::array::from_fn(|level| {
            if level == 0 {
                MerkleHashOrchard::from_cmx(
                    bundle.actions().get(1 - index).expect("two actions").cmx(),
                )
            } else {
                MerkleHashOrchard::empty_root(Level::from(level as u8))
            }
        }),
    )
}
fn received_path(
    index: usize,
    funding: &Bundle<Authorized, i64>,
    payment: &Bundle<Authorized, i64>,
) -> MerklePath {
    let funding_root = MerkleHashOrchard::combine(
        Level::from(0),
        &MerkleHashOrchard::from_cmx(funding.actions().get(0).expect("two actions").cmx()),
        &MerkleHashOrchard::from_cmx(funding.actions().get(1).expect("two actions").cmx()),
    );
    MerklePath::from_parts(
        (2 + index) as u32,
        std::array::from_fn(|level| match level {
            0 => MerkleHashOrchard::from_cmx(
                payment.actions().get(1 - index).expect("two actions").cmx(),
            ),
            1 => funding_root,
            _ => MerkleHashOrchard::empty_root(Level::from(level as u8)),
        }),
    )
}
fn context(value: i64, fee: Option<u64>) -> AuthorizationContext {
    AuthorizationContext {
        expires_at: EXPIRY,
        public_value_balance: value,
        sponsor: SPONSOR,
        withdrawal_recipient: None,
        shielded_fee: fee,
    }
}

pub fn version_json() -> String {
    serde_json::json!({"format":"zolana-browser-core-version-v1","orchard":"0.16.0","circuit":"orchard_v2","multicore":cfg!(any(feature="native-multicore",feature="browser-multicore")),"fixture_only":true}).to_string()
}

pub fn prepare_json() -> Result<String> {
    ENGINE.with(|slot| {
        let mut slot=slot.borrow_mut(); let cached=slot.is_some(); let timer=Timer::start();
        if !cached { *slot=Some(Engine { key:ProvingKey::build(bundle_version().circuit_version()),last:None }); }
        Ok(serde_json::json!({"format":"zolana-browser-prover-ready-v1","fixture_only":true,"proof_key_ms":timer.ms(),"cached":cached}).to_string())
    })
}

pub fn construct_json() -> Result<String> {
    ENGINE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let engine = slot.as_mut().ok_or("prepare the public prover first")?;
        // A failed new construction cannot leave an old decryption result usable.
        engine.last = None;
        let alice_key = fresh_key();
        let bob_key = fresh_key();
        let alice = FullViewingKey::from(&alice_key);
        let bob = FullViewingKey::from(&bob_key);
        let version = bundle_version();
        let mut rng = rand::rng();
        let timer = Timer::start();
        let mut funding = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            Anchor::empty_tree(),
        )
        .map_err(error)?;
        funding
            .add_output(
                None,
                alice.address_at(0u32, Scope::External),
                NoteValue::from_raw(100),
                [0; 512],
            )
            .map_err(error)?;
        let (funding, _) = funding
            .build::<i64>(&mut rng)
            .map_err(error)?
            .ok_or("missing synthetic funding")?;
        let funding_context = context(-100, None);
        let digest = authorization_digest(NETWORK, &funding, &funding_context).map_err(error)?;
        let funding = funding
            .create_proof(&engine.key, &mut rng)
            .map_err(error)?
            .apply_signatures(&mut rng, digest, &[])
            .map_err(error)?;
        let funding_ms = timer.ms();
        let (index, _, note, _, _) = funding
            .decrypt_outputs_with_keys(&[alice.to_ivk(Scope::External)])
            .into_iter()
            .find(|(_, _, note, _, _)| note.value().inner() == 100)
            .ok_or("synthetic funding decryption failed")?;
        let path = funding_path(index, &funding);
        let anchor = path.root(note.commitment().into());
        let timer = Timer::start();
        let mut payment = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            anchor,
        )
        .map_err(error)?;
        payment
            .add_spend(alice.clone(), note, path)
            .map_err(error)?;
        payment
            .add_output(
                None,
                bob.address_at(0u32, Scope::External),
                NoteValue::from_raw(40),
                [0; 512],
            )
            .map_err(error)?;
        payment
            .add_output(
                None,
                alice.address_at(0u32, Scope::Internal),
                NoteValue::from_raw(57),
                [0; 512],
            )
            .map_err(error)?;
        let (payment, _) = payment
            .build::<i64>(&mut rng)
            .map_err(error)?
            .ok_or("missing synthetic payment")?;
        let payment_context = context(3, Some(3));
        if *payment.value_balance() != 3 {
            return Err("synthetic balance mismatch".into());
        }
        let digest = authorization_digest(NETWORK, &payment, &payment_context).map_err(error)?;
        let payment = payment
            .create_proof(&engine.key, &mut rng)
            .map_err(error)?
            .apply_signatures(&mut rng, digest, &[SpendAuthorizingKey::from(&alice_key)])
            .map_err(error)?;
        let payment_ms = timer.ms();
        let funding_payload = wire::encode(NETWORK, &funding_context, &funding).map_err(error)?;
        let payment_payload = wire::encode(NETWORK, &payment_context, &payment).map_err(error)?;
        let frame = envelope::encode(NETWORK, &payment_payload).map_err(error)?;
        let timer = Timer::start();
        let key = Arc::new(engine.key.verifying_key());
        let result = verify_packets(&funding_payload, &payment_payload, &frame, key)?;
        let final_root = result.1;
        let fixture = PublicFixture {
            format: FORMAT.into(),
            fixture_only: true,
            network_hex: hex(&NETWORK),
            funding_payload_hex: hex(&funding_payload),
            payment_payload_hex: hex(&payment_payload),
            envelope_hex: hex(&frame),
            timings_ms: Timings {
                funding_proof: funding_ms,
                payment_proof: payment_ms,
                local_verify: timer.ms(),
            },
        };
        let json = serde_json::to_string(&fixture).map_err(error)?;
        if json.len() > MAX_FIXTURE_BYTES {
            return Err("synthetic fixture exceeds bound".into());
        }
        engine.last = Some(PrivateFixture {
            bob,
            alice,
            funding,
            payment,
            final_root,
        });
        Ok(json)
    })
}

fn verify_packets(
    funding_payload: &[u8],
    payment_payload: &[u8],
    frame: &[u8],
    key: Arc<orchard::circuit::VerifyingKey>,
) -> Result<(VerificationReport, [u8; 32])> {
    let verifier = PaymentVerifier::with_shared_key(NETWORK, Arc::clone(&key)).map_err(error)?;
    let funding = wire::decode(NETWORK, funding_payload).map_err(error)?;
    let payment = wire::decode(NETWORK, payment_payload).map_err(error)?;
    if funding.context != context(-100, None) || payment.context != context(3, Some(3)) {
        return Err("synthetic fixture context mismatch".into());
    }
    let mut pool = PoolState::new_slot_anchored(NETWORK, 1).map_err(error)?;
    pool.complete_slot(0).map_err(error)?;
    let roots = pool.accepted_roots(1).map_err(error)?;
    let mut spent = BTreeSet::new();
    let effects = verifier
        .verify(
            &funding.bundle,
            &funding.context,
            &ValidationView {
                current_slot: 1,
                accepted_anchors: &roots,
                spent_nullifiers: &spent,
                authorized_public_value_balance: -100,
            },
        )
        .map_err(error)?;
    spent.extend(effects.nullifiers);
    pool = pool.with_payment(&effects).map_err(error)?;
    pool.complete_slot(1).map_err(error)?;
    let roots = pool.accepted_roots(2).map_err(error)?;
    let effects = verifier
        .verify(
            &payment.bundle,
            &payment.context,
            &ValidationView {
                current_slot: 2,
                accepted_anchors: &roots,
                spent_nullifiers: &spent,
                authorized_public_value_balance: 3,
            },
        )
        .map_err(error)?;
    let decoded = envelope::decode(NETWORK, 2, frame).map_err(error)?;
    if wire::encode(NETWORK, &decoded.payment.context, &decoded.payment.bundle).map_err(error)?
        != payment_payload
    {
        return Err("inline envelope does not match payment".into());
    }
    if wire::encode(NETWORK, &funding.context, &funding.bundle).map_err(error)? != funding_payload {
        return Err("noncanonical synthetic funding".into());
    }
    // These mutations retain the valid bundle and proof. They must fail at the
    // precise authorization or admission boundary, before proof verification.
    let payment_view = ValidationView {
        current_slot: 2,
        accepted_anchors: &roots,
        spent_nullifiers: &spent,
        authorized_public_value_balance: 3,
    };
    let mut changed = payment.context;
    changed.sponsor = [0x54; 32];
    if verifier.verify(&payment.bundle, &changed, &payment_view)
        != Err(Error::InvalidSpendAuthorization)
    {
        return Err("changed shielded fee recipient was not rejected by authorization".into());
    }
    changed = payment.context;
    changed.expires_at -= 1;
    if verifier.verify(&payment.bundle, &changed, &payment_view)
        != Err(Error::InvalidSpendAuthorization)
    {
        return Err("changed unexpired expiry was not rejected by authorization".into());
    }
    changed = payment.context;
    changed.shielded_fee = Some(4);
    if verifier.verify(&payment.bundle, &changed, &payment_view) != Err(Error::InvalidContext) {
        return Err("inconsistent shielded fee was not rejected by context validation".into());
    }
    let unknown_roots = BTreeSet::new();
    if verifier.verify(
        &payment.bundle,
        &payment.context,
        &ValidationView {
            accepted_anchors: &unknown_roots,
            ..payment_view
        },
    ) != Err(Error::UnknownAnchor)
    {
        return Err("unknown anchor was not rejected".into());
    }
    let other_network = [0xb4; 32];
    // A rewritten wire header alone cannot authenticate a different network.
    // Decode a canonical other-network packet and check the signed domain too.
    let other_payload =
        wire::encode(other_network, &payment.context, &payment.bundle).map_err(error)?;
    let other_payment = wire::decode(other_network, &other_payload).map_err(error)?;
    let other_verifier = PaymentVerifier::with_shared_key(other_network, key).map_err(error)?;
    if other_verifier.verify(&other_payment.bundle, &other_payment.context, &payment_view)
        != Err(Error::InvalidSpendAuthorization)
    {
        return Err("rewritten network was not rejected by signed authorization".into());
    }
    spent.extend(effects.nullifiers);
    if verifier.verify(
        &payment.bundle,
        &payment.context,
        &ValidationView {
            current_slot: 2,
            accepted_anchors: &roots,
            spent_nullifiers: &spent,
            authorized_public_value_balance: 3,
        },
    ) != Err(Error::SpentNullifier)
    {
        return Err("replay was not rejected by the nullifier set".into());
    }
    if wire::decode([0xb4; 32], payment_payload).is_ok()
        || envelope::decode([0xb4; 32], 2, frame).is_ok()
    {
        return Err("wrong network was accepted".into());
    }
    let mut corrupt = payment_payload.to_vec();
    let index = corrupt
        .len()
        .checked_sub(65)
        .ok_or("short synthetic payment")?;
    corrupt[index] ^= 1;
    let corrupted = wire::decode(NETWORK, &corrupt).map_err(error)?;
    if verifier.verify(
        &corrupted.bundle,
        &corrupted.context,
        &ValidationView {
            current_slot: 2,
            accepted_anchors: &roots,
            spent_nullifiers: &BTreeSet::new(),
            authorized_public_value_balance: 3,
        },
    ) != Err(Error::InvalidProof)
    {
        return Err("corrupted proof was not rejected by proof verification".into());
    }
    pool = pool.with_payment(&effects).map_err(error)?;
    pool.complete_slot(2).map_err(error)?;
    if pool.backing != 97 || pool.note_count() != 4 {
        return Err("synthetic accounting mismatch".into());
    }
    Ok((
        VerificationReport {
            ok: true,
            format: "zolana-browser-native-parity-v1",
            fixture_only: true,
            checks: vec![
                "orchard_v2_funding_proof",
                "shielded_fee_payment_proof",
                "canonical_inline_envelope",
                "slot_anchored_backing_and_nullifiers",
                "spent_replay_rejected",
                "wrong_network_rejected",
                "signed_network_mutation_rejected",
                "shielded_fee_recipient_mutation_rejected",
                "unexpired_expiry_mutation_rejected",
                "inconsistent_fee_context_rejected",
                "unknown_anchor_rejected",
                "corrupted_proof_rejected",
            ],
            payload_bytes: payment_payload.len(),
            envelope_bytes: frame.len(),
            backing_after: pool.backing,
            commitments: pool.note_count(),
        },
        pool.root(),
    ))
}

pub fn check_public_fixture(raw: &str) -> Result<VerificationReport> {
    if raw.is_empty() || raw.len() > MAX_FIXTURE_BYTES {
        return Err("bounded synthetic fixture required".into());
    }
    let fixture: PublicFixture = serde_json::from_str(raw).map_err(error)?;
    if fixture.format != FORMAT || !fixture.fixture_only || fixture.network_hex != hex(&NETWORK) {
        return Err("only the disposable browser fixture is accepted".into());
    }
    let funding = unhex(&fixture.funding_payload_hex, 16_384)?;
    let payment = unhex(&fixture.payment_payload_hex, 16_384)?;
    let frame = unhex(&fixture.envelope_hex, 16_384)?;
    let key = Arc::new(orchard::circuit::VerifyingKey::build(
        bundle_version().circuit_version(),
    ));
    Ok(verify_packets(&funding, &payment, &frame, key)?.0)
}

pub fn decrypt_json() -> Result<String> {
    ENGINE.with(|slot| {
        let slot=slot.borrow(); let fixture=slot.as_ref().and_then(|engine|engine.last.as_ref()).ok_or("construct the synthetic fixture first")?;
        let timer=Timer::start();
        let bob=fixture.payment.decrypt_outputs_with_keys(&[fixture.bob.to_ivk(Scope::External)]);
        let alice=fixture.payment.decrypt_outputs_with_keys(&[fixture.alice.to_ivk(Scope::Internal)]);
        let wrong=FullViewingKey::from(&fresh_key());
        let wrong_notes=fixture.payment.decrypt_outputs_with_keys(&[wrong.to_ivk(Scope::External)]).len();
        if bob.len()!=1 || alice.len()!=1 || bob[0].2.value().inner()!=40 || alice[0].2.value().inner()!=57 || wrong_notes!=0 { return Err("synthetic recipient/change decryption mismatch".into()); }
        let path=received_path(bob[0].0,&fixture.funding,&fixture.payment);
        if path.root(bob[0].2.commitment().into()).to_bytes()!=fixture.final_root { return Err("received witness does not match verified pool root".into()); }
        Ok(serde_json::json!({"format":"zolana-browser-decryption-v1","fixture_only":true,"recipient_value":40,"change_value":57,"recipient_note_count":bob.len(),"change_note_count":alice.len(),"wrong_key_notes":wrong_notes,"witness_root_verified":true,"elapsed_ms":timer.ms()}).to_string())
    })
}

#[cfg(target_arch = "wasm32")]
mod web {
    use wasm_bindgen::prelude::*;
    #[wasm_bindgen]
    pub fn version() -> String {
        super::version_json()
    }
    #[wasm_bindgen]
    pub fn prepare_prover() -> std::result::Result<String, JsValue> {
        super::prepare_json().map_err(|e| JsValue::from_str(&e))
    }
    #[wasm_bindgen]
    pub fn synthetic_fixture() -> std::result::Result<String, JsValue> {
        super::construct_json().map_err(|e| JsValue::from_str(&e))
    }
    #[wasm_bindgen]
    pub fn decrypt_fixture() -> std::result::Result<String, JsValue> {
        super::decrypt_json().map_err(|e| JsValue::from_str(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_format_hex_and_fixture_only_guards() {
        assert_eq!(unhex("00ff10", 3).unwrap(), vec![0, 255, 16]);
        for bad in ["", "0", "FF", "gg", "0000"] {
            assert!(unhex(bad, 1).is_err());
        }
        assert!(check_public_fixture("{}").is_err());
        assert!(check_public_fixture(&"x".repeat(MAX_FIXTURE_BYTES + 1)).is_err());
        assert!(version_json().contains("orchard_v2"));
    }
    #[test]
    fn real_proof_browser_core_roundtrip_and_tampering() {
        ENGINE.with(|slot| *slot.borrow_mut() = None);
        assert!(construct_json().is_err());
        assert!(decrypt_json().is_err());
        let first: serde_json::Value = serde_json::from_str(&prepare_json().unwrap()).unwrap();
        assert_eq!(first["cached"], false);
        let second: serde_json::Value = serde_json::from_str(&prepare_json().unwrap()).unwrap();
        assert_eq!(second["cached"], true);
        let raw = construct_json().unwrap();
        let report = check_public_fixture(&raw).unwrap();
        assert_eq!(report.backing_after, 97);
        assert_eq!(report.commitments, 4);
        assert_eq!(report.payload_bytes, 9230);
        let decrypted: serde_json::Value = serde_json::from_str(&decrypt_json().unwrap()).unwrap();
        assert_eq!(decrypted["witness_root_verified"], true);
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["network_hex"] = serde_json::json!("00".repeat(32));
        assert!(check_public_fixture(&value.to_string()).is_err());
        value = serde_json::from_str(&raw).unwrap();
        let packet = value["payment_payload_hex"].as_str().unwrap();
        value["payment_payload_hex"] = serde_json::json!(format!("00{}", &packet[2..]));
        assert!(check_public_fixture(&value.to_string()).is_err());
        value = serde_json::from_str(&raw).unwrap();
        value["fixture_only"] = serde_json::json!(false);
        assert!(check_public_fixture(&value.to_string()).is_err());
        value = serde_json::from_str(&raw).unwrap();
        value["secret_seed"] = serde_json::json!("not accepted");
        assert!(check_public_fixture(&value.to_string()).is_err());
    }
}
