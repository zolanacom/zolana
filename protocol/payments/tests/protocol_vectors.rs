//! Test vectors for `docs/protocol-spec.md`.
//!
//! The JSON files in `tests/vectors/` are written by this crate's own encoders
//! and record what its own decoders, verifier and state transition return. Every
//! run regenerates them and compares them with the committed copies, so a change
//! of a format, a rule or an error fails here until the vectors and the
//! specification are changed with it.
//!
//! The four payments in `tests/vectors/payloads/` carry real proofs. Building a
//! proof is slow, so a run reads those four files, requires the verifier to
//! accept each one and derives everything else from them. The ignored test
//! rebuilds the four payments from fixed keys and a fixed byte stream and
//! compares them with the files.
//!
//! After an intended change of the payment encoding, rebuild the payments:
//!
//!     PROTOCOL_VECTORS_PROVE=1 sh tools/dev.sh test --offline --locked \
//!         -p native-payments --test protocol_vectors -- --ignored
//!
//! After any intended change, rewrite the JSON files:
//!
//!     WRITE_PROTOCOL_VECTORS=1 sh tools/dev.sh test --offline --locked \
//!         -p native-payments --test protocol_vectors
//!
//! Every key in these files is public test material. None of it is a network.
use incrementalmerkletree::{Hashable, Level};
use native_payments::{
    anchors::{
        AnchorHistory, ANCHOR_HISTORY_VERSION, ANCHOR_WINDOW_SLOTS, MAX_ANCHOR_HISTORY_BYTES,
        MAX_SLOT_ANCHORS,
    },
    envelope::{
        self, ENVELOPE_DOMAIN, ENVELOPE_HEADER_BYTES, ENVELOPE_VERSION, MAX_ENVELOPE_BYTES,
        MAX_INNER_PAYMENT_BYTES,
    },
    native_accounts::{
        self, nullifier_address, pool_address, Buffer, ACCOUNT_BYTES, HEADER, PROGRAM_ID, SYSTEM_ID,
    },
    staging::{payload_digest, MAX_CHUNK_BYTES, MAX_PAYLOAD_BYTES},
    state::{PoolState, MAX_COMMITMENTS, MAX_ROOTS, SLOT_STATE_BYTES, STATE_BYTES},
    verification::{
        authorization_digest, bundle_version, AuthorizationContext, PaymentVerifier,
        ValidationView, VerifiedPayment, ACTION_COUNT, MAX_EXPIRY_WINDOW, PROTOCOL_VERSION,
    },
    wire::{self, ACTION_BYTES, HEADER_BYTES, MAGIC, SHIELDED_FEE_MAGIC, WITHDRAWAL_MAGIC},
    Error,
};
use orchard::{
    builder::{Builder, BundleType, UnauthorizedBundle},
    bundle::TxVersion,
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::Nullifier,
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitment},
    Address, Note, Proof,
};
use rand::{TryCryptoRng, TryRng};
use solana_pubkey::Pubkey;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    sync::Arc,
};

const DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors");

// ---------------------------------------------------------------------------
// The scenario

/// Public synthetic network domain `a0 a1 .. bf`; not a network.
const NETWORK: [u8; 32] = {
    let mut bytes = [0; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = 0xa0 + index as u8;
        index += 1;
    }
    bytes
};
/// Arbitrary numbers: the rent floor is a stored field the transition never reads.
const RENT_FLOOR_003: u64 = 22_724_400;
const RENT_FLOOR_004: u64 = 179_957_760;

const DEPOSIT: i64 = 1_000_000;
const TO_BOB: u64 = 400_000;
const ALICE_CHANGE: u64 = 600_000;
const TO_CAROL: u64 = 150_000;
const BOB_CHANGE: u64 = 245_000;
const FEE: u64 = 5_000;
const WITHDRAWN: i64 = 250_000;
const ALICE_REST: u64 = 350_000;

const PAYMENTS: [&str; 4] = ["deposit", "send", "fee-payment", "withdrawal"];
const PARTIES: [(&str, u8); 3] = [("alice", 0xa1), ("bob", 0xb0), ("carol", 0xc4)];

/// The Pallas base field modulus, little-endian: the least non-canonical encoding.
const FIELD_MODULUS: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
];

fn plain_digest(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .to_state();
    for part in parts {
        state.update(part);
    }
    state.finalize().as_bytes().try_into().unwrap()
}

/// A point of the Ed25519 curve nobody holds a key for, as the validator
/// requires of a withdrawal recipient.
fn public_key(label: &str) -> [u8; 32] {
    (0u32..)
        .map(|index| {
            plain_digest(
                b"ZolanaVectorKey1",
                &[label.as_bytes(), &index.to_le_bytes()],
            )
        })
        .find(|key| Pubkey::new_from_array(*key).is_on_curve())
        .unwrap()
}

fn sponsor() -> [u8; 32] {
    public_key("sponsor")
}
fn relay() -> [u8; 32] {
    public_key("relay")
}
fn recipient() -> [u8; 32] {
    public_key("recipient")
}

struct Party {
    key: SpendingKey,
    view: FullViewingKey,
    address: Address,
}

fn party(seed: u8) -> Party {
    let key = Option::<SpendingKey>::from(SpendingKey::from_bytes([seed; 32])).unwrap();
    let view = FullViewingKey::from(&key);
    let address = view.address_at(0u32, Scope::External);
    Party { key, view, address }
}

/// A fixed byte stream: block `n` is BLAKE2b-512 of the label and `n`.
struct Stream {
    label: String,
    counter: u64,
    block: [u8; 64],
    used: usize,
}

impl Stream {
    fn new(payment: &str, purpose: &str) -> Self {
        Self {
            label: format!("{payment}/{purpose}"),
            counter: 0,
            block: [0; 64],
            used: 64,
        }
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0; N];
        for byte in &mut bytes {
            if self.used == 64 {
                let block = blake2b_simd::Params::new()
                    .hash_length(64)
                    .personal(b"ZolanaVectorRng1")
                    .to_state()
                    .update(self.label.as_bytes())
                    .update(&self.counter.to_le_bytes())
                    .finalize();
                self.block.copy_from_slice(block.as_bytes());
                self.counter += 1;
                self.used = 0;
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
        bytes
    }
}

impl TryRng for Stream {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes(self.take()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes(self.take()))
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Infallible> {
        for byte in bytes {
            *byte = self.take::<1>()[0];
        }
        Ok(())
    }
}

impl TryCryptoRng for Stream {}

// ---------------------------------------------------------------------------
// A full tree, kept leaf by leaf, to check the stored frontier against.

fn node(bytes: &[u8; 32]) -> MerkleHashOrchard {
    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes)).unwrap()
}

/// The root of the tree and the sibling of `position` at every level.
fn tree(leaves: &[[u8; 32]], position: usize) -> ([u8; 32], [MerkleHashOrchard; 32]) {
    let mut nodes: Vec<MerkleHashOrchard> = leaves.iter().map(node).collect();
    let mut index = position;
    let path = std::array::from_fn(|level| {
        let height = Level::from(level as u8);
        let empty = MerkleHashOrchard::empty_root(height);
        let sibling = nodes.get(index ^ 1).copied().unwrap_or(empty);
        nodes = nodes
            .chunks(2)
            .map(|pair| MerkleHashOrchard::combine(height, &pair[0], pair.get(1).unwrap_or(&empty)))
            .collect();
        index >>= 1;
        sibling
    });
    let root = nodes
        .first()
        .copied()
        .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(32)));
    (root.to_bytes(), path)
}

fn tree_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    tree(leaves, 0).0
}

// ---------------------------------------------------------------------------
// Building the four payments (ignored test only)

fn builder(anchor: [u8; 32]) -> Builder {
    let version = bundle_version();
    Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        Option::<Anchor>::from(Anchor::from_bytes(anchor)).unwrap(),
    )
    .unwrap()
}

fn authorize(
    name: &str,
    key: &ProvingKey,
    bundle: UnauthorizedBundle<i64>,
    context: &AuthorizationContext,
    signers: &[SpendAuthorizingKey],
) -> Vec<u8> {
    let digest = authorization_digest(NETWORK, &bundle, context).unwrap();
    let bundle = bundle
        .create_proof(key, Stream::new(name, "prove"))
        .unwrap()
        .apply_signatures(Stream::new(name, "sign"), digest, signers)
        .unwrap();
    wire::encode(NETWORK, context, &bundle).unwrap()
}

/// The note of `value` that `owner` receives in `payload`, and its action.
fn received(payload: &[u8], owner: &Party, value: u64) -> (usize, Note) {
    let (action, _, note, _, _) = wire::decode(NETWORK, payload)
        .unwrap()
        .bundle
        .decrypt_outputs_with_keys(&[owner.view.to_ivk(Scope::External)])
        .into_iter()
        .find(|(_, _, note, _, _)| note.value().inner() == value)
        .unwrap();
    (action, note)
}

fn commitments(payload: &[u8]) -> [[u8; 32]; 2] {
    let decoded = wire::decode(NETWORK, payload).unwrap();
    std::array::from_fn(|index| decoded.bundle.actions()[index].cmx().to_bytes())
}

fn spend(builder: &mut Builder, owner: &Party, note: Note, leaves: &[[u8; 32]], position: usize) {
    let path = MerklePath::from_parts(position as u32, tree(leaves, position).1);
    builder.add_spend(owner.view.clone(), note, path).unwrap();
}

fn output(builder: &mut Builder, to: &Party, value: u64) {
    builder
        .add_output(None, to.address, NoteValue::from_raw(value), [0; 512])
        .unwrap();
}

fn generate_payments() -> Vec<Vec<u8>> {
    let key = ProvingKey::build(bundle_version().circuit_version());
    let [alice, bob, carol] = PARTIES.map(|(_, seed)| party(seed));
    let mut leaves: Vec<[u8; 32]> = Vec::new();

    // Alice deposits public coins into one note.
    let mut deposit = builder(tree_root(&leaves));
    output(&mut deposit, &alice, DEPOSIT as u64);
    let (bundle, _) = deposit
        .build::<i64>(Stream::new("deposit", "build"))
        .unwrap()
        .unwrap();
    let deposit = authorize(
        "deposit",
        &key,
        bundle,
        &AuthorizationContext {
            expires_at: 3_100,
            public_value_balance: -DEPOSIT,
            sponsor: sponsor(),
            withdrawal_recipient: None,
            shielded_fee: None,
        },
        &[],
    );
    let (action, alice_note) = received(&deposit, &alice, DEPOSIT as u64);
    let alice_position = leaves.len() + action;
    leaves.extend(commitments(&deposit));

    // Alice pays Bob and keeps the change; nothing public moves.
    let mut send = builder(tree_root(&leaves));
    spend(&mut send, &alice, alice_note, &leaves, alice_position);
    output(&mut send, &bob, TO_BOB);
    output(&mut send, &alice, ALICE_CHANGE);
    let (bundle, _) = send
        .build::<i64>(Stream::new("send", "build"))
        .unwrap()
        .unwrap();
    let send = authorize(
        "send",
        &key,
        bundle,
        &AuthorizationContext {
            expires_at: 3_100,
            public_value_balance: 0,
            sponsor: sponsor(),
            withdrawal_recipient: None,
            shielded_fee: None,
        },
        &[SpendAuthorizingKey::from(&alice.key)],
    );
    let (action, bob_note) = received(&send, &bob, TO_BOB);
    let bob_position = leaves.len() + action;
    let (action, alice_note) = received(&send, &alice, ALICE_CHANGE);
    let alice_position = leaves.len() + action;
    leaves.extend(commitments(&send));

    // Bob pays Carol and reimburses a relay from his note.
    let mut fee = builder(tree_root(&leaves));
    spend(&mut fee, &bob, bob_note, &leaves, bob_position);
    output(&mut fee, &carol, TO_CAROL);
    output(&mut fee, &bob, BOB_CHANGE);
    let (bundle, _) = fee
        .build::<i64>(Stream::new("fee-payment", "build"))
        .unwrap()
        .unwrap();
    let fee = authorize(
        "fee-payment",
        &key,
        bundle,
        &AuthorizationContext {
            expires_at: 4_000,
            public_value_balance: FEE as i64,
            sponsor: relay(),
            withdrawal_recipient: None,
            shielded_fee: Some(FEE),
        },
        &[SpendAuthorizingKey::from(&bob.key)],
    );
    leaves.extend(commitments(&fee));

    // Alice withdraws part of her change to a public account.
    let mut withdrawal = builder(tree_root(&leaves));
    spend(&mut withdrawal, &alice, alice_note, &leaves, alice_position);
    output(&mut withdrawal, &alice, ALICE_REST);
    let (bundle, _) = withdrawal
        .build::<i64>(Stream::new("withdrawal", "build"))
        .unwrap()
        .unwrap();
    let withdrawal = authorize(
        "withdrawal",
        &key,
        bundle,
        &AuthorizationContext {
            expires_at: 3_200,
            public_value_balance: WITHDRAWN,
            sponsor: sponsor(),
            withdrawal_recipient: Some(recipient()),
            shielded_fee: None,
        },
        &[SpendAuthorizingKey::from(&alice.key)],
    );
    vec![deposit, send, fee, withdrawal]
}

fn payload_path(name: &str) -> String {
    format!("{DIRECTORY}/payloads/{name}.hex")
}

fn load_payments() -> Vec<Vec<u8>> {
    PAYMENTS
        .iter()
        .map(|name| {
            let text = std::fs::read_to_string(payload_path(name))
                .unwrap_or_else(|_| panic!("{name}: no payload; see the header of this file"));
            unhex(text.trim_end())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// JSON, written by hand: the crate has no serializer among its dependencies.

enum Json {
    Null,
    Number(i128),
    Text(String),
    List(Vec<Json>),
    Map(Vec<(&'static str, Json)>),
}

fn number(value: impl Into<i128>) -> Json {
    Json::Number(value.into())
}
fn size(value: usize) -> Json {
    Json::Number(value as i128)
}
fn text(value: impl std::fmt::Display) -> Json {
    Json::Text(value.to_string())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}
fn bytes(bytes: &[u8]) -> Json {
    Json::Text(hex(bytes))
}
fn ascii(bytes: &[u8]) -> Json {
    Json::Text(String::from_utf8(bytes.to_vec()).unwrap())
}
fn address(bytes: [u8; 32]) -> Json {
    text(Pubkey::new_from_array(bytes))
}
fn outcome<T>(result: &Result<T, Error>) -> Json {
    match result {
        Ok(_) => text("ok"),
        Err(error) => text(format!("{error:?}")),
    }
}
fn roots(set: &BTreeSet<[u8; 32]>) -> Json {
    Json::List(set.iter().map(|root| bytes(root)).collect())
}

/// An account or a frame that ends in zero bytes: its length, the bytes up to
/// the last non-zero one, and the unkeyed BLAKE2b-256 of the whole.
fn blob(data: &[u8]) -> Json {
    let end = data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    Json::Map(vec![
        ("bytes", size(data.len())),
        ("prefix_hex", bytes(&data[..end])),
        (
            "blake2b_256",
            bytes(
                blake2b_simd::Params::new()
                    .hash_length(32)
                    .hash(data)
                    .as_bytes(),
            ),
        ),
    ])
}

impl Json {
    fn scalar(&self) -> bool {
        !matches!(self, Json::List(_) | Json::Map(_))
    }

    fn write(&self, depth: usize, out: &mut String) {
        let pad = "  ".repeat(depth + 1);
        match self {
            Json::Null => out.push_str("null"),
            Json::Number(value) => out.push_str(&value.to_string()),
            Json::Text(value) => {
                assert!(value
                    .chars()
                    .all(|c| (' '..='~').contains(&c) && c != '"' && c != '\\'));
                out.push('"');
                out.push_str(value);
                out.push('"');
            }
            Json::List(items) if items.is_empty() => out.push_str("[]"),
            Json::List(items) => {
                let mut line = String::new();
                if items.iter().all(Json::scalar) {
                    for (index, item) in items.iter().enumerate() {
                        line.push_str(if index == 0 { "[" } else { ", " });
                        item.write(0, &mut line);
                    }
                    line.push(']');
                }
                if !line.is_empty() && line.len() <= 96 {
                    out.push_str(&line);
                    return;
                }
                out.push_str("[\n");
                for (index, item) in items.iter().enumerate() {
                    out.push_str(&pad);
                    item.write(depth + 1, out);
                    out.push_str(if index + 1 == items.len() {
                        "\n"
                    } else {
                        ",\n"
                    });
                }
                out.push_str(&"  ".repeat(depth));
                out.push(']');
            }
            Json::Map(items) => {
                out.push_str("{\n");
                for (index, (key, item)) in items.iter().enumerate() {
                    out.push_str(&format!("{pad}\"{key}\": "));
                    item.write(depth + 1, out);
                    out.push_str(if index + 1 == items.len() {
                        "\n"
                    } else {
                        ",\n"
                    });
                }
                out.push_str(&"  ".repeat(depth));
                out.push('}');
            }
        }
    }

    fn file(self) -> String {
        let mut out = String::new();
        self.write(0, &mut out);
        out.push('\n');
        out
    }
}

// ---------------------------------------------------------------------------
// Edits of a base encoding, applied in order

#[derive(Clone)]
enum Edit {
    Replace(usize, Vec<u8>),
    Remove(usize, usize),
    Truncate(usize),
    Append(Vec<u8>),
    /// Zero bytes appended up to a length.
    Extend(usize),
}

fn replace(at: usize, with: &[u8]) -> Edit {
    Edit::Replace(at, with.to_vec())
}

fn apply(base: &[u8], edits: &[Edit]) -> Vec<u8> {
    let mut data = base.to_vec();
    for edit in edits {
        match edit {
            Edit::Replace(at, with) => data[*at..*at + with.len()].copy_from_slice(with),
            Edit::Remove(at, length) => {
                data.drain(*at..*at + *length);
            }
            Edit::Truncate(to) => data.truncate(*to),
            Edit::Append(with) => data.extend_from_slice(with),
            Edit::Extend(to) => data.resize(*to, 0),
        }
    }
    data
}

fn edits(list: &[Edit]) -> Json {
    Json::List(
        list.iter()
            .map(|edit| {
                Json::Map(match edit {
                    Edit::Replace(at, with) => vec![
                        ("op", text("replace")),
                        ("at", size(*at)),
                        ("hex", bytes(with)),
                    ],
                    Edit::Remove(at, length) => vec![
                        ("op", text("remove")),
                        ("at", size(*at)),
                        ("length", size(*length)),
                    ],
                    Edit::Truncate(to) => vec![("op", text("truncate")), ("to", size(*to))],
                    Edit::Append(with) => vec![("op", text("append")), ("hex", bytes(with))],
                    Edit::Extend(to) => vec![("op", text("zero_extend")), ("to", size(*to))],
                })
            })
            .collect(),
    )
}

/// One decoder case: a base, its edits and the result the specification states.
struct Case {
    name: &'static str,
    base: &'static str,
    edits: Vec<Edit>,
    expected: Result<(), Error>,
}

fn case(
    name: &'static str,
    base: &'static str,
    edits: Vec<Edit>,
    expected: Result<(), Error>,
) -> Case {
    Case {
        name,
        base,
        edits,
        expected,
    }
}

/// Runs the cases through `decode`, requires the stated results and lists them.
fn decode_cases(
    cases: Vec<Case>,
    bases: &BTreeMap<&'static str, Vec<u8>>,
    decode: impl Fn(&[u8]) -> Result<(), Error>,
) -> Json {
    let mut names = BTreeSet::new();
    Json::List(
        cases
            .into_iter()
            .map(|case| {
                assert!(names.insert(case.name), "{}: name used twice", case.name);
                let input = apply(&bases[case.base], &case.edits);
                let result = decode(&input);
                assert_eq!(result, case.expected, "{}", case.name);
                Json::Map(vec![
                    ("name", text(case.name)),
                    ("base", text(case.base)),
                    ("edits", edits(&case.edits)),
                    ("result", outcome(&result)),
                ])
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Encodings that are canonical field elements but not points, and the like

/// The least canonical x-coordinate that is on no curve point.
fn not_a_point() -> [u8; 32] {
    (1u8..)
        .map(|value| {
            let mut bytes = [0; 32];
            bytes[0] = value;
            bytes
        })
        .find(|bytes| !bool::from(ValueCommitment::from_bytes(bytes).is_some()))
        .unwrap()
}

/// The largest canonical field element: the modulus less one.
fn largest_element() -> [u8; 32] {
    let mut bytes = FIELD_MODULUS;
    bytes[0] -= 1;
    assert!(bool::from(Nullifier::from_bytes(&bytes).is_some()));
    assert!(!bool::from(Nullifier::from_bytes(&FIELD_MODULUS).is_some()));
    bytes
}

/// A canonical field element that is no root or commitment of the scenario.
fn element(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    assert!(bool::from(Anchor::from_bytes(bytes).is_some()));
    bytes
}

// ---------------------------------------------------------------------------
// payments.json

struct Layout {
    extra: usize,
    anchor: usize,
    actions: usize,
    proof_length: usize,
    proof: usize,
    binding: usize,
    total: usize,
}

fn layout(tag: &[u8]) -> Layout {
    let extra = if tag == SHIELDED_FEE_MAGIC {
        8
    } else if tag == WITHDRAWAL_MAGIC {
        32
    } else {
        assert_eq!(tag, MAGIC);
        0
    };
    let actions = HEADER_BYTES + extra;
    let proof_length = actions + ACTION_COUNT * ACTION_BYTES;
    let proof = proof_length + 4;
    let binding = proof + Proof::expected_proof_size(ACTION_COUNT);
    Layout {
        extra,
        anchor: 88 + extra,
        actions,
        proof_length,
        proof,
        binding,
        total: binding + 64,
    }
}

struct Digests {
    compact: [u8; 32],
    memos: [u8; 32],
    noncompact: [u8; 32],
    commitment: [u8; 32],
    personal: &'static [u8; 16],
    preimage: Vec<u8>,
    digest: [u8; 32],
}

/// The authorization digest, computed from the payload bytes alone as the
/// specification describes it, and required to equal the crate's.
fn digests(payload: &[u8]) -> Digests {
    let at = layout(&payload[..8]);
    let mut compact = Vec::new();
    let mut memos = Vec::new();
    let mut noncompact = Vec::new();
    for index in 0..ACTION_COUNT {
        let action = &payload[at.actions + index * ACTION_BYTES..][..ACTION_BYTES];
        compact.extend_from_slice(&action[..32]);
        compact.extend_from_slice(&action[64..128]);
        compact.extend_from_slice(&action[128..180]);
        memos.extend_from_slice(&action[180..692]);
        noncompact.extend_from_slice(&action[788..820]);
        noncompact.extend_from_slice(&action[32..64]);
        noncompact.extend_from_slice(&action[692..788]);
    }
    let compact = plain_digest(b"ZTxIdOrcActCHash", &[&compact]);
    let memos = plain_digest(b"ZTxIdOrcActMHash", &[&memos]);
    let noncompact = plain_digest(b"ZTxIdOrcActNHash", &[&noncompact]);
    let commitment = plain_digest(
        b"ZTxIdOrchardHash",
        &[
            &compact,
            &memos,
            &noncompact,
            &payload[at.anchor + 32..at.anchor + 33],
            &payload[48..56],
            &payload[at.anchor..at.anchor + 32],
        ],
    );
    let personal: &[u8; 16] = match at.extra {
        8 => b"NativePayAuthV3!",
        32 => b"NativePayAuthV2!",
        _ => b"NativePayAuthV1!",
    };
    let mut preimage = payload[8..40].to_vec();
    preimage.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    preimage.extend_from_slice(&commitment);
    preimage.extend_from_slice(&payload[40..at.anchor]);
    let digest = plain_digest(personal, &[&preimage]);

    let decoded = wire::decode(NETWORK, payload).unwrap();
    let theirs: [u8; 32] = decoded.bundle.commitment(TxVersion::V5).unwrap().into();
    assert_eq!(commitment, theirs);
    assert_eq!(
        digest,
        authorization_digest(NETWORK, &decoded.bundle, &decoded.context).unwrap()
    );
    Digests {
        compact,
        memos,
        noncompact,
        commitment,
        personal,
        preimage,
        digest,
    }
}

fn effects(payment: &VerifiedPayment) -> Json {
    Json::Map(vec![
        (
            "nullifiers",
            Json::List(payment.nullifiers.iter().map(|n| bytes(n)).collect()),
        ),
        (
            "commitments",
            Json::List(payment.commitments.iter().map(|c| bytes(c)).collect()),
        ),
        ("public_value_balance", number(payment.public_value_balance)),
    ])
}

fn payment(name: &str, payload: &[u8]) -> Json {
    let at = layout(&payload[..8]);
    assert_eq!(payload.len(), at.total);
    let decoded = wire::decode(NETWORK, payload).unwrap();
    assert_eq!(
        wire::encode(NETWORK, &decoded.context, &decoded.bundle).unwrap(),
        payload
    );
    let context = decoded.context;
    let digests = digests(payload);
    let actions = (0..ACTION_COUNT)
        .map(|index| {
            let start = at.actions + index * ACTION_BYTES;
            let action = &payload[start..start + ACTION_BYTES];
            Json::Map(vec![
                ("offset", size(start)),
                ("nullifier", bytes(&action[..32])),
                ("rk", bytes(&action[32..64])),
                ("cmx", bytes(&action[64..96])),
                ("epk", bytes(&action[96..128])),
                ("cv_net", bytes(&action[788..820])),
                ("spend_signature", bytes(&action[820..884])),
            ])
        })
        .collect();
    // What the three test wallets can read in the encrypted outputs.
    let notes = PARTIES
        .iter()
        .flat_map(|(owner, seed)| {
            decoded
                .bundle
                .decrypt_outputs_with_keys(&[party(*seed).view.to_ivk(Scope::External)])
                .into_iter()
                .map(|(action, _, note, _, _)| (action, *owner, note.value().inner()))
                .collect::<Vec<_>>()
        })
        .filter(|(_, _, value)| *value != 0)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(action, owner, value)| {
            Json::Map(vec![
                ("action", size(action)),
                ("recipient", text(owner)),
                ("value", number(value)),
            ])
        })
        .collect();
    Json::Map(vec![
        ("name", text(name)),
        ("tag", ascii(&payload[..8])),
        ("payload_bytes", size(payload.len())),
        ("payload_digest", bytes(&payload_digest(payload))),
        (
            "fields",
            Json::Map(vec![
                ("network", bytes(&payload[8..40])),
                ("expires_at", number(context.expires_at)),
                ("public_value_balance", number(context.public_value_balance)),
                ("sponsor", bytes(&context.sponsor)),
                (
                    "shielded_fee",
                    context.shielded_fee.map_or(Json::Null, number),
                ),
                (
                    "withdrawal_recipient",
                    context
                        .withdrawal_recipient
                        .map_or(Json::Null, |key| bytes(&key)),
                ),
                ("anchor_offset", size(at.anchor)),
                ("anchor", bytes(&payload[at.anchor..at.anchor + 32])),
                ("flags", number(payload[at.anchor + 32])),
                ("action_count", number(payload[at.anchor + 33])),
                ("actions", Json::List(actions)),
                ("proof_length_offset", size(at.proof_length)),
                ("proof_offset", size(at.proof)),
                ("proof_bytes", size(at.binding - at.proof)),
                ("binding_signature_offset", size(at.binding)),
                ("binding_signature", bytes(&payload[at.binding..])),
            ]),
        ),
        (
            "authorization",
            Json::Map(vec![
                ("compact_digest", bytes(&digests.compact)),
                ("memos_digest", bytes(&digests.memos)),
                ("noncompact_digest", bytes(&digests.noncompact)),
                ("bundle_commitment", bytes(&digests.commitment)),
                ("personalization", ascii(digests.personal)),
                ("preimage_hex", bytes(&digests.preimage)),
                ("digest", bytes(&digests.digest)),
            ]),
        ),
        ("decrypted_outputs", Json::List(notes)),
        ("payload_hex", bytes(payload)),
    ])
}

fn wire_cases(bases: &BTreeMap<&'static str, Vec<u8>>) -> Json {
    use Error::*;
    let plain = layout(MAGIC);
    let fee = layout(SHIELDED_FEE_MAGIC);
    let bound = layout(WITHDRAWAL_MAGIC);
    let second = plain.actions + ACTION_BYTES;
    let high = [0xff; 32];
    let no_point = not_a_point();
    let mut cases = vec![
        case("unchanged", "send", vec![], Ok(())),
        case(
            "one byte short",
            "send",
            vec![Edit::Truncate(plain.total - 1)],
            Err(InvalidLength),
        ),
        case(
            "one byte long",
            "send",
            vec![Edit::Append(vec![0])],
            Err(InvalidLength),
        ),
        case("empty", "send", vec![Edit::Truncate(0)], Err(InvalidLength)),
        case(
            "unknown tag of the plain size",
            "send",
            vec![replace(0, b"NPAY0004")],
            Err(UnsupportedVersion),
        ),
        case(
            "withdrawal tag on the plain size",
            "send",
            vec![replace(0, WITHDRAWAL_MAGIC)],
            Err(InvalidLength),
        ),
        case(
            "fee tag on the plain size",
            "send",
            vec![replace(0, SHIELDED_FEE_MAGIC)],
            Err(InvalidLength),
        ),
        case(
            "plain tag on the withdrawal size",
            "withdrawal",
            vec![replace(0, MAGIC)],
            Err(InvalidLength),
        ),
        case(
            "another network",
            "send",
            vec![replace(8, &[0xa1])],
            Err(WrongNetwork),
        ),
        case(
            "any expiry decodes",
            "send",
            vec![replace(40, &u64::MAX.to_le_bytes())],
            Ok(()),
        ),
        case(
            "any plain value balance decodes",
            "send",
            vec![replace(48, &i64::MIN.to_le_bytes())],
            Ok(()),
        ),
        case(
            "zero sponsor",
            "send",
            vec![replace(56, &[0; 32])],
            Err(InvalidContext),
        ),
        case(
            "zero fee",
            "fee-payment",
            vec![replace(48, &[0; 8]), replace(88, &[0; 8])],
            Err(InvalidContext),
        ),
        case(
            "fee differs from the value balance",
            "fee-payment",
            vec![replace(88, &(FEE + 1).to_le_bytes())],
            Err(InvalidContext),
        ),
        case(
            "fee above the largest signed amount",
            "fee-payment",
            vec![
                replace(48, &i64::MIN.to_le_bytes()),
                replace(88, &(1u64 << 63).to_le_bytes()),
            ],
            Err(InvalidContext),
        ),
        case(
            "zero withdrawal recipient",
            "withdrawal",
            vec![replace(88, &[0; 32])],
            Err(InvalidContext),
        ),
        case(
            "withdrawal of nothing",
            "withdrawal",
            vec![replace(48, &[0; 8])],
            Err(InvalidContext),
        ),
        case(
            "withdrawal of a negative amount",
            "withdrawal",
            vec![replace(48, &(-1i64).to_le_bytes())],
            Err(InvalidContext),
        ),
        case(
            "anchor is not a field element",
            "send",
            vec![replace(plain.anchor, &high)],
            Err(InvalidEncoding),
        ),
        case(
            "anchor is the field modulus",
            "send",
            vec![replace(plain.anchor, &FIELD_MODULUS)],
            Err(InvalidEncoding),
        ),
        case(
            "anchor is the largest field element",
            "send",
            vec![replace(plain.anchor, &largest_element())],
            Ok(()),
        ),
        case(
            "fee payment anchor is not a field element",
            "fee-payment",
            vec![replace(fee.anchor, &high)],
            Err(InvalidEncoding),
        ),
        case(
            "withdrawal anchor is not a field element",
            "withdrawal",
            vec![replace(bound.anchor, &high)],
            Err(InvalidEncoding),
        ),
        case(
            "flags without outputs",
            "send",
            vec![replace(plain.anchor + 32, &[1])],
            Err(InvalidShape),
        ),
        case(
            "flags with a reserved bit",
            "send",
            vec![replace(plain.anchor + 32, &[7])],
            Err(InvalidShape),
        ),
        case(
            "one action",
            "send",
            vec![replace(plain.anchor + 33, &[1])],
            Err(InvalidShape),
        ),
        case(
            "three actions",
            "send",
            vec![replace(plain.anchor + 33, &[3])],
            Err(InvalidShape),
        ),
        case(
            "proof length field too small",
            "send",
            vec![replace(plain.proof_length, &7_263u32.to_le_bytes())],
            Err(InvalidLength),
        ),
        case(
            "proof length field too large",
            "send",
            vec![replace(plain.proof_length, &7_265u32.to_le_bytes())],
            Err(InvalidLength),
        ),
        case(
            "any proof bytes decode",
            "send",
            vec![replace(plain.proof, &[0; 64])],
            Ok(()),
        ),
        case(
            "any signature bytes decode",
            "send",
            vec![
                replace(plain.actions + 820, &[0xff; 64]),
                replace(plain.binding, &[0xff; 64]),
            ],
            Ok(()),
        ),
        case(
            "equal nullifiers decode",
            "send",
            vec![Edit::Replace(
                second,
                bases["send"][plain.actions..plain.actions + 32].to_vec(),
            )],
            Ok(()),
        ),
    ];
    // Every field of an action, in the first action and in the second.
    for (start, which) in [(plain.actions, "first"), (second, "second")] {
        let named = |field: &str| -> &'static str {
            Box::leak(format!("{which} action: {field}").into_boxed_str())
        };
        cases.extend([
            case(
                named("nullifier is not a field element"),
                "send",
                vec![replace(start, &high)],
                Err(InvalidEncoding),
            ),
            case(
                named("nullifier is the field modulus"),
                "send",
                vec![replace(start, &FIELD_MODULUS)],
                Err(InvalidEncoding),
            ),
            case(
                named("rk is the identity"),
                "send",
                vec![replace(start + 32, &[0; 32])],
                Err(InvalidEncoding),
            ),
            case(
                named("rk is not a point"),
                "send",
                vec![replace(start + 32, &no_point)],
                Err(InvalidEncoding),
            ),
            case(
                named("rk is not a field element"),
                "send",
                vec![replace(start + 32, &high)],
                Err(InvalidEncoding),
            ),
            case(
                named("cmx is not a field element"),
                "send",
                vec![replace(start + 64, &high)],
                Err(InvalidEncoding),
            ),
            case(
                named("epk is the identity"),
                "send",
                vec![replace(start + 96, &[0; 32])],
                Err(InvalidEncoding),
            ),
            case(
                named("epk is not a point"),
                "send",
                vec![replace(start + 96, &no_point)],
                Err(InvalidEncoding),
            ),
            case(
                named("any ciphertext decodes"),
                "send",
                vec![replace(start + 128, &[0x5a; 660])],
                Ok(()),
            ),
            case(
                named("cv_net is the identity"),
                "send",
                vec![replace(start + 788, &[0; 32])],
                Ok(()),
            ),
            case(
                named("cv_net is not a point"),
                "send",
                vec![replace(start + 788, &no_point)],
                Err(InvalidEncoding),
            ),
        ]);
    }
    decode_cases(cases, bases, |input| {
        let decoded = wire::decode(NETWORK, input)?;
        // What decodes encodes back to the same bytes.
        assert_eq!(
            wire::encode(NETWORK, &decoded.context, &decoded.bundle).unwrap(),
            input
        );
        Ok(())
    })
}

struct Check {
    name: &'static str,
    base: &'static str,
    edits: Vec<Edit>,
    slot: u64,
    /// `None`: exactly the anchor of the payment.
    anchors: Option<Vec<[u8; 32]>>,
    spent: Vec<[u8; 32]>,
    /// `None`: the value balance of the payment.
    authorized: Option<i64>,
    expected: Result<(), Error>,
}

fn check(
    name: &'static str,
    base: &'static str,
    edits: Vec<Edit>,
    slot: u64,
    expected: Result<(), Error>,
) -> Check {
    Check {
        name,
        base,
        edits,
        slot,
        anchors: None,
        spent: Vec::new(),
        authorized: None,
        expected,
    }
}

fn verification_cases(bases: &BTreeMap<&'static str, Vec<u8>>, verifier: &PaymentVerifier) -> Json {
    use Error::*;
    let plain = layout(MAGIC);
    let bound = layout(WITHDRAWAL_MAGIC);
    let fee = layout(SHIELDED_FEE_MAGIC);
    let send = &bases["send"];
    let first_nullifier: [u8; 32] = send[plain.actions..plain.actions + 32].try_into().unwrap();
    let flipped = |at: usize, base: &[u8]| Edit::Replace(at, vec![base[at] ^ 1]);
    let mut cases = vec![
        check("deposit accepted", "deposit", vec![], 3_000, Ok(())),
        check("send accepted", "send", vec![], 3_002, Ok(())),
        check("fee payment accepted", "fee-payment", vec![], 3_004, Ok(())),
        check("withdrawal accepted", "withdrawal", vec![], 3_005, Ok(())),
        check("accepted in the expiry slot", "send", vec![], 3_100, Ok(())),
        check(
            "refused after the expiry slot",
            "send",
            vec![],
            3_101,
            Err(Expired),
        ),
        check(
            "accepted 1,024 slots before expiry",
            "send",
            vec![],
            3_100 - MAX_EXPIRY_WINDOW,
            Ok(()),
        ),
        check(
            "refused 1,025 slots before expiry",
            "send",
            vec![],
            3_100 - MAX_EXPIRY_WINDOW - 1,
            Err(InvalidContext),
        ),
        Check {
            anchors: Some(vec![]),
            ..check(
                "anchor is not accepted",
                "send",
                vec![],
                3_002,
                Err(UnknownAnchor),
            )
        },
        Check {
            anchors: Some(vec![tree_root(&[])]),
            ..check(
                "another anchor is accepted",
                "send",
                vec![],
                3_002,
                Err(UnknownAnchor),
            )
        },
        Check {
            spent: vec![first_nullifier],
            ..check(
                "a nullifier is spent",
                "send",
                vec![],
                3_002,
                Err(SpentNullifier),
            )
        },
        Check {
            authorized: Some(1),
            ..check(
                "another public movement is authorized",
                "send",
                vec![],
                3_002,
                Err(WrongValueBalance),
            )
        },
        check(
            "equal nullifiers",
            "send",
            vec![Edit::Replace(
                plain.actions + ACTION_BYTES,
                first_nullifier.to_vec(),
            )],
            3_002,
            Err(DuplicateNullifier),
        ),
        // Each edit below changes signed bytes: the digest no longer matches.
        check(
            "expiry changed",
            "send",
            vec![replace(40, &3_099u64.to_le_bytes())],
            3_002,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "value balance changed",
            "send",
            vec![replace(48, &1i64.to_le_bytes())],
            3_002,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "sponsor changed",
            "send",
            vec![flipped(56, send)],
            3_002,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "ciphertext changed",
            "send",
            vec![flipped(plain.actions + 128, send)],
            3_002,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "commitment changed",
            "send",
            vec![replace(plain.actions + 64, &element(9))],
            3_002,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "fee and value balance changed together",
            "fee-payment",
            vec![
                replace(48, &(FEE + 1).to_le_bytes()),
                replace(88, &(FEE + 1).to_le_bytes()),
            ],
            3_004,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "relay changed",
            "fee-payment",
            vec![flipped(56, &bases["fee-payment"])],
            3_004,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "recipient changed",
            "withdrawal",
            vec![flipped(88, &bases["withdrawal"])],
            3_005,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "withdrawal turned into a plain payment",
            "withdrawal",
            vec![replace(0, MAGIC), Edit::Remove(88, 32)],
            3_005,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "fee payment turned into a plain payment",
            "fee-payment",
            vec![replace(0, MAGIC), Edit::Remove(88, 8)],
            3_004,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "spend signature changed",
            "send",
            vec![flipped(plain.actions + 820, send)],
            3_002,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "second spend signature changed",
            "send",
            vec![flipped(plain.actions + ACTION_BYTES + 820, send)],
            3_002,
            Err(InvalidSpendAuthorization),
        ),
        check(
            "binding signature changed",
            "send",
            vec![flipped(plain.binding, send)],
            3_002,
            Err(InvalidBindingSignature),
        ),
        check(
            "proof changed",
            "send",
            vec![flipped(plain.proof + 100, send)],
            3_002,
            Err(InvalidProof),
        ),
        check(
            "withdrawal proof changed",
            "withdrawal",
            vec![flipped(bound.proof + 100, &bases["withdrawal"])],
            3_005,
            Err(InvalidProof),
        ),
        check(
            "fee payment proof changed",
            "fee-payment",
            vec![flipped(fee.proof + 100, &bases["fee-payment"])],
            3_004,
            Err(InvalidProof),
        ),
    ];
    // An expired payment is refused as expired whatever else is wrong with it.
    cases.push(Check {
        anchors: Some(vec![]),
        spent: vec![first_nullifier],
        ..check(
            "expiry is checked before anchor and nullifiers",
            "send",
            vec![flipped(plain.binding, send)],
            3_101,
            Err(Expired),
        )
    });
    let mut names = BTreeSet::new();
    Json::List(
        cases
            .into_iter()
            .map(|case| {
                assert!(names.insert(case.name), "{}: name used twice", case.name);
                let payload = apply(&bases[case.base], &case.edits);
                let decoded = wire::decode(NETWORK, &payload).unwrap();
                let anchors: BTreeSet<[u8; 32]> = case
                    .anchors
                    .unwrap_or_else(|| vec![decoded.bundle.anchor().to_bytes()])
                    .into_iter()
                    .collect();
                let spent: BTreeSet<[u8; 32]> = case.spent.into_iter().collect();
                let authorized = case
                    .authorized
                    .unwrap_or(decoded.context.public_value_balance);
                let result = verifier.verify(
                    &decoded.bundle,
                    &decoded.context,
                    &ValidationView {
                        current_slot: case.slot,
                        accepted_anchors: &anchors,
                        spent_nullifiers: &spent,
                        authorized_public_value_balance: authorized,
                    },
                );
                assert_eq!(
                    result.as_ref().map(|_| ()).map_err(|error| *error),
                    case.expected,
                    "{}",
                    case.name
                );
                let mut entry = vec![
                    ("name", text(case.name)),
                    ("base", text(case.base)),
                    ("edits", edits(&case.edits)),
                    ("current_slot", number(case.slot)),
                    ("accepted_anchors", roots(&anchors)),
                    ("spent_nullifiers", roots(&spent)),
                    ("authorized_public_value_balance", number(authorized)),
                    ("result", outcome(&result)),
                ];
                if let Ok(payment) = &result {
                    entry.push(("effects", effects(payment)));
                }
                Json::Map(entry)
            })
            .collect(),
    )
}

fn payments_file(bases: &BTreeMap<&'static str, Vec<u8>>, verifier: &PaymentVerifier) -> Json {
    Json::Map(vec![
        ("format", text("zolana-protocol-vectors/payments/1")),
        ("network", bytes(&NETWORK)),
        ("protocol_version", number(PROTOCOL_VERSION)),
        ("action_count", size(ACTION_COUNT)),
        ("action_bytes", size(ACTION_BYTES)),
        (
            "proof_bytes",
            size(Proof::expected_proof_size(ACTION_COUNT)),
        ),
        ("max_expiry_window", number(MAX_EXPIRY_WINDOW)),
        (
            "test_spending_keys",
            Json::Map(
                PARTIES
                    .iter()
                    .map(|(name, seed)| (*name, bytes(&[*seed; 32])))
                    .collect(),
            ),
        ),
        (
            "payments",
            Json::List(
                PAYMENTS
                    .iter()
                    .map(|name| payment(name, &bases[name]))
                    .collect(),
            ),
        ),
        ("decode_cases", wire_cases(bases)),
        ("verification_cases", verification_cases(bases, verifier)),
    ])
}

// ---------------------------------------------------------------------------
// envelope.json

fn envelope_file(bases: &BTreeMap<&'static str, Vec<u8>>) -> Json {
    use Error::*;
    let payload = &bases["fee-payment"];
    let frame = envelope::encode(NETWORK, payload).unwrap();
    assert_eq!(frame.len(), ENVELOPE_HEADER_BYTES + payload.len());
    assert_eq!(&frame[ENVELOPE_HEADER_BYTES..], payload);
    let expires_at = u64::from_le_bytes(payload[40..48].try_into().unwrap());

    // A frame around a payment that is not a fee payment, made by hand.
    let framed = |inner: &[u8]| {
        let mut bytes = frame[..58].to_vec();
        bytes.extend_from_slice(&inner[40..48]);
        bytes.extend_from_slice(&payload_digest(inner));
        bytes.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        bytes.extend_from_slice(inner);
        bytes
    };
    let mut inputs = BTreeMap::new();
    inputs.insert("frame", frame.clone());
    inputs.insert("frame around the send", framed(&bases["send"]));
    inputs.insert("frame around the withdrawal", framed(&bases["withdrawal"]));
    let mut later = payload.clone();
    later[40..48].copy_from_slice(&(expires_at + 1).to_le_bytes());
    // The inner payment says one slot later than the header.
    let mut mismatched = framed(&later);
    mismatched[58..66].copy_from_slice(&expires_at.to_le_bytes());
    inputs.insert("frame with another inner expiry", mismatched);

    let slots = [
        (expires_at - MAX_EXPIRY_WINDOW - 1, Err(InvalidContext)),
        (expires_at - MAX_EXPIRY_WINDOW, Ok(())),
        (expires_at, Ok(())),
        (expires_at + 1, Err(Expired)),
    ]
    .into_iter()
    .map(|(slot, expected)| {
        let result = envelope::decode(NETWORK, slot, &frame);
        assert_eq!(result.as_ref().map(|_| ()).map_err(|e| *e), expected);
        if let Ok(decoded) = &result {
            assert_eq!(decoded.payment_id, payload_digest(payload));
        }
        Json::Map(vec![
            ("current_slot", number(slot)),
            ("result", outcome(&result)),
        ])
    })
    .collect();

    let length_at = ENVELOPE_HEADER_BYTES - 4;
    let cases = vec![
        case("unchanged", "frame", vec![], Ok(())),
        case(
            "tag changed",
            "frame",
            vec![replace(0, b"ZOLNPAY2")],
            Err(UnsupportedVersion),
        ),
        case(
            "version 2",
            "frame",
            vec![replace(8, &2u16.to_le_bytes())],
            Err(UnsupportedVersion),
        ),
        case(
            "domain changed",
            "frame",
            vec![replace(10, b"z")],
            Err(InvalidContext),
        ),
        case(
            "another network in the header",
            "frame",
            vec![replace(26, &[0xa1])],
            Err(WrongNetwork),
        ),
        case(
            "header expiry differs from the payment",
            "frame with another inner expiry",
            vec![],
            Err(InvalidContext),
        ),
        case(
            "identity changed",
            "frame",
            vec![replace(66, &[0; 32])],
            Err(DigestMismatch),
        ),
        case(
            "payment byte changed",
            "frame",
            vec![Edit::Replace(
                frame.len() - 1,
                vec![frame[frame.len() - 1] ^ 1],
            )],
            Err(DigestMismatch),
        ),
        case(
            "length field of zero",
            "frame",
            vec![replace(length_at, &0u32.to_le_bytes())],
            Err(InvalidLength),
        ),
        case(
            "length field one short",
            "frame",
            vec![replace(
                length_at,
                &(payload.len() as u32 - 1).to_le_bytes(),
            )],
            Err(InvalidLength),
        ),
        case(
            "length field above the frame limit",
            "frame",
            vec![replace(
                length_at,
                &(MAX_INNER_PAYMENT_BYTES as u32 + 1).to_le_bytes(),
            )],
            Err(InvalidLength),
        ),
        case(
            "trailing byte",
            "frame",
            vec![Edit::Append(vec![0])],
            Err(InvalidLength),
        ),
        case(
            "header only",
            "frame",
            vec![Edit::Truncate(ENVELOPE_HEADER_BYTES)],
            Err(InvalidLength),
        ),
        case(
            "padded to the frame limit",
            "frame",
            vec![Edit::Extend(MAX_ENVELOPE_BYTES)],
            Err(InvalidLength),
        ),
        case(
            "padded past the frame limit",
            "frame",
            vec![Edit::Extend(MAX_ENVELOPE_BYTES + 1)],
            Err(InvalidLength),
        ),
        case(
            "plain payment inside",
            "frame around the send",
            vec![],
            Err(UnsupportedVersion),
        ),
        case(
            "withdrawal inside",
            "frame around the withdrawal",
            vec![],
            Err(UnsupportedVersion),
        ),
    ];
    // Every case is read at slot 3,000, inside the window of each framed payment.
    let cases = decode_cases(cases, &inputs, |input| {
        envelope::decode(NETWORK, 3_000, input).map(|_| ())
    });
    assert_eq!(
        envelope::encode(NETWORK, &bases["send"]).err(),
        Some(UnsupportedVersion)
    );
    Json::Map(vec![
        ("format", text("zolana-protocol-vectors/envelope/1")),
        ("network", bytes(&NETWORK)),
        ("tag", ascii(&frame[..8])),
        ("version", number(ENVELOPE_VERSION)),
        ("domain", ascii(ENVELOPE_DOMAIN)),
        ("header_bytes", size(ENVELOPE_HEADER_BYTES)),
        ("max_envelope_bytes", size(MAX_ENVELOPE_BYTES)),
        ("max_inner_payment_bytes", size(MAX_INNER_PAYMENT_BYTES)),
        (
            "frame",
            Json::Map(vec![
                ("payment", text("fee-payment")),
                ("bytes", size(frame.len())),
                ("header_hex", bytes(&frame[..ENVELOPE_HEADER_BYTES])),
                ("expires_at", number(expires_at)),
                ("payment_id", bytes(&frame[66..98])),
                ("payload_length", size(payload.len())),
                (
                    "blake2b_256",
                    bytes(
                        blake2b_simd::Params::new()
                            .hash_length(32)
                            .hash(&frame)
                            .as_bytes(),
                    ),
                ),
            ]),
        ),
        ("decode_by_slot", Json::List(slots)),
        (
            "bases",
            Json::Map(
                inputs
                    .iter()
                    .filter(|(name, _)| **name != "frame")
                    .map(|(name, input)| {
                        (
                            *name,
                            Json::Map(vec![
                                ("header_hex", bytes(&input[..ENVELOPE_HEADER_BYTES])),
                                (
                                    "payload",
                                    text(match *name {
                                        "frame around the send" => "send",
                                        "frame around the withdrawal" => "withdrawal",
                                        _ => "fee-payment with expires_at one higher",
                                    }),
                                ),
                            ]),
                        )
                    })
                    .collect(),
            ),
        ),
        ("decode_cases_at_slot", number(3_000)),
        ("decode_cases", cases),
    ])
}

// ---------------------------------------------------------------------------
// staging.json

fn staging_file(bases: &BTreeMap<&'static str, Vec<u8>>) -> Json {
    type Fault = native_accounts::Error;
    let fault = |result: Result<(), Fault>| match result {
        Ok(()) => text("ok"),
        Err(error) => text(format!("{error:?}")),
    };
    let payload = &bases["send"];
    let digest = payload_digest(payload);
    let empty = vec![0; ACCOUNT_BYTES];
    let header = |buffer: &Buffer| bytes(&buffer.bytes()[..HEADER]);
    let mut steps = Vec::new();
    let mut step = |name: &str, result: Json, buffer: &Buffer, written: usize| {
        // The payload region holds what was written and zeros after it.
        assert_eq!(
            &buffer.bytes()[HEADER..HEADER + written],
            &payload[..written]
        );
        assert!(buffer.bytes()[HEADER + written..].iter().all(|b| *b == 0));
        Buffer::decode(buffer.bytes()).unwrap();
        steps.push(Json::Map(vec![
            ("operation", text(name)),
            ("result", result),
            ("header_hex", header(buffer)),
            ("payload_bytes_present", size(written)),
            (
                "account_blake2b_256",
                bytes(
                    blake2b_simd::Params::new()
                        .hash_length(32)
                        .hash(buffer.bytes())
                        .as_bytes(),
                ),
            ),
        ]));
    };

    let mut buffer =
        Buffer::initialize(&empty, sponsor(), payload.len() as u32, digest, 3_100).unwrap();
    step("initialize", text("ok"), &buffer, 0);
    step("seal before any write", fault(buffer.seal()), &buffer, 0);
    step(
        "write at offset 1",
        fault(buffer.write(1, &[0])),
        &buffer,
        0,
    );
    step("write of no bytes", fault(buffer.write(0, &[])), &buffer, 0);
    step(
        "write of 769 bytes",
        fault(buffer.write(0, &payload[..MAX_CHUNK_BYTES + 1])),
        &buffer,
        0,
    );
    let mut written = 0;
    for chunk in payload.chunks(MAX_CHUNK_BYTES) {
        let result = buffer.write(written as u32, chunk);
        written += chunk.len();
        let name = format!(
            "write {} bytes at offset {}",
            chunk.len(),
            written - chunk.len()
        );
        step(&name, fault(result), &buffer, written);
        if written == MAX_CHUNK_BYTES {
            step(
                "write again at offset 0",
                fault(buffer.write(0, &[0])),
                &buffer,
                written,
            );
            step(
                "payload before sealing",
                fault(buffer.payload().map(|_| ())),
                &buffer,
                written,
            );
            step(
                "seal before the last write",
                fault(buffer.seal()),
                &buffer,
                written,
            );
        }
    }
    step(
        "write past the stated length",
        fault(buffer.write(written as u32, &[0])),
        &buffer,
        written,
    );
    step("seal", fault(buffer.seal()), &buffer, written);
    assert_eq!(buffer.payload().unwrap(), payload);
    step("seal again", fault(buffer.seal()), &buffer, written);
    step(
        "write after sealing",
        fault(buffer.write(written as u32, &[0])),
        &buffer,
        written,
    );
    step("consume", fault(buffer.consume()), &buffer, written);
    step("consume again", fault(buffer.consume()), &buffer, written);
    step(
        "payload after consuming",
        fault(buffer.payload().map(|_| ())),
        &buffer,
        written,
    );

    // A buffer whose bytes do not match the digest it was initialized with.
    let mut other =
        Buffer::initialize(&empty, sponsor(), 4, payload_digest(&[1; 4]), 3_100).unwrap();
    other.write(0, &[2; 4]).unwrap();
    let wrong_digest = fault(other.seal());

    let initialize = |bytes: &[u8], length: u32| {
        fault(Buffer::initialize(bytes, sponsor(), length, digest, 3_100).map(|_| ()))
    };
    let mut used = empty.clone();
    used[ACCOUNT_BYTES - 1] = 1;
    let initializations = Json::List(vec![
        Json::Map(vec![
            ("name", text("length of zero")),
            ("result", initialize(&empty, 0)),
        ]),
        Json::Map(vec![
            ("name", text("length of 16,384")),
            ("result", initialize(&empty, MAX_PAYLOAD_BYTES as u32)),
        ]),
        Json::Map(vec![
            ("name", text("length of 16,385")),
            ("result", initialize(&empty, MAX_PAYLOAD_BYTES as u32 + 1)),
        ]),
        Json::Map(vec![
            ("name", text("account one byte short")),
            ("result", initialize(&empty[1..], 4)),
        ]),
        Json::Map(vec![
            ("name", text("account with a non-zero byte")),
            ("result", initialize(&used, 4)),
        ]),
    ]);

    // Stored accounts the decoder accepts or refuses, as edits of two accounts.
    let mut sealed =
        Buffer::initialize(&empty, sponsor(), 4, payload_digest(&[7; 4]), 3_100).unwrap();
    sealed.write(0, &[7; 4]).unwrap();
    let open = Buffer::decode(sealed.bytes()).unwrap();
    sealed.seal().unwrap();
    let mut stored = BTreeMap::new();
    stored.insert("sealed four-byte buffer", sealed.bytes().to_vec());
    stored.insert("unsealed four-byte buffer", open.bytes().to_vec());
    let stored_cases: Vec<(&'static str, &'static str, Vec<Edit>, bool)> = vec![
        ("unchanged", "sealed four-byte buffer", vec![], true),
        (
            "unsealed unchanged",
            "unsealed four-byte buffer",
            vec![],
            true,
        ),
        (
            "tag changed",
            "sealed four-byte buffer",
            vec![replace(0, b"NBUF0002")],
            false,
        ),
        (
            "one byte short",
            "sealed four-byte buffer",
            vec![Edit::Truncate(ACCOUNT_BYTES - 1)],
            false,
        ),
        (
            "state 2",
            "sealed four-byte buffer",
            vec![replace(88, &[2])],
            false,
        ),
        (
            "state 3",
            "sealed four-byte buffer",
            vec![replace(88, &[3])],
            true,
        ),
        (
            "state 4",
            "sealed four-byte buffer",
            vec![replace(88, &[4])],
            false,
        ),
        (
            "reserved byte set",
            "sealed four-byte buffer",
            vec![replace(95, &[1])],
            false,
        ),
        (
            "length of zero",
            "sealed four-byte buffer",
            vec![replace(40, &[0; 4])],
            false,
        ),
        (
            "length above the limit",
            "sealed four-byte buffer",
            vec![replace(40, &(MAX_PAYLOAD_BYTES as u32 + 1).to_le_bytes())],
            false,
        ),
        (
            "received above the length",
            "sealed four-byte buffer",
            vec![replace(44, &5u32.to_le_bytes())],
            false,
        ),
        (
            "sealed with bytes missing",
            "sealed four-byte buffer",
            vec![replace(44, &3u32.to_le_bytes()), replace(HEADER + 3, &[0])],
            false,
        ),
        (
            "byte after the received bytes",
            "unsealed four-byte buffer",
            vec![replace(HEADER + 4, &[1])],
            false,
        ),
        (
            "sealed with another digest stored",
            "sealed four-byte buffer",
            vec![replace(48, &[0; 32])],
            true,
        ),
        (
            "unsealed with two bytes received",
            "unsealed four-byte buffer",
            vec![
                replace(44, &2u32.to_le_bytes()),
                replace(HEADER + 2, &[0; 2]),
            ],
            true,
        ),
    ];
    let stored_cases = Json::List(
        stored_cases
            .into_iter()
            .map(|(name, base, list, accepted)| {
                let result = Buffer::decode(&apply(&stored[base], &list)).map(|_| ());
                assert_eq!(result.is_ok(), accepted, "{name}");
                Json::Map(vec![
                    ("name", text(name)),
                    ("base", text(base)),
                    ("edits", edits(&list)),
                    ("result", fault(result)),
                ])
            })
            .collect(),
    );

    Json::Map(vec![
        ("format", text("zolana-protocol-vectors/staging/1")),
        ("max_payload_bytes", size(MAX_PAYLOAD_BYTES)),
        ("max_chunk_bytes", size(MAX_CHUNK_BYTES)),
        ("header_bytes", size(HEADER)),
        ("account_bytes", size(ACCOUNT_BYTES)),
        ("digest_personalization", text("NativeStageV1!!!")),
        (
            "payload_digests",
            Json::List(
                [&b""[..], b"abc", &[0; 64]]
                    .into_iter()
                    .map(|input| {
                        Json::Map(vec![
                            ("input_hex", bytes(input)),
                            ("digest", bytes(&payload_digest(input))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "buffer",
            Json::Map(vec![
                ("payment", text("send")),
                ("sponsor", bytes(&sponsor())),
                ("length", size(payload.len())),
                ("digest", bytes(&digest)),
                ("expiry", number(3_100)),
                ("steps", Json::List(steps)),
            ]),
        ),
        ("seal_with_other_bytes", wrong_digest),
        ("initializations", initializations),
        (
            "stored_bases",
            Json::Map(
                stored
                    .iter()
                    .map(|(name, data)| (*name, blob(data)))
                    .collect(),
            ),
        ),
        ("stored_cases", stored_cases),
    ])
}

// ---------------------------------------------------------------------------
// anchors.json

fn entries(history: &AnchorHistory) -> Json {
    Json::List(
        history
            .entries()
            .iter()
            .map(|entry| {
                Json::List(vec![
                    number(entry.slot),
                    number(entry.note_count),
                    bytes(&entry.root),
                ])
            })
            .collect(),
    )
}

/// A slot, a note count, a root, the stated result and what the record shows.
type Record = (u64, u64, [u8; 32], Result<(), Error>, &'static str);

fn anchors_file() -> Json {
    use Error::*;
    let empty = tree_root(&[]);
    let mut history = AnchorHistory::new(NETWORK).unwrap();
    let fresh = history.encode();
    let records: Vec<Record> = vec![
        (10, 2, element(1), Ok(()), "first checkpoint"),
        (11, 4, element(2), Ok(()), "a later slot with more notes"),
        (
            11,
            6,
            element(3),
            Ok(()),
            "the same slot again replaces its checkpoint",
        ),
        (10, 8, element(4), Err(InvalidContext), "an earlier slot"),
        (12, 4, element(2), Err(InvalidEncoding), "fewer notes"),
        (
            12,
            6,
            element(5),
            Err(InvalidEncoding),
            "the same notes under another root",
        ),
        (
            12,
            8,
            element(3),
            Err(InvalidEncoding),
            "more notes under the same root",
        ),
        (12, 7, element(5), Err(InvalidEncoding), "an odd note count"),
        (
            12,
            MAX_COMMITMENTS + 2,
            element(5),
            Err(InvalidEncoding),
            "more notes than the tree holds",
        ),
        (12, 8, [0; 32], Err(InvalidEncoding), "a zero root"),
        (
            12,
            8,
            FIELD_MODULUS,
            Err(InvalidEncoding),
            "a root that is not a field element",
        ),
        (
            12,
            8,
            empty,
            Err(InvalidEncoding),
            "the empty root with notes",
        ),
        (
            12,
            8,
            element(1),
            Err(InvalidEncoding),
            "a root already recorded for another note count",
        ),
        (
            12,
            6,
            element(3),
            Ok(()),
            "an empty produced slot repeats the root",
        ),
        (
            522,
            8,
            element(4),
            Ok(()),
            "slot 10 is now 512 slots old and is dropped",
        ),
        (
            1_033,
            8,
            element(4),
            Ok(()),
            "slots 11 and 12 are dropped; slot 522 is 511 slots old and stays",
        ),
    ];
    let mut steps = Vec::new();
    let mut retained = Vec::new();
    for (slot, count, root, expected, why) in records {
        let before = history.encode();
        let result = history.record(slot, count, root);
        assert_eq!(result, expected, "{why}");
        if result.is_err() {
            assert_eq!(history.encode(), before);
        }
        if why == "an empty produced slot repeats the root" {
            retained = history.encode();
        }
        steps.push(Json::Map(vec![
            (
                "record",
                Json::List(vec![number(slot), number(count), bytes(&root)]),
            ),
            ("note", text(why)),
            ("result", outcome(&result)),
            ("entries_after", entries(&history)),
            ("encoding_hex", bytes(&history.encode())),
        ]));
    }

    // Which roots a payment executing in a slot may use.
    let three = AnchorHistory::decode(NETWORK, &retained).unwrap();
    let mut early = AnchorHistory::new(NETWORK).unwrap();
    early.record(0, 2, element(1)).unwrap();
    let none = AnchorHistory::new(NETWORK).unwrap();
    let queries: Vec<(&str, &AnchorHistory, Vec<u64>)> = vec![
        ("no checkpoints", &none, vec![0, 511, 512]),
        ("one checkpoint at slot 0", &early, vec![0, 1, 511, 512]),
        (
            "checkpoints at slots 10, 11 and 12",
            &three,
            vec![9, 10, 11, 12, 13, 511, 512, 521, 522, 523, 524],
        ),
    ];
    let queries = Json::List(
        queries
            .into_iter()
            .map(|(name, history, slots)| {
                Json::Map(vec![
                    ("history", text(name)),
                    ("entries", entries(history)),
                    ("encoding_hex", bytes(&history.encode())),
                    (
                        "roots_at",
                        Json::List(
                            slots
                                .into_iter()
                                .map(|slot| {
                                    let result = history.roots_at(slot);
                                    Json::Map(vec![
                                        ("execution_slot", number(slot)),
                                        ("result", outcome(&result)),
                                        ("roots", result.as_ref().map_or(Json::Null, roots)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    );

    // The largest history: a checkpoint in each of 512 consecutive slots.
    let mut full = AnchorHistory::new(NETWORK).unwrap();
    for slot in 0..=ANCHOR_WINDOW_SLOTS {
        full.record(slot, 2 * (slot + 1), element(slot + 1))
            .unwrap();
    }
    assert_eq!(full.entries().len(), MAX_SLOT_ANCHORS);
    assert_eq!(full.encode().len(), MAX_ANCHOR_HISTORY_BYTES);
    assert_eq!(full.entries()[0].slot, 1);

    let mut bases = BTreeMap::new();
    bases.insert("three checkpoints", retained.clone());
    bases.insert("no checkpoints", fresh.clone());
    let second = 60 + 48;
    let third = 60 + 96;
    let cases = vec![
        case("unchanged", "three checkpoints", vec![], Ok(())),
        case("no checkpoints", "no checkpoints", vec![], Ok(())),
        case(
            "tag changed",
            "three checkpoints",
            vec![replace(0, b"ZOLANCH2")],
            Err(UnsupportedVersion),
        ),
        case(
            "version 2",
            "three checkpoints",
            vec![replace(8, &2u16.to_le_bytes())],
            Err(UnsupportedVersion),
        ),
        case(
            "domain changed",
            "three checkpoints",
            vec![replace(10, b"z")],
            Err(InvalidContext),
        ),
        case(
            "another network",
            "three checkpoints",
            vec![replace(26, &[0xa1])],
            Err(WrongNetwork),
        ),
        case(
            "header one byte short",
            "no checkpoints",
            vec![Edit::Truncate(59)],
            Err(InvalidLength),
        ),
        case(
            "count above the entries present",
            "three checkpoints",
            vec![replace(58, &4u16.to_le_bytes())],
            Err(InvalidLength),
        ),
        case(
            "count below the entries present",
            "three checkpoints",
            vec![replace(58, &2u16.to_le_bytes())],
            Err(InvalidLength),
        ),
        case(
            "count of 513",
            "three checkpoints",
            vec![replace(58, &513u16.to_le_bytes())],
            Err(InvalidLength),
        ),
        case(
            "trailing byte",
            "three checkpoints",
            vec![Edit::Append(vec![0])],
            Err(InvalidLength),
        ),
        case(
            "slots out of order",
            "three checkpoints",
            vec![replace(second, &9u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "a slot twice",
            "three checkpoints",
            vec![replace(second, &10u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "last slot 511 after the first",
            "three checkpoints",
            vec![replace(third, &521u64.to_le_bytes())],
            Ok(()),
        ),
        case(
            "last slot 512 after the first",
            "three checkpoints",
            vec![replace(third, &522u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "note count decreases",
            "three checkpoints",
            vec![replace(second + 8, &0u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "odd note count",
            "three checkpoints",
            vec![replace(second + 8, &5u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "same note count under another root",
            "three checkpoints",
            vec![replace(third + 16, &element(9))],
            Err(InvalidEncoding),
        ),
        case(
            "more notes under an earlier root",
            "three checkpoints",
            vec![
                replace(second + 16, &element(1)),
                replace(third + 16, &element(1)),
            ],
            Err(InvalidEncoding),
        ),
        case(
            "zero root",
            "three checkpoints",
            vec![replace(second + 16, &[0; 32])],
            Err(InvalidEncoding),
        ),
        case(
            "root that is not a field element",
            "three checkpoints",
            vec![replace(second + 16, &FIELD_MODULUS)],
            Err(InvalidEncoding),
        ),
        case(
            "empty root with notes",
            "three checkpoints",
            vec![replace(60 + 16, &empty)],
            Err(InvalidEncoding),
        ),
        case(
            "no notes under another root",
            "three checkpoints",
            vec![replace(60 + 8, &0u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
    ];
    let cases = decode_cases(cases, &bases, |input| {
        let history = AnchorHistory::decode(NETWORK, input)?;
        assert_eq!(history.encode(), input);
        Ok(())
    });
    assert_eq!(
        AnchorHistory::decode([0; 32], &retained).err(),
        Some(WrongNetwork)
    );

    Json::Map(vec![
        ("format", text("zolana-protocol-vectors/anchors/1")),
        ("network", bytes(&NETWORK)),
        ("tag", ascii(&fresh[..8])),
        ("version", number(ANCHOR_HISTORY_VERSION)),
        ("domain", ascii(&fresh[10..26])),
        ("header_bytes", size(fresh.len())),
        ("entry_bytes", size(48)),
        ("window_slots", number(ANCHOR_WINDOW_SLOTS)),
        ("max_entries", size(MAX_SLOT_ANCHORS)),
        ("max_bytes", size(MAX_ANCHOR_HISTORY_BYTES)),
        ("empty_tree_root", bytes(&empty)),
        ("no_checkpoints_hex", bytes(&fresh)),
        ("records", Json::List(steps)),
        ("queries", queries),
        (
            "full_window",
            Json::Map(vec![
                (
                    "description",
                    text("record(slot, 2 * (slot + 1), slot + 1 as a little-endian field element) for slots 0 to 512"),
                ),
                ("entries", size(full.entries().len())),
                ("first_slot", number(full.entries()[0].slot)),
                ("last_slot", number(ANCHOR_WINDOW_SLOTS)),
                ("encoding", blob(&full.encode())),
            ]),
        ),
        (
            "decode_bases",
            Json::Map(vec![
                ("three checkpoints", bytes(&retained)),
                ("no checkpoints", bytes(&fresh)),
            ]),
        ),
        ("decode_cases", cases),
    ])
}

// ---------------------------------------------------------------------------
// pool.json

fn state(pool: &PoolState, slot_anchored: bool) -> Json {
    let data = pool.encode();
    assert_eq!(
        data.len(),
        if slot_anchored {
            SLOT_STATE_BYTES
        } else {
            STATE_BYTES
        }
    );
    assert_eq!(PoolState::decode(&data).unwrap().encode(), data);
    let mut entry = vec![
        ("backing", number(pool.backing)),
        ("note_count", number(pool.note_count())),
        ("root", bytes(&pool.root())),
    ];
    if let Some(history) = pool.slot_anchors() {
        entry.push(("checkpoints", entries(history)));
    } else {
        // The stored order: oldest first, the present root last.
        let stored = usize::from(data[64]);
        entry.push((
            "recent_roots",
            Json::List(
                (0..stored)
                    .map(|index| bytes(&data[1_089 + 32 * index..][..32]))
                    .collect(),
            ),
        ));
    }
    entry.push(("account", blob(&data)));
    Json::Map(entry)
}

struct Flow {
    pool: PoolState,
    slot_anchored: bool,
    leaves: Vec<[u8; 32]>,
    spent: BTreeSet<[u8; 32]>,
    steps: Vec<Json>,
    states: BTreeMap<&'static str, Vec<u8>>,
}

impl Flow {
    fn pay(
        &mut self,
        slot: u64,
        name: &'static str,
        payload: &[u8],
        verifier: &PaymentVerifier,
        expected: Result<(), Error>,
    ) {
        let decoded = wire::decode(NETWORK, payload).unwrap();
        let accepted = self.pool.accepted_roots(slot).unwrap();
        let result = verifier.verify(
            &decoded.bundle,
            &decoded.context,
            &ValidationView {
                current_slot: slot,
                accepted_anchors: &accepted,
                spent_nullifiers: &self.spent,
                authorized_public_value_balance: decoded.context.public_value_balance,
            },
        );
        assert_eq!(
            result.as_ref().map(|_| ()).map_err(|e| *e),
            expected,
            "{name} in slot {slot}"
        );
        let mut entry = vec![
            ("event", text("payment")),
            ("slot", number(slot)),
            ("payment", text(name)),
            ("accepted_roots", roots(&accepted)),
            ("result", outcome(&result)),
        ];
        if let Ok(payment) = result {
            self.pool = self.pool.with_payment(&payment).unwrap();
            self.spent.extend(payment.nullifiers);
            self.leaves.extend(payment.commitments);
            // The stored frontier gives the root of the full tree.
            assert_eq!(self.pool.root(), tree_root(&self.leaves));
            entry.push(("effects", effects(&payment)));
            entry.push(("state_after", state(&self.pool, self.slot_anchored)));
        }
        self.steps.push(Json::Map(entry));
    }

    fn complete(&mut self, slot: u64) {
        self.pool.complete_slot(slot).unwrap();
        self.steps.push(Json::Map(vec![
            ("event", text("complete_slot")),
            ("slot", number(slot)),
            ("result", text("ok")),
            ("state_after", state(&self.pool, self.slot_anchored)),
        ]));
    }

    fn query(&mut self, slot: u64) {
        let accepted = self.pool.accepted_roots(slot).unwrap();
        self.steps.push(Json::Map(vec![
            ("event", text("accepted_roots")),
            ("slot", number(slot)),
            ("accepted_roots", roots(&accepted)),
        ]));
    }

    fn keep(&mut self, name: &'static str) {
        self.states.insert(name, self.pool.encode());
    }
}

fn flows(
    bases: &BTreeMap<&'static str, Vec<u8>>,
    verifier: &PaymentVerifier,
) -> (Json, BTreeMap<&'static str, Vec<u8>>) {
    use Error::*;
    let new = |pool: PoolState, slot_anchored| Flow {
        pool,
        slot_anchored,
        leaves: Vec::new(),
        spent: BTreeSet::new(),
        steps: Vec::new(),
        states: BTreeMap::new(),
    };
    // Per-payment roots: a root is usable from the next payment on.
    let mut legacy = new(PoolState::new(NETWORK, RENT_FLOOR_003).unwrap(), false);
    let genesis_003 = state(&legacy.pool, false);
    legacy.keep("NPOOL003 at genesis");
    legacy.pay(3_000, "deposit", &bases["deposit"], verifier, Ok(()));
    legacy.pay(3_002, "send", &bases["send"], verifier, Ok(()));
    legacy.keep("NPOOL003 after the send");
    legacy.pay(
        3_004,
        "fee-payment",
        &bases["fee-payment"],
        verifier,
        Ok(()),
    );
    legacy.pay(3_004, "withdrawal", &bases["withdrawal"], verifier, Ok(()));
    legacy.pay(
        3_004,
        "withdrawal",
        &bases["withdrawal"],
        verifier,
        Err(SpentNullifier),
    );

    // Slot checkpoints: a root is usable from the slot after its block.
    let mut slots = new(
        PoolState::new_slot_anchored(NETWORK, RENT_FLOOR_004).unwrap(),
        true,
    );
    let genesis_004 = state(&slots.pool, true);
    slots.keep("NPOOL004 at genesis");
    slots.complete(0);
    slots.complete(2_999);
    slots.pay(3_000, "deposit", &bases["deposit"], verifier, Ok(()));
    slots.pay(3_000, "send", &bases["send"], verifier, Err(UnknownAnchor));
    slots.complete(3_000);
    slots.complete(3_001);
    slots.pay(3_002, "send", &bases["send"], verifier, Ok(()));
    slots.complete(3_002);
    slots.keep("NPOOL004 after slot 3002");
    // Slot 3,003 is skipped: no block, no checkpoint.
    slots.pay(
        3_004,
        "fee-payment",
        &bases["fee-payment"],
        verifier,
        Ok(()),
    );
    slots.pay(
        3_004,
        "withdrawal",
        &bases["withdrawal"],
        verifier,
        Err(UnknownAnchor),
    );
    slots.keep("NPOOL004 inside slot 3004");
    slots.complete(3_004);
    slots.pay(3_005, "withdrawal", &bases["withdrawal"], verifier, Ok(()));
    slots.complete(3_005);
    slots.pay(
        3_006,
        "withdrawal",
        &bases["withdrawal"],
        verifier,
        Err(SpentNullifier),
    );
    // The root of slot 3,005 is accepted for 511 more slots and no longer.
    slots.query(3_005 + ANCHOR_WINDOW_SLOTS - 1);
    slots.query(3_005 + ANCHOR_WINDOW_SLOTS);
    for pool in [&legacy.pool, &slots.pool] {
        assert_eq!(pool.note_count(), 8);
        assert_eq!(pool.backing, (DEPOSIT - FEE as i64 - WITHDRAWN) as u64);
    }
    let mut states = legacy.states;
    states.extend(slots.states);
    let json = Json::List(vec![
        Json::Map(vec![
            ("pool_format", text("NPOOL003")),
            ("rent_floor", number(RENT_FLOOR_003)),
            ("genesis", genesis_003),
            ("steps", Json::List(legacy.steps)),
        ]),
        Json::Map(vec![
            ("pool_format", text("NPOOL004")),
            ("rent_floor", number(RENT_FLOOR_004)),
            ("genesis", genesis_004),
            ("steps", Json::List(slots.steps)),
        ]),
    ]);
    (json, states)
}

/// A legacy pool with `count` notes in a tree of empty subtrees, as bytes.
fn assembled(count: u64, backing: u64) -> Vec<u8> {
    let mut data = b"NPOOL003".to_vec();
    data.extend_from_slice(&NETWORK);
    for value in [RENT_FLOOR_003, backing, count] {
        data.extend_from_slice(&value.to_le_bytes());
    }
    data.push(1);
    let mut root = MerkleHashOrchard::empty_leaf();
    for level in 0..32u8 {
        let height = Level::from(level);
        let empty = MerkleHashOrchard::empty_root(height);
        if (count >> level) & 1 == 1 {
            data.extend_from_slice(&empty.to_bytes());
            root = MerkleHashOrchard::combine(height, &empty, &root);
        } else {
            data.extend_from_slice(&[0; 32]);
            root = MerkleHashOrchard::combine(height, &root, &empty);
        }
    }
    data.extend_from_slice(&root.to_bytes());
    data.resize(STATE_BYTES, 0);
    data
}

/// A name, the account before, the effects applied and the stated result.
type Transition = (&'static str, Vec<u8>, VerifiedPayment, Result<(), Error>);

fn transitions() -> Json {
    use Error::*;
    let plain = |balance: i64| VerifiedPayment {
        nullifiers: [element(1), element(2)],
        commitments: [element(3), element(4)],
        public_value_balance: balance,
    };
    let largest = i64::MAX as u64;
    let cases: Vec<Transition> = vec![
        (
            "the last two notes of the tree",
            assembled(MAX_COMMITMENTS - 2, 0),
            plain(-1),
            Ok(()),
        ),
        (
            "a full tree",
            assembled(MAX_COMMITMENTS, 0),
            plain(-1),
            Err(CapacityExceeded),
        ),
        (
            "a deposit up to the largest backing",
            assembled(0, largest - 5),
            plain(-5),
            Ok(()),
        ),
        (
            "a deposit past the largest backing",
            assembled(0, largest - 5),
            plain(-6),
            Err(CapacityExceeded),
        ),
        (
            "the most negative value balance",
            assembled(0, 0),
            plain(i64::MIN),
            Err(CapacityExceeded),
        ),
        (
            "a withdrawal of the whole backing",
            assembled(2, 7),
            plain(7),
            Ok(()),
        ),
        (
            "a withdrawal above the backing",
            assembled(2, 7),
            plain(8),
            Err(InsufficientBacking),
        ),
        (
            "a commitment that is not a field element",
            assembled(0, 0),
            VerifiedPayment {
                commitments: [element(3), FIELD_MODULUS],
                ..plain(-1)
            },
            Err(InvalidEncoding),
        ),
        (
            "equal commitments",
            assembled(0, 0),
            VerifiedPayment {
                commitments: [element(3), element(3)],
                ..plain(-1)
            },
            Ok(()),
        ),
    ];
    Json::List(
        cases
            .into_iter()
            .map(|(name, before, payment, expected)| {
                let pool = PoolState::decode(&before).unwrap();
                let result = pool.with_payment(&payment);
                assert_eq!(
                    result.as_ref().map(|_| ()).map_err(|e| *e),
                    expected,
                    "{name}"
                );
                let mut entry = vec![
                    ("name", text(name)),
                    ("state", blob(&before)),
                    ("payment", effects(&payment)),
                    ("result", outcome(&result)),
                ];
                if let Ok(next) = &result {
                    entry.push(("state_after", state(next, false)));
                }
                Json::Map(entry)
            })
            .collect(),
    )
}

fn pool_cases(states: &BTreeMap<&'static str, Vec<u8>>) -> Json {
    use Error::*;
    let legacy = "NPOOL003 after the send";
    let slots = "NPOOL004 after slot 3002";
    let inside = "NPOOL004 inside slot 3004";
    let frontier_003 = 65;
    let roots_003 = frontier_003 + 32 * 32;
    let frontier_004 = 64;
    let history_length = frontier_004 + 32 * 32;
    let history = history_length + 4;
    // After the send both pools hold four notes: frontier level 2 is occupied.
    let stored =
        u32::from_le_bytes(states[slots][history_length..history].try_into().unwrap()) as usize;
    assert_eq!(stored, 60 + 4 * 48);
    let last = history + stored - 48;
    let high = [0xff; 32];
    let cases = vec![
        case("legacy: unchanged", legacy, vec![], Ok(())),
        case("legacy: at genesis", "NPOOL003 at genesis", vec![], Ok(())),
        case(
            "legacy: earlier tag",
            legacy,
            vec![replace(0, b"NPOOL002")],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: one byte short",
            legacy,
            vec![Edit::Truncate(STATE_BYTES - 1)],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: one byte long",
            legacy,
            vec![Edit::Append(vec![0])],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: zero network",
            legacy,
            vec![replace(8, &[0; 32])],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: any rent floor",
            legacy,
            vec![replace(40, &u64::MAX.to_le_bytes())],
            Ok(()),
        ),
        case(
            "legacy: largest backing",
            legacy,
            vec![replace(48, &i64::MAX.to_le_bytes())],
            Ok(()),
        ),
        case(
            "legacy: backing above the largest signed amount",
            legacy,
            vec![replace(48, &(1u64 << 63).to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: odd note count",
            legacy,
            vec![replace(56, &5u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: note count above the tree",
            legacy,
            vec![replace(56, &(MAX_COMMITMENTS + 2).to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: no roots",
            legacy,
            vec![replace(64, &[0])],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: 65 roots",
            legacy,
            vec![replace(64, &[65])],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: one root fewer than stored",
            legacy,
            vec![replace(64, &[2])],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: node at an unoccupied level",
            legacy,
            vec![replace(frontier_003, &element(1))],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: occupied level zeroed",
            legacy,
            vec![replace(frontier_003 + 64, &[0; 32])],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: occupied level is not a field element",
            legacy,
            vec![replace(frontier_003 + 64, &high)],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: occupied level holds another node",
            legacy,
            vec![replace(frontier_003 + 64, &element(1))],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: present root changed",
            legacy,
            vec![replace(roots_003 + 64, &element(1))],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: older root is not a field element",
            legacy,
            vec![replace(roots_003, &high)],
            Err(InvalidEncoding),
        ),
        case(
            "legacy: older root replaced by another field element",
            legacy,
            vec![replace(roots_003, &element(1))],
            Ok(()),
        ),
        case(
            "legacy: byte in an unused root",
            legacy,
            vec![replace(STATE_BYTES - 1, &[1])],
            Err(InvalidEncoding),
        ),
        case("slots: unchanged", slots, vec![], Ok(())),
        case("slots: at genesis", "NPOOL004 at genesis", vec![], Ok(())),
        case(
            "slots: between a payment and the end of its slot",
            inside,
            vec![],
            Ok(()),
        ),
        case(
            "slots: frontier node changed between a payment and the end of its slot",
            inside,
            vec![replace(frontier_004 + 32, &element(1))],
            Ok(()),
        ),
        case(
            "slots: one byte short",
            slots,
            vec![Edit::Truncate(SLOT_STATE_BYTES - 1)],
            Err(InvalidEncoding),
        ),
        case(
            "slots: one byte long",
            slots,
            vec![Edit::Append(vec![0])],
            Err(InvalidEncoding),
        ),
        case(
            "slots: legacy size under this tag",
            slots,
            vec![Edit::Truncate(STATE_BYTES)],
            Err(InvalidEncoding),
        ),
        case(
            "slots: zero network",
            slots,
            vec![replace(8, &[0; 32])],
            Err(InvalidEncoding),
        ),
        case(
            "slots: backing above the largest signed amount",
            slots,
            vec![replace(48, &(1u64 << 63).to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "slots: odd note count",
            slots,
            vec![replace(56, &5u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "slots: node at an unoccupied level",
            slots,
            vec![replace(frontier_004, &element(1))],
            Err(InvalidEncoding),
        ),
        case(
            "slots: occupied level holds another node",
            slots,
            vec![replace(frontier_004 + 64, &element(1))],
            Err(InvalidEncoding),
        ),
        case(
            "slots: history length above the limit",
            slots,
            vec![replace(
                history_length,
                &(MAX_ANCHOR_HISTORY_BYTES as u32 + 1).to_le_bytes(),
            )],
            Err(InvalidLength),
        ),
        case(
            "slots: history length one too large",
            slots,
            vec![replace(history_length, &(stored as u32 + 1).to_le_bytes())],
            Err(InvalidLength),
        ),
        case(
            "slots: history length one too small",
            slots,
            vec![replace(history_length, &(stored as u32 - 1).to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "slots: byte in the padding",
            slots,
            vec![replace(SLOT_STATE_BYTES - 1, &[1])],
            Err(InvalidEncoding),
        ),
        case(
            "slots: history tag changed",
            slots,
            vec![replace(history, b"ZOLANCH2")],
            Err(UnsupportedVersion),
        ),
        case(
            "slots: history domain changed",
            slots,
            vec![replace(history + 10, b"z")],
            Err(InvalidContext),
        ),
        case(
            "slots: history of another network",
            slots,
            vec![replace(history + 26, &[0xa1])],
            Err(WrongNetwork),
        ),
        case(
            "slots: last checkpoint ahead of the tree",
            slots,
            vec![replace(last + 8, &6u64.to_le_bytes())],
            Err(InvalidEncoding),
        ),
        case(
            "slots: last checkpoint of the present tree under another root",
            slots,
            vec![replace(last + 16, &element(1))],
            Err(InvalidEncoding),
        ),
        case(
            "slots: earlier checkpoint under another root",
            slots,
            vec![
                replace(last - 96 + 16, &element(1)),
                replace(last - 48 + 16, &element(1)),
            ],
            Ok(()),
        ),
    ];
    decode_cases(cases, states, |input| {
        let pool = PoolState::decode(input)?;
        assert_eq!(pool.encode(), input);
        Ok(())
    })
}

fn pool_file(bases: &BTreeMap<&'static str, Vec<u8>>, verifier: &PaymentVerifier) -> Json {
    let (flows, states) = flows(bases, verifier);
    let empty_roots: Vec<Json> = (0..=32u8)
        .map(|level| bytes(&MerkleHashOrchard::empty_root(Level::from(level)).to_bytes()))
        .collect();
    assert_eq!(
        MerkleHashOrchard::empty_root(Level::from(0)),
        MerkleHashOrchard::empty_leaf()
    );
    // Parent nodes of the scenario's tree, for a check of the tree hash alone.
    let leaves: Vec<[u8; 32]> = PAYMENTS
        .iter()
        .flat_map(|name| commitments(&bases[name]))
        .collect();
    let mut combine = Vec::new();
    let mut nodes: Vec<MerkleHashOrchard> = leaves.iter().map(node).collect();
    for level in 0..4u8 {
        let height = Level::from(level);
        let empty = MerkleHashOrchard::empty_root(height);
        let (left, right) = (nodes[0], nodes.get(1).copied().unwrap_or(empty));
        combine.push(Json::Map(vec![
            ("level", number(level)),
            ("left", bytes(&left.to_bytes())),
            ("right", bytes(&right.to_bytes())),
            (
                "parent",
                bytes(&MerkleHashOrchard::combine(height, &left, &right).to_bytes()),
            ),
        ]));
        nodes = nodes
            .chunks(2)
            .map(|pair| MerkleHashOrchard::combine(height, &pair[0], pair.get(1).unwrap_or(&empty)))
            .collect();
    }

    // More payments than a legacy pool keeps roots.
    let mut pool = PoolState::new(NETWORK, RENT_FLOOR_003).unwrap();
    let mut seen = vec![pool.root()];
    for index in 0..MAX_ROOTS as u64 + 2 {
        pool = pool
            .with_payment(&VerifiedPayment {
                nullifiers: [element(1), element(2)],
                commitments: [element(2 * index + 3), element(2 * index + 4)],
                public_value_balance: -1,
            })
            .unwrap();
        seen.push(pool.root());
    }
    let kept = pool.roots();
    assert_eq!(kept.len(), MAX_ROOTS);
    assert!(seen[..3].iter().all(|root| !kept.contains(root)));
    assert!(seen[3..].iter().all(|root| kept.contains(root)));

    Json::Map(vec![
        ("format", text("zolana-protocol-vectors/pool/1")),
        ("network", bytes(&NETWORK)),
        ("npool003_bytes", size(STATE_BYTES)),
        ("npool004_bytes", size(SLOT_STATE_BYTES)),
        ("max_commitments", number(MAX_COMMITMENTS)),
        ("max_roots", size(MAX_ROOTS)),
        (
            "empty_leaf",
            bytes(&MerkleHashOrchard::empty_leaf().to_bytes()),
        ),
        ("empty_roots_by_level", Json::List(empty_roots)),
        ("combine", Json::List(combine)),
        ("flows", flows),
        (
            "root_rotation",
            Json::Map(vec![
                (
                    "description",
                    text("66 payments on a fresh NPOOL003 pool; payment i (from 0) has commitments 2i+3 and 2i+4 as little-endian field elements and public value balance -1"),
                ),
                ("roots_dropped", Json::List(seen[..3].iter().map(|r| bytes(r)).collect())),
                ("oldest_root_kept", bytes(&seen[3])),
                ("state_after", state(&pool, false)),
            ]),
        ),
        ("transitions", transitions()),
        (
            "decode_bases",
            Json::Map(states.iter().map(|(name, data)| (*name, blob(data))).collect()),
        ),
        ("decode_cases", pool_cases(&states)),
    ])
}

// ---------------------------------------------------------------------------
// accounts.json

fn derived(seeds: &[&[u8]]) -> (Json, [u8; 32]) {
    let program = Pubkey::new_from_array(PROGRAM_ID);
    let (key, bump) = Pubkey::find_program_address(seeds, &program);
    (
        Json::Map(vec![
            (
                "seeds_hex",
                Json::List(seeds.iter().map(|seed| bytes(seed)).collect()),
            ),
            ("bump", number(bump)),
            ("address_hex", bytes(&key.to_bytes())),
            ("address", text(key)),
        ]),
        key.to_bytes(),
    )
}

fn accounts_file(bases: &BTreeMap<&'static str, Vec<u8>>) -> Json {
    let (pool, pool_key) = derived(&[b"native-payment-pool-v1"]);
    assert_eq!(pool_key, pool_address());
    let markers = PAYMENTS
        .iter()
        .flat_map(|name| {
            let at = layout(&bases[name][..8]);
            (0..ACTION_COUNT).map(move |index| (*name, index, at.actions + index * ACTION_BYTES))
        })
        .map(|(name, index, offset)| {
            let nullifier: [u8; 32] = bases[name][offset..offset + 32].try_into().unwrap();
            let (account, key) = derived(&[b"native-payment-spent-v1", &pool_key, &nullifier]);
            assert_eq!(key, nullifier_address(&nullifier));
            Json::Map(vec![
                ("payment", text(name)),
                ("action", size(index)),
                ("nullifier", bytes(&nullifier)),
                ("account", account),
            ])
        })
        .collect();
    Json::Map(vec![
        ("format", text("zolana-protocol-vectors/accounts/1")),
        ("program_id_hex", bytes(&PROGRAM_ID)),
        ("program_id", address(PROGRAM_ID)),
        ("system_program_id", address(SYSTEM_ID)),
        ("pool_seed", text("native-payment-pool-v1")),
        ("marker_seed", text("native-payment-spent-v1")),
        ("pool", pool),
        ("nullifier_markers", Json::List(markers)),
        (
            "scenario_keys",
            Json::Map(vec![
                ("sponsor", address(sponsor())),
                ("sponsor_hex", bytes(&sponsor())),
                ("relay", address(relay())),
                ("relay_hex", bytes(&relay())),
                ("recipient", address(recipient())),
                ("recipient_hex", bytes(&recipient())),
            ]),
        ),
    ])
}

// ---------------------------------------------------------------------------

fn vector_files(payments: &[Vec<u8>]) -> Vec<(&'static str, String)> {
    let bases: BTreeMap<&'static str, Vec<u8>> = PAYMENTS
        .iter()
        .copied()
        .zip(payments.iter().cloned())
        .collect();
    let key = Arc::new(VerifyingKey::build(bundle_version().circuit_version()));
    let verifier = PaymentVerifier::with_shared_key(NETWORK, key).unwrap();
    vec![
        ("accounts.json", accounts_file(&bases).file()),
        ("anchors.json", anchors_file().file()),
        ("envelope.json", envelope_file(&bases).file()),
        ("payments.json", payments_file(&bases, &verifier).file()),
        ("pool.json", pool_file(&bases, &verifier).file()),
        ("staging.json", staging_file(&bases).file()),
    ]
}

#[test]
fn committed_vectors_are_what_the_code_produces() {
    let files = vector_files(&load_payments());
    let write = std::env::var_os("WRITE_PROTOCOL_VECTORS").is_some();
    let mut stale = Vec::new();
    for (name, expected) in &files {
        let path = format!("{DIRECTORY}/{name}");
        if write {
            std::fs::write(&path, expected).unwrap();
        }
        if std::fs::read_to_string(&path).ok().as_ref() != Some(expected) {
            stale.push(*name);
        }
    }
    assert!(
        stale.is_empty(),
        "tests/vectors differs from the code in {stale:?}; see the header of this file"
    );
    // Nothing else lives in the directory: a vector no test reads proves nothing.
    let mut present: Vec<String> = std::fs::read_dir(DIRECTORY)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    present.sort();
    let mut known: Vec<String> = files.iter().map(|(name, _)| name.to_string()).collect();
    known.extend(["README.md".to_string(), "payloads".to_string()]);
    known.sort();
    assert_eq!(present, known);
}

#[test]
#[ignore = "builds four real proofs; see the header of this file"]
fn payments_are_reproduced_by_the_generator() {
    let write = std::env::var_os("PROTOCOL_VECTORS_PROVE").is_some();
    for (name, payload) in PAYMENTS.iter().zip(generate_payments()) {
        let expected = format!("{}\n", hex(&payload));
        if write {
            std::fs::create_dir_all(format!("{DIRECTORY}/payloads")).unwrap();
            std::fs::write(payload_path(name), &expected).unwrap();
        }
        assert!(
            std::fs::read_to_string(payload_path(name)).ok().as_ref() == Some(&expected),
            "{name}: the generator no longer builds the committed payment"
        );
    }
}
