//! Fuzz targets for every decoder of the protocol crate: payments, envelopes,
//! pool states, slot anchor histories and staged payload buffers.
//!
//! Each target takes bytes and checks three things. The decoder must not
//! panic. It must accept exactly the inputs that the reference statement of
//! the format in `support/reference.rs` accepts, which includes every size
//! bound. Whatever it accepts must encode back to the same bytes.
//!
//! Inputs are valid encodings with a few mutations, encodings assembled from
//! deliberately inconsistent parts, and unstructured bytes. See
//! `docs/protocol-fuzzing.md` for how to run the targets for longer and how to
//! record a finding.

mod support;

use incrementalmerkletree::{Hashable, Level};
use native_payments::{
    anchors::{AnchorHistory, ANCHOR_WINDOW_SLOTS, MAX_ANCHOR_HISTORY_BYTES, MAX_SLOT_ANCHORS},
    envelope::{self, ENVELOPE_HEADER_BYTES, MAX_ENVELOPE_BYTES, MAX_INNER_PAYMENT_BYTES},
    native_accounts::{Buffer, ACCOUNT_BYTES, HEADER as BUFFER_HEADER_BYTES},
    staging::{StagedPayload, MAX_CHUNK_BYTES, MAX_PAYLOAD_BYTES},
    state::{PoolState, MAX_COMMITMENTS, MAX_ROOTS, SLOT_STATE_BYTES, STATE_BYTES},
    verification::{
        authorization_digest, AuthorizationContext, VerifiedPayment, ACTION_COUNT,
        MAX_EXPIRY_WINDOW,
    },
    wire::{self, ACTION_BYTES},
    Error,
};
use orchard::{primitives::redpallas, tree::MerkleHashOrchard};
use support::{
    assert_input, layout, mutated,
    reference::{
        self, Entry, PoolParts, ANCHOR_ENTRY_BYTES, ANCHOR_HEADER_BYTES, FEE_TAG, PAYMENT_TAG,
        POOL_PREFIX_BYTES, WITHDRAWAL_TAG,
    },
    Budget, Field, Rng, NETWORK,
};

const OTHER_NETWORK: [u8; 32] = [43; 32];

fn number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
}

fn fail<T>(message: impl Into<String>) -> Result<T, String> {
    Err(message.into())
}

// ---------------------------------------------------------------------------
// Payments

fn point(rng: &mut Rng) -> [u8; 32] {
    loop {
        let mut bytes: [u8; 32] = rng.array();
        bytes[31] &= 0xbf;
        if bytes != [0; 32]
            && reference::is_point(bytes)
            && redpallas::VerificationKey::<redpallas::SpendAuth>::try_from(bytes).is_ok()
        {
            return bytes;
        }
    }
}

/// A payment that the format allows, assembled field by field. Its proof and
/// signatures are random: decoding does not verify them.
fn payment(rng: &mut Rng, tag: &[u8; 8]) -> Vec<u8> {
    let expires_at = if rng.chance(1, 4) {
        rng.pick(support::INTERESTING)
    } else {
        rng.next()
    };
    let positive = match rng.below(4) {
        0 => 1,
        1 => i64::MAX,
        2 => 1 + rng.below(1_000_000) as i64,
        _ => 1 + rng.below(i64::MAX as u64) as i64,
    };
    let balance = if tag == PAYMENT_TAG {
        match rng.below(6) {
            0 => 0,
            1 => i64::MIN,
            2 => -positive,
            _ => positive,
        }
    } else {
        positive
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(&NETWORK);
    bytes.extend_from_slice(&expires_at.to_le_bytes());
    bytes.extend_from_slice(&balance.to_le_bytes());
    bytes.extend_from_slice(&rng.field_element());
    if tag == FEE_TAG {
        bytes.extend_from_slice(&balance.to_le_bytes());
    }
    if tag == WITHDRAWAL_TAG {
        bytes.extend_from_slice(&rng.field_element());
    }
    bytes.extend_from_slice(&rng.field_element());
    bytes.push(reference::flag_byte());
    bytes.push(ACTION_COUNT as u8);
    for _ in 0..ACTION_COUNT {
        bytes.extend_from_slice(&rng.field_element());
        bytes.extend_from_slice(&point(rng));
        bytes.extend_from_slice(&rng.field_element());
        bytes.extend_from_slice(&point(rng));
        bytes.extend_from_slice(&rng.bytes(580 + 80));
        bytes.extend_from_slice(&point(rng));
        bytes.extend_from_slice(&rng.bytes(64));
    }
    bytes.extend_from_slice(&(reference::proof_bytes() as u32).to_le_bytes());
    bytes.extend_from_slice(&rng.bytes(reference::proof_bytes() + 64));
    bytes
}

fn payment_fields(bytes: &[u8]) -> Vec<Field> {
    let mut lengths = vec![8, 32, 8, 8, 32];
    match reference::tag_extra_bytes(bytes) {
        Some(0) | None => {}
        Some(extra) => lengths.push(extra),
    }
    lengths.extend([32, 1, 1]);
    for _ in 0..ACTION_COUNT {
        lengths.extend([32, 32, 32, 32, 580, 80, 32, 64]);
    }
    lengths.extend([4, reference::proof_bytes(), 64]);
    layout(0, &lengths)
}

fn check_payment(bytes: &[u8]) -> Result<(), String> {
    let allowed = reference::payment_is_valid(NETWORK, bytes);
    let decoded = match wire::decode(NETWORK, bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            if allowed {
                return fail(format!("refused a valid payment: {error}"));
            }
            // The size check comes first and never depends on the content.
            let exact = reference::payment_bytes(reference::tag_extra_bytes(bytes).unwrap_or(0));
            if bytes.len() != exact && error != Error::InvalidLength {
                return fail(format!(
                    "a payment of the wrong size was refused as {error}"
                ));
            }
            return Ok(());
        }
    };
    if !allowed {
        return fail("decoded a payment that the format does not allow");
    }
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return fail("decoded a payment larger than a staged payload");
    }
    let context = decoded.context;
    if context.validate().is_err()
        || context.expires_at != number(&bytes[40..48])
        || context.public_value_balance.to_le_bytes() != bytes[48..56]
        || context.sponsor != bytes[56..88]
        || *decoded.bundle.value_balance() != context.public_value_balance
        || decoded.bundle.actions().len() != ACTION_COUNT
    {
        return fail("the decoded context does not mirror the bytes");
    }
    match wire::encode(NETWORK, &context, &decoded.bundle) {
        Ok(again) if again == bytes => {}
        Ok(_) => return fail("a decoded payment encodes to different bytes"),
        Err(error) => return fail(format!("a decoded payment does not encode: {error}")),
    }
    if let Err(error) = authorization_digest(NETWORK, &decoded.bundle, &context) {
        return fail(format!(
            "a decoded payment has no authorization digest: {error}"
        ));
    }
    if wire::decode(OTHER_NETWORK, bytes).is_ok() || wire::decode([0; 32], bytes).is_ok() {
        return fail("decoded a payment for a different network");
    }
    Ok(())
}

fn payment_corpus(rng: &mut Rng) -> Vec<Vec<u8>> {
    [
        PAYMENT_TAG,
        WITHDRAWAL_TAG,
        FEE_TAG,
        PAYMENT_TAG,
        WITHDRAWAL_TAG,
        FEE_TAG,
    ]
    .into_iter()
    .map(|tag| payment(rng, tag))
    .collect()
}

#[test]
fn payment_decoder() {
    let mut budget = Budget::new("payment_decoder", 30_000);
    let corpus = payment_corpus(&mut Rng::new(1));
    for base in &corpus {
        assert_eq!(check_payment(base), Ok(()));
        assert!(wire::decode(NETWORK, base).is_ok());
    }
    let mut accepted = 0;
    while let Some(mut rng) = budget.next_case() {
        let base = &corpus[rng.index(corpus.len())];
        let donor = &corpus[rng.index(corpus.len())];
        let input = if rng.chance(1, 16) {
            let tag = rng.pick(&[PAYMENT_TAG, WITHDRAWAL_TAG, FEE_TAG]);
            payment(&mut rng, tag)
        } else {
            mutated(&mut rng, base, &payment_fields(base), donor)
        };
        assert_input("payment_decoder", base, &input, &check_payment);
        accepted += u64::from(wire::decode(NETWORK, &input).is_ok());
    }
    budget.finish_decoder(accepted);
    assert!(accepted > 0 && accepted < budget.cases_run());
}

/// The encoder refuses every context the decoder would refuse, and a context
/// it accepts comes back unchanged.
#[test]
fn payment_encoder_agrees_with_decoder() {
    let mut budget = Budget::new("payment_encoder", 5_000);
    let bundles: Vec<_> = payment_corpus(&mut Rng::new(2))
        .iter()
        .map(|bytes| wire::decode(NETWORK, bytes).unwrap().bundle)
        .collect();
    let mut accepted = 0;
    while let Some(mut rng) = budget.next_case() {
        let balance = match rng.below(5) {
            0 => 0,
            1 => -1 - rng.below(1_000) as i64,
            2 => rng.next() as i64,
            _ => 1 + rng.below(1_000) as i64,
        };
        let key = |rng: &mut Rng| {
            if rng.chance(1, 8) {
                [0; 32]
            } else {
                rng.array()
            }
        };
        let context = AuthorizationContext {
            expires_at: rng.next(),
            public_value_balance: balance,
            sponsor: key(&mut rng),
            withdrawal_recipient: rng.chance(1, 3).then(|| key(&mut rng)),
            shielded_fee: rng.chance(1, 3).then(|| match rng.below(4) {
                0 => 0,
                1 => rng.next(),
                _ => balance as u64,
            }),
        };
        let bundle_balance = if rng.chance(1, 8) {
            balance ^ 1
        } else {
            balance
        };
        let bundle = bundles[rng.index(bundles.len())]
            .clone()
            .try_map_value_balance::<_, Error, _>(|_| Ok(bundle_balance))
            .unwrap();
        let fee_is_valid = context.shielded_fee.is_none_or(|fee| {
            fee != 0
                && fee <= i64::MAX as u64
                && balance == fee as i64
                && context.withdrawal_recipient.is_none()
        });
        let recipient_is_valid = context
            .withdrawal_recipient
            .is_none_or(|recipient| recipient != [0; 32] && balance > 0);
        let allowed = fee_is_valid
            && recipient_is_valid
            && context.sponsor != [0; 32]
            && bundle_balance == balance;
        match wire::encode(NETWORK, &context, &bundle) {
            Ok(bytes) => {
                assert!(
                    allowed,
                    "encoded a context the format does not allow: {context:?}"
                );
                assert!(bytes.len() <= MAX_PAYLOAD_BYTES);
                assert!(reference::payment_is_valid(NETWORK, &bytes));
                assert_eq!(wire::decode(NETWORK, &bytes).unwrap().context, context);
                assert_eq!(check_payment(&bytes), Ok(()));
                assert!(wire::encode([0; 32], &context, &bundle).is_err());
                accepted += 1;
            }
            Err(error) => assert!(
                !allowed,
                "refused a valid context with {error}: {context:?}"
            ),
        }
    }
    budget.finish_decoder(accepted);
    assert!(accepted > 0 && accepted < budget.cases_run());
}

// ---------------------------------------------------------------------------
// Envelopes

fn check_envelope(current_slot: u64, bytes: &[u8]) -> Result<(), String> {
    let allowed = reference::envelope_is_valid(NETWORK, current_slot, bytes);
    let decoded = match envelope::decode(NETWORK, current_slot, bytes) {
        Ok(decoded) => decoded,
        Err(_) if !allowed => return Ok(()),
        Err(error) => return fail(format!("refused a valid envelope: {error}")),
    };
    if !allowed {
        return fail("decoded an envelope that the format does not allow");
    }
    let payload = &bytes[ENVELOPE_HEADER_BYTES..];
    if bytes.len() > MAX_ENVELOPE_BYTES || payload.len() > MAX_INNER_PAYMENT_BYTES {
        return fail("decoded an envelope larger than one frame");
    }
    let context = decoded.payment.context;
    if decoded.payment_id != reference::payload_digest(payload)
        || context.shielded_fee.is_none()
        || context.expires_at < current_slot
        || context.expires_at - current_slot > MAX_EXPIRY_WINDOW
    {
        return fail("the decoded envelope does not mirror the bytes");
    }
    if wire::encode(NETWORK, &context, &decoded.payment.bundle).as_deref() != Ok(payload) {
        return fail("the decoded inner payment encodes to different bytes");
    }
    if envelope::encode(NETWORK, payload).as_deref() != Ok(bytes) {
        return fail("a decoded envelope encodes to different bytes");
    }
    if envelope::decode(OTHER_NETWORK, current_slot, bytes).is_ok() {
        return fail("decoded an envelope for a different network");
    }
    Ok(())
}

fn envelope_fields(length: usize) -> Vec<Field> {
    let mut fields = layout(0, &[8, 2, 16, 32, 8, 32, 4]);
    if length > ENVELOPE_HEADER_BYTES {
        fields.push(Field {
            offset: ENVELOPE_HEADER_BYTES,
            len: length - ENVELOPE_HEADER_BYTES,
        });
    }
    fields
}

#[test]
fn envelope_decoder() {
    let mut budget = Budget::new("envelope_decoder", 15_000);
    let corpus = payment_corpus(&mut Rng::new(3));
    let mut accepted = 0;
    while let Some(mut rng) = budget.next_case() {
        // Mostly fee payments: the envelope carries nothing else.
        let mut payload = if rng.chance(3, 4) {
            corpus[2 + 3 * rng.index(2)].clone()
        } else {
            corpus[rng.index(corpus.len())].clone()
        };
        if rng.chance(1, 4) {
            payload = mutated(&mut rng, &payload, &payment_fields(&payload), &corpus[5]);
        }
        let inner_expiry = payload.get(40..48).map_or(0, number);
        let expires_at = if rng.chance(1, 12) {
            rng.next()
        } else {
            inner_expiry
        };
        let identity = if rng.chance(1, 12) {
            rng.array()
        } else {
            reference::payload_digest(&payload)
        };
        let length = if rng.chance(1, 12) {
            rng.pick(support::INTERESTING) as u32
        } else {
            payload.len() as u32
        };
        let base = reference::frame(NETWORK, expires_at, identity, length, &payload);
        let input = if rng.chance(1, 3) {
            mutated(&mut rng, &base, &envelope_fields(base.len()), &base)
        } else {
            base.clone()
        };
        let current_slot = match rng.below(8) {
            0 => expires_at,
            1 => expires_at.wrapping_add(1),
            2 => expires_at.wrapping_sub(MAX_EXPIRY_WINDOW),
            3 => expires_at.wrapping_sub(MAX_EXPIRY_WINDOW + 1),
            4 => rng.next(),
            _ => expires_at.saturating_sub(rng.below(MAX_EXPIRY_WINDOW + 1)),
        };
        assert_input("envelope_decoder", &base, &input, &|bytes| {
            check_envelope(current_slot, bytes)
        });
        accepted += u64::from(envelope::decode(NETWORK, current_slot, &input).is_ok());
        // The encoder frames exactly the fee payments and nothing else.
        let framed = envelope::encode(NETWORK, &payload);
        let frameable = payload.starts_with(FEE_TAG)
            && payload.len() <= MAX_INNER_PAYMENT_BYTES
            && reference::payment_is_valid(NETWORK, &payload);
        assert_eq!(framed.is_ok(), frameable);
        if let Ok(framed) = framed {
            let digest = reference::payload_digest(&payload);
            let length = payload.len() as u32;
            assert_eq!(
                framed,
                reference::frame(NETWORK, inner_expiry, digest, length, &payload)
            );
        }
    }
    budget.finish_decoder(accepted);
    assert!(accepted > 0 && accepted < budget.cases_run());
}

// ---------------------------------------------------------------------------
// Slot anchor histories

fn check_history(bytes: &[u8]) -> Result<(), String> {
    let allowed = reference::decode_history(NETWORK, bytes);
    let history = match AnchorHistory::decode(NETWORK, bytes) {
        Ok(history) => history,
        Err(_) if allowed.is_none() => return Ok(()),
        Err(error) => return fail(format!("refused a valid anchor history: {error}")),
    };
    let Some(entries) = allowed else {
        return fail("decoded an anchor history that the rules do not allow");
    };
    let decoded: Vec<Entry> = history
        .entries()
        .iter()
        .map(|entry| Entry {
            slot: entry.slot,
            note_count: entry.note_count,
            root: entry.root,
        })
        .collect();
    if decoded != entries || history.network() != NETWORK {
        return fail("the decoded anchor history does not mirror the bytes");
    }
    if bytes.len() > MAX_ANCHOR_HISTORY_BYTES || entries.len() > MAX_SLOT_ANCHORS {
        return fail("decoded an anchor history larger than its bound");
    }
    if history.encode() != bytes {
        return fail("a decoded anchor history encodes to different bytes");
    }
    if AnchorHistory::decode(OTHER_NETWORK, bytes).is_ok() {
        return fail("decoded an anchor history for a different network");
    }
    let newest = entries.last().map_or(0, |entry| entry.slot);
    for execution_slot in [
        newest,
        newest.saturating_add(1),
        newest.saturating_add(ANCHOR_WINDOW_SLOTS - 1),
        newest.saturating_add(ANCHOR_WINDOW_SLOTS),
        newest.saturating_sub(1),
        u64::MAX,
    ] {
        let roots = history.roots_at(execution_slot);
        if execution_slot < newest {
            if roots.is_ok() {
                return fail("served roots for a slot before the newest checkpoint");
            }
        } else if roots != Ok(reference::eligible_roots(&entries, execution_slot)) {
            return fail(format!("wrong eligible roots at slot {execution_slot}"));
        }
    }
    Ok(())
}

/// Entries that satisfy every rule, optionally with one rule broken.
fn history_entries(rng: &mut Rng, break_a_rule: bool) -> Vec<Entry> {
    let length = match rng.below(24) {
        0 => 0,
        1 => MAX_SLOT_ANCHORS,
        2 => MAX_SLOT_ANCHORS - 1,
        3 => 100 + rng.index(300),
        _ => 1 + rng.index(8),
    };
    let mut slot = match rng.below(4) {
        0 => 0,
        1 => u64::MAX - ANCHOR_WINDOW_SLOTS - rng.below(2),
        _ => rng.below(1 << 40),
    };
    let mut note_count = if rng.chance(1, 2) {
        0
    } else {
        2 * rng.below(1 << 20)
    };
    let mut root = if note_count == 0 {
        reference::empty_root()
    } else {
        rng.field_element()
    };
    // The whole list has to fit inside one window of slots.
    let spare = ANCHOR_WINDOW_SLOTS - 1 - (length as u64).saturating_sub(1);
    let widest_gap = spare / (length as u64).max(2);
    let mut entries = Vec::with_capacity(length);
    for index in 0..length {
        if index > 0 {
            slot += 1 + rng.below(widest_gap + 1);
            if rng.chance(1, 2) {
                note_count += 2 * (1 + rng.below(4));
                root = rng.field_element();
            }
        }
        entries.push(Entry {
            slot,
            note_count,
            root,
        });
    }
    if break_a_rule && !entries.is_empty() {
        let at = rng.index(entries.len());
        let other = entries[rng.index(entries.len())];
        let mut entry = entries[at];
        match rng.below(12) {
            0 => entry.slot = other.slot,
            1 => entry.note_count ^= 1,
            2 => entry.note_count = entry.note_count.wrapping_sub(2),
            3 => entry.note_count += 2,
            4 => entry.root = rng.field_element(),
            5 => entry.root = other.root,
            6 => entry.root = [0; 32],
            7 => entry.root = [0xff; 32],
            8 => entry.root = reference::empty_root(),
            9 => entry.note_count = 0,
            10 => entry.note_count = MAX_COMMITMENTS + 2 * rng.below(2),
            _ => entry.slot = entries[0].slot + ANCHOR_WINDOW_SLOTS - rng.below(2),
        }
        entries[at] = entry;
    }
    entries
}

fn history_fields(bytes: &[u8]) -> Vec<Field> {
    let entries = bytes.len().saturating_sub(ANCHOR_HEADER_BYTES) / ANCHOR_ENTRY_BYTES;
    let mut lengths = vec![8, 2, 16, 32, 2];
    for _ in 0..entries {
        lengths.extend([8, 8, 32]);
    }
    layout(0, &lengths)
}

#[test]
fn anchor_history_decoder() {
    let mut budget = Budget::new("anchor_history_decoder", 60_000);
    let mut accepted = 0;
    while let Some(mut rng) = budget.next_case() {
        let break_a_rule = rng.chance(1, 3);
        let entries = history_entries(&mut rng, break_a_rule);
        let base = reference::encode_history(NETWORK, &entries);
        let donor = reference::encode_history(NETWORK, &history_entries(&mut rng, false));
        let input = if rng.chance(1, 3) {
            mutated(&mut rng, &base, &history_fields(&base), &donor)
        } else {
            base.clone()
        };
        assert_input("anchor_history_decoder", &base, &input, &check_history);
        accepted += u64::from(AnchorHistory::decode(NETWORK, &input).is_ok());
    }
    budget.finish_decoder(accepted);
    assert!(accepted > 0 && accepted < budget.cases_run());
}

// ---------------------------------------------------------------------------
// Pool states

fn deposit(seed: u8) -> VerifiedPayment {
    VerifiedPayment {
        nullifiers: [[seed; 32], [seed.wrapping_add(1); 32]],
        commitments: [[seed & 0x3f; 32], [seed.wrapping_add(1) & 0x3f; 32]],
        public_value_balance: -1,
    }
}

fn check_pool_state(bytes: &[u8]) -> Result<(), String> {
    let allowed = reference::pool_state_is_valid(bytes);
    let state = match PoolState::decode(bytes) {
        Ok(state) => state,
        Err(_) if !allowed => return Ok(()),
        Err(error) => return fail(format!("refused a valid pool state: {error}")),
    };
    if !allowed {
        return fail("decoded a pool state that the format does not allow");
    }
    let slot_anchored = state.uses_slot_anchors();
    let size = if slot_anchored {
        SLOT_STATE_BYTES
    } else {
        STATE_BYTES
    };
    if bytes.len() != size || state.encode() != bytes {
        return fail("a decoded pool state encodes to different bytes");
    }
    let count = state.note_count();
    if state.network != bytes[8..40]
        || state.network == [0; 32]
        || state.rent_floor != number(&bytes[40..48])
        || state.backing != number(&bytes[48..56])
        || state.backing > i64::MAX as u64
        || count != number(&bytes[56..64])
        || count > MAX_COMMITMENTS
        || !count.is_multiple_of(2)
    {
        return fail("the decoded pool state does not mirror the bytes");
    }
    let root = state.root();
    if slot_anchored {
        let history = state.slot_anchors().expect("slot anchored");
        let newest = history.entries().last();
        if !state.roots().is_empty()
            || history.network() != state.network
            || newest.is_some_and(|entry| entry.note_count > count)
            || newest.is_some_and(|entry| entry.note_count == count && entry.root != root)
        {
            return fail("the decoded checkpoints do not belong to the decoded tree");
        }
        let slot = newest.map_or(0, |entry| entry.slot.saturating_add(1));
        let entries: Vec<Entry> = history
            .entries()
            .iter()
            .map(|entry| Entry {
                slot: entry.slot,
                note_count: entry.note_count,
                root: entry.root,
            })
            .collect();
        if newest.is_none_or(|entry| entry.slot <= slot)
            && state.accepted_roots(slot) != Ok(reference::eligible_roots(&entries, slot))
        {
            return fail("the pool serves roots other than those of completed slots");
        }
        // Every decoded state can complete a slot: the slot of its newest
        // checkpoint again, and the one after it. Completing a slot changes
        // nothing but the checkpoints.
        for slot in [newest.map_or(0, |entry| entry.slot), slot] {
            let mut completed = state.clone();
            if let Err(error) = completed.complete_slot(slot) {
                return fail(format!(
                    "a decoded state cannot complete slot {slot}: {error}"
                ));
            }
            let again = completed.encode();
            if completed.root() != root
                || completed.note_count() != count
                || completed.backing != state.backing
                || PoolState::decode(&again).map(|state| state.encode()) != Ok(again)
            {
                return fail("the state after a completed slot is wrong or does not decode");
            }
        }
    } else {
        let roots = state.roots();
        if roots.is_empty()
            || roots.len() > MAX_ROOTS
            || !roots.contains(&root)
            || state.accepted_roots(0) != Ok(roots)
            || state.slot_anchors().is_some()
            || state.clone().complete_slot(0) != Err(Error::UnsupportedVersion)
        {
            return fail("the decoded roots do not belong to the decoded tree");
        }
    }
    // A note equal to the empty leaf is refused whatever the state.
    let mut hollow = deposit(1);
    hollow.commitments[usize::from(bytes[40] & 1)] = reference::empty_leaf();
    if state.with_payment(&hollow).err() != Some(Error::InvalidEncoding)
        && !(count > MAX_COMMITMENTS - 2 || state.backing == i64::MAX as u64)
    {
        return fail("a decoded state accepted a note equal to the empty leaf");
    }
    // A deposit of one unit applies, or is refused because the tree or the
    // backing is full. Either way the decoded state itself is untouched.
    match state.with_payment(&deposit(1)) {
        Ok(next) => {
            let again = next.encode();
            if next.note_count() != count + 2
                || next.backing != state.backing + 1
                || PoolState::decode(&again)
                    .map(|state| state.encode())
                    .as_ref()
                    != Ok(&again)
            {
                return fail("a deposit into a decoded state gave a wrong state");
            }
            // The slot the deposit executed in records the tree it leaves,
            // unless a stored checkpoint already claims that root for fewer
            // notes: decoding cannot tell that such a root is not the root of
            // the tree it stands for. The transition never writes that state.
            if let Some(history) = state.slot_anchors() {
                let entries: Vec<Entry> = history
                    .entries()
                    .iter()
                    .map(|entry| Entry {
                        slot: entry.slot,
                        note_count: entry.note_count,
                        root: entry.root,
                    })
                    .collect();
                let slot = entries.last().map_or(0, |entry| entry.slot);
                let expected =
                    reference::tree_can_be_recorded(&entries, next.note_count(), next.root());
                let mut sealed = next.clone();
                if sealed.complete_slot(slot).is_ok() != expected {
                    return fail("slot completion after a deposit disagrees with the rules");
                }
                if !expected && sealed.encode() != again {
                    return fail("a refused slot completion changed the state");
                }
            }
        }
        Err(Error::CapacityExceeded)
            if count > MAX_COMMITMENTS - 2 || state.backing == i64::MAX as u64 => {}
        Err(error) => return fail(format!("a deposit into a decoded state failed: {error}")),
    }
    if state.encode() != bytes {
        return fail("applying a payment changed the state it was applied to");
    }
    Ok(())
}

/// A pool state assembled from parts: any note count, with a frontier and a
/// newest root that fit it.
fn crafted_pool_state(rng: &mut Rng, slot_anchored: bool) -> Vec<u8> {
    let mut count = match rng.below(8) {
        0 => 0,
        1 => MAX_COMMITMENTS,
        2 => MAX_COMMITMENTS - 2 * (1 + rng.below(3)),
        3 => 2 * rng.below(1 << 31),
        _ => 2 * (1 + rng.below(40)),
    };
    // Counts no pool can have, with a frontier and a root that fit them.
    match rng.below(8) {
        0 => count |= 1,
        1 => count = MAX_COMMITMENTS + 1 + rng.below(4),
        _ => {}
    }
    let mut parts = PoolParts {
        network: NETWORK,
        rent_floor: rng.next(),
        backing: match rng.below(4) {
            0 => 0,
            1 => i64::MAX as u64 - rng.below(2),
            _ => rng.below(i64::MAX as u64),
        },
        count,
        frontier: [[0; 32]; 32],
    };
    // Mostly arbitrary subtrees; sometimes subtrees of empty leaves, whose
    // tree keeps the root of the empty tree whatever its note count. The
    // legacy format decodes such a tree; the slot-anchored format refuses it.
    let empty_leaves = rng.chance(1, 8);
    for level in 0..32 {
        if (count >> level) & 1 == 1 {
            parts.frontier[level] = if empty_leaves {
                MerkleHashOrchard::empty_root(Level::from(level as u8)).to_bytes()
            } else {
                rng.field_element()
            };
        }
    }
    let root = reference::tree_root(count, &parts.frontier).expect("valid frontier");
    if !slot_anchored {
        let mut roots: Vec<[u8; 32]> = (0..rng.index(MAX_ROOTS))
            .map(|_| rng.field_element())
            .collect();
        roots.push(root);
        return parts.encode_with_roots(&roots);
    }
    // Older checkpoints of smaller trees, then perhaps one of this tree.
    let mut entries = Vec::new();
    let mut slot = rng.below(1 << 40);
    let older = rng.below(5).min(count / 2);
    let present_tree = rng.below(8);
    for index in 0..older {
        entries.push(Entry {
            slot,
            note_count: 2 * index,
            root: if index == 0 {
                reference::empty_root()
            } else {
                rng.field_element()
            },
        });
        slot += 1 + rng.below(100);
    }
    match present_tree {
        // A checkpoint of this very tree.
        0..=3 => entries.push(Entry {
            slot,
            note_count: count,
            root,
        }),
        // An older checkpoint that claims the root of this tree: the newest
        // one, or one before it when there is one. The decoder refuses the
        // state, because one root would stand for two note counts.
        4 | 5 if entries.len() > 1 => {
            let at = if entries.len() > 2 && rng.chance(2, 3) {
                1 + rng.index(entries.len() - 2)
            } else {
                entries.len() - 1
            };
            entries[at].root = root;
        }
        _ => {}
    }
    parts.encode_with_history(&reference::encode_history(NETWORK, &entries))
}

/// States reached by the transition itself, at different points of its life.
fn reached_pool_states(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut states = Vec::new();
    let mut legacy = PoolState::new(NETWORK, 1_000).unwrap();
    states.push(legacy.encode());
    for step in 0..70u8 {
        legacy = legacy.with_payment(&deposit(step)).unwrap();
        if [0, 2, 62, 63, 69].contains(&step) {
            states.push(legacy.encode());
        }
    }
    let mut anchored = PoolState::new_slot_anchored(NETWORK, 1_000).unwrap();
    states.push(anchored.encode());
    let mut slot = rng.below(1_000);
    for step in 0..MAX_SLOT_ANCHORS as u64 + 8 {
        if step % 97 == 3 {
            anchored = anchored.with_payment(&deposit(step as u8)).unwrap();
        }
        anchored.complete_slot(slot).unwrap();
        if [0, 4, 5, 300, MAX_SLOT_ANCHORS as u64 + 7].contains(&step) {
            states.push(anchored.encode());
        }
        slot += 1;
    }
    // A payment since the newest checkpoint leaves the tree ahead of it.
    states.push(anchored.with_payment(&deposit(9)).unwrap().encode());
    states
}

fn pool_state_fields(bytes: &[u8]) -> Vec<Field> {
    let mut lengths = vec![8, 32, 8, 8, 8];
    if !bytes.starts_with(b"NPOOL004") {
        lengths.push(1);
        lengths.extend([32; 32 + MAX_ROOTS]);
        return layout(0, &lengths);
    }
    lengths.extend([32; 32]);
    lengths.extend([4, 8, 2, 16, 32, 2]);
    let history_start = POOL_PREFIX_BYTES + 32 * 32 + 4;
    let entries = bytes
        .get(history_start - 4..history_start)
        .map_or(0, |length| {
            u32::from_le_bytes(length.try_into().unwrap()) as usize
        })
        .saturating_sub(ANCHOR_HEADER_BYTES)
        / ANCHOR_ENTRY_BYTES;
    for _ in 0..entries.min(MAX_SLOT_ANCHORS) {
        lengths.extend([8, 8, 32]);
    }
    let mut fields = layout(0, &lengths);
    // The first and the last byte of the zero padding, when there is any.
    let used: usize = lengths.iter().sum();
    if used < bytes.len() {
        fields.push(Field {
            offset: used,
            len: 1,
        });
        fields.push(Field {
            offset: bytes.len() - 1,
            len: 1,
        });
    }
    fields
}

#[test]
fn pool_state_decoder() {
    const CASES: u64 = 1_200;
    let mut budget = Budget::new("pool_state_decoder", CASES);
    let reached = reached_pool_states(&mut Rng::new(4));
    for state in &reached {
        assert_eq!(check_pool_state(state), Ok(()));
        assert!(PoolState::decode(state).is_ok());
    }
    let mut accepted = 0;
    // Inputs that keep every rule of the format but one: no completed slot
    // could record their tree.
    let mut unrecordable = 0;
    while let Some(mut rng) = budget.next_case() {
        let base = if rng.chance(1, 2) {
            reached[rng.index(reached.len())].clone()
        } else {
            let slot_anchored = rng.chance(1, 2);
            crafted_pool_state(&mut rng, slot_anchored)
        };
        let donor = &reached[rng.index(reached.len())];
        let input = if rng.chance(3, 4) {
            mutated(&mut rng, &base, &pool_state_fields(&base), donor)
        } else {
            base.clone()
        };
        assert_input("pool_state_decoder", &base, &input, &check_pool_state);
        accepted += u64::from(PoolState::decode(&input).is_ok());
        unrecordable +=
            u64::from(reference::slot_anchored_tree_is_recordable(&input) == Some(false));
    }
    budget.finish(format_args!(
        "{accepted} accepted, {} refused, {unrecordable} of them only because no slot could \
         record the tree",
        budget.cases_run() - accepted
    ));
    assert!(accepted > 0 && accepted < budget.cases_run());
    if budget.cases_run() >= CASES {
        assert!(unrecordable > 0, "no input broke the recording rule alone");
    }
}

// ---------------------------------------------------------------------------
// Staged payloads

fn buffer_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() != ACCOUNT_BYTES
        || &bytes[..8] != b"NBUF0001"
        || !matches!(bytes[88], 0 | 1 | 3)
        || bytes[89..BUFFER_HEADER_BYTES] != [0; 7]
    {
        return false;
    }
    let length = u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize;
    let received = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
    (1..=MAX_PAYLOAD_BYTES).contains(&length)
        && received <= length
        && (bytes[88] == 0 || received == length)
        && bytes[BUFFER_HEADER_BYTES + received..]
            .iter()
            .all(|byte| *byte == 0)
}

fn check_buffer(bytes: &[u8]) -> Result<(), String> {
    let allowed = buffer_is_valid(bytes);
    let mut buffer = match Buffer::decode(bytes) {
        Ok(buffer) => buffer,
        Err(_) if !allowed => return Ok(()),
        Err(error) => return fail(format!("refused a valid staging buffer: {error}")),
    };
    if !allowed {
        return fail("decoded a staging buffer that the format does not allow");
    }
    if buffer.bytes() != bytes
        || buffer.sponsor() != bytes[8..40]
        || buffer.expiry() != number(&bytes[80..88])
    {
        return fail("the decoded staging buffer does not mirror the bytes");
    }
    let length = u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize;
    let sealed_payload = &bytes[BUFFER_HEADER_BYTES..BUFFER_HEADER_BYTES + length];
    match buffer.payload() {
        Ok(payload) if bytes[88] == 1 && payload == sealed_payload => {}
        Err(_) if bytes[88] != 1 => {}
        _ => return fail("the payload is readable in exactly the sealed state"),
    }
    // Further instructions may be refused, but leave a decodable account.
    let _ = buffer.write(u32::from_le_bytes(bytes[44..48].try_into().unwrap()), &[7]);
    let _ = buffer.seal();
    let _ = buffer.consume();
    if !buffer_is_valid(buffer.bytes()) || Buffer::decode(buffer.bytes()).is_err() {
        return fail("instructions left a staging buffer that does not decode");
    }
    Ok(())
}

/// Drives the in-memory assembler and the account buffer with the same
/// chunks. They must accept and refuse the same writes and hold the same
/// bytes, and the account must stay decodable after every step.
fn staging_run(rng: &mut Rng) -> (Vec<Vec<u8>>, bool) {
    let length = match rng.below(8) {
        0 => 0,
        1 => MAX_PAYLOAD_BYTES + 1,
        2 => MAX_PAYLOAD_BYTES,
        3 => 1,
        4 => 1 + rng.index(MAX_PAYLOAD_BYTES),
        _ => 1 + rng.index(3 * MAX_CHUNK_BYTES),
    };
    let payload = rng.bytes(length);
    let honest = rng.chance(7, 8);
    let digest = if honest {
        reference::payload_digest(&payload)
    } else {
        rng.array()
    };
    let sponsor: [u8; 32] = rng.array();
    let expiry = rng.next();
    let staged = StagedPayload::new(length, digest);
    let buffer = Buffer::initialize(&[0; ACCOUNT_BYTES], sponsor, length as u32, digest, expiry);
    let allowed = (1..=MAX_PAYLOAD_BYTES).contains(&length);
    assert_eq!(staged.is_ok(), allowed);
    assert_eq!(buffer.is_ok(), allowed);
    let (Ok(mut staged), Ok(mut buffer)) = (staged, buffer) else {
        return (Vec::new(), false);
    };
    let mut snapshots = vec![buffer.bytes().to_vec()];
    let mut written: Vec<u8> = Vec::new();
    let mut sealed = false;
    for _ in 0..4 + rng.index(40) {
        if rng.chance(1, 6) {
            let complete = !sealed && written.len() == length;
            let sealable = complete && reference::payload_digest(&written) == digest;
            let expected = if sealed {
                Err(Error::SealedPayload)
            } else if !complete {
                Err(Error::IncompletePayload)
            } else if !sealable {
                Err(Error::DigestMismatch)
            } else {
                Ok(())
            };
            assert_eq!(staged.seal(), expected);
            assert_eq!(buffer.seal().is_ok(), sealable);
            sealed |= sealable;
        } else {
            let remaining = length - written.len();
            let offset = match rng.below(10) {
                0 => written.len() + 1,
                1 => written.len().saturating_sub(1),
                2 => rng.index(MAX_PAYLOAD_BYTES + 2),
                _ => written.len(),
            };
            let size = match rng.below(10) {
                0 => 0,
                1 => MAX_CHUNK_BYTES + 1,
                2 => remaining + 1,
                3 => remaining,
                4 => MAX_CHUNK_BYTES,
                _ => 1 + rng.index(MAX_CHUNK_BYTES),
            };
            let chunk = if honest && offset == written.len() && offset + size <= length {
                payload[offset..offset + size].to_vec()
            } else {
                rng.bytes(size)
            };
            let fits = !sealed
                && offset == written.len()
                && (1..=MAX_CHUNK_BYTES).contains(&size)
                && size <= remaining;
            assert_eq!(staged.append(offset, &chunk).is_ok(), fits);
            assert_eq!(buffer.write(offset as u32, &chunk).is_ok(), fits);
            if fits {
                written.extend_from_slice(&chunk);
            }
        }
        assert!(written.len() <= length);
        assert_eq!(buffer.payload().ok(), sealed.then_some(written.as_slice()));
        assert_eq!(check_buffer(buffer.bytes()), Ok(()));
        snapshots.push(buffer.bytes().to_vec());
    }
    assert_eq!(staged.into_payload().ok(), sealed.then_some(written));
    if sealed {
        buffer.consume().unwrap();
        assert!(buffer.payload().is_err() && buffer.consume().is_err());
        snapshots.push(buffer.bytes().to_vec());
    }
    (snapshots, sealed)
}

#[test]
fn staged_payload_and_buffer_decoder() {
    let mut budget = Budget::new("staging_buffer_decoder", 4_000);
    let fields = layout(0, &[8, 32, 4, 4, 32, 8, 1, 7, 1, 767, 768]);
    let mut accepted = 0;
    let mut sealed_runs = 0;
    while let Some(mut rng) = budget.next_case() {
        let (snapshots, sealed) = staging_run(&mut rng);
        sealed_runs += u64::from(sealed);
        if snapshots.is_empty() {
            continue;
        }
        for _ in 0..4 {
            let base = &snapshots[rng.index(snapshots.len())];
            let donor = &snapshots[rng.index(snapshots.len())];
            let mut all = fields.clone();
            let received = u32::from_le_bytes(base[44..48].try_into().unwrap()) as usize;
            all.push(Field {
                offset: BUFFER_HEADER_BYTES + received.saturating_sub(1),
                len: 2,
            });
            let input = mutated(&mut rng, base, &all, donor);
            assert_input("staging_buffer_decoder", base, &input, &check_buffer);
            accepted += u64::from(Buffer::decode(&input).is_ok());
        }
    }
    budget.finish(format_args!(
        "{accepted} mutated buffers accepted, {sealed_runs} payloads sealed"
    ));
    assert!(accepted > 0 && sealed_runs > 0);
}

// ---------------------------------------------------------------------------
// Unstructured input

/// Bytes with no structure beyond, mostly, a known tag and the exact size of
/// some encoding. Every decoder sees every input.
#[test]
fn unstructured_bytes_reach_no_panic() {
    let mut budget = Budget::new("unstructured_bytes", 200_000);
    let shapes: [(&[u8], usize); 12] = [
        (PAYMENT_TAG, reference::payment_bytes(0)),
        (WITHDRAWAL_TAG, reference::payment_bytes(32)),
        (FEE_TAG, reference::payment_bytes(8)),
        (
            b"ZOLNPAY1",
            ENVELOPE_HEADER_BYTES + reference::payment_bytes(8),
        ),
        (b"ZOLNPAY1", MAX_ENVELOPE_BYTES + 1),
        (b"ZOLANCH1", ANCHOR_HEADER_BYTES),
        (b"ZOLANCH1", ANCHOR_HEADER_BYTES + ANCHOR_ENTRY_BYTES),
        (b"ZOLANCH1", MAX_ANCHOR_HISTORY_BYTES),
        (b"NPOOL003", STATE_BYTES),
        (b"NPOOL004", SLOT_STATE_BYTES),
        (b"NBUF0001", ACCOUNT_BYTES),
        (b"", ACTION_BYTES),
    ];
    let mut accepted = 0;
    while let Some(mut rng) = budget.next_case() {
        let (mut tag, mut size) = rng.pick(&shapes);
        match rng.below(8) {
            0 => size = rng.index(200),
            1 => size = size + rng.index(3) - 1,
            2 => tag = rng.pick(&shapes).0,
            _ => {}
        }
        let mut input = match rng.below(3) {
            0 => vec![0; size],
            1 => vec![0xff; size],
            _ => rng.bytes(size),
        };
        if input.len() >= tag.len() {
            input[..tag.len()].copy_from_slice(tag);
        }
        let current_slot = rng.next();
        let check = |bytes: &[u8]| {
            check_payment(bytes)?;
            check_envelope(current_slot, bytes)?;
            check_history(bytes)?;
            check_pool_state(bytes)?;
            check_buffer(bytes)
        };
        assert_input("unstructured_bytes", &input, &input, &check);
        accepted += u64::from(
            wire::decode(NETWORK, &input).is_ok()
                || envelope::decode(NETWORK, current_slot, &input).is_ok()
                || AnchorHistory::decode(NETWORK, &input).is_ok()
                || PoolState::decode(&input).is_ok()
                || Buffer::decode(&input).is_ok(),
        );
    }
    budget.finish_decoder(accepted);
}
