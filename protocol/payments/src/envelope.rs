//! Bounded framing for a complete shielded-fee payment, without staged chunks.
//!
//! This is an opt-in execution candidate, not an enabled network transport. The
//! fixed framing domain does not introduce a new signature authorization domain:
//! the inner V3 signatures already bind the network, expiry, fee and payee. Native
//! and staged ingress MUST share the same durable nullifier checks and atomic
//! accounting. A successfully decoded envelope is NOT a verified payment.

use crate::{
    staging::payload_digest,
    verification::MAX_EXPIRY_WINDOW,
    wire::{self, DecodedPayment},
    Error,
};

const MAGIC: &[u8; 8] = b"ZOLNPAY1";
pub const ENVELOPE_VERSION: u16 = 1;
pub const ENVELOPE_DOMAIN: &[u8; 16] = b"ZolanaNativePay!";
pub const ENVELOPE_HEADER_BYTES: usize = 8 + 2 + 16 + 32 + 8 + 32 + 4;
/// Includes the header, so one frame never exceeds the native 16 KiB budget.
pub const MAX_ENVELOPE_BYTES: usize = 16_384;
pub const MAX_INNER_PAYMENT_BYTES: usize = MAX_ENVELOPE_BYTES - ENVELOPE_HEADER_BYTES;

#[derive(Debug)]
pub struct DecodedEnvelope {
    /// Exact canonical inner V3 payload identity, also used by staged recovery.
    /// This is not an execution receipt or proof that the payment was accepted.
    pub payment_id: [u8; 32],
    pub payment: DecodedPayment,
}

/// Wraps an existing signed V3 payment unchanged. Does not verify its proof or
/// signatures; callers must use the existing PaymentVerifier before execution.
pub fn encode(network: [u8; 32], payload: &[u8]) -> Result<Vec<u8>, Error> {
    validate_length(payload.len())?;
    let payment = canonical_payment(network, payload)?;
    let mut bytes = Vec::with_capacity(ENVELOPE_HEADER_BYTES + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    bytes.extend_from_slice(ENVELOPE_DOMAIN);
    bytes.extend_from_slice(&network);
    bytes.extend_from_slice(&payment.context.expires_at.to_le_bytes());
    bytes.extend_from_slice(&payload_digest(payload));
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Decodes and checks bounded framing and the signed expiry. `current_slot` must
/// come from the executing bank, never from an RPC request or wall clock. This
/// intentionally returns DecodedPayment rather than VerifiedPayment: the caller
/// must still verify authorization/proof against authenticated chain state, then
/// atomically check durable nullifiers and apply all accounting effects.
pub fn decode(
    network: [u8; 32],
    current_slot: u64,
    bytes: &[u8],
) -> Result<DecodedEnvelope, Error> {
    if bytes.len() <= ENVELOPE_HEADER_BYTES || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::InvalidLength);
    }
    let mut input = bytes;
    if &take::<8>(&mut input)? != MAGIC || u16::from_le_bytes(take(&mut input)?) != ENVELOPE_VERSION
    {
        return Err(Error::UnsupportedVersion);
    }
    if &take::<16>(&mut input)? != ENVELOPE_DOMAIN {
        return Err(Error::InvalidContext);
    }
    if network == [0; 32] || take::<32>(&mut input)? != network {
        return Err(Error::WrongNetwork);
    }
    let expires_at = u64::from_le_bytes(take(&mut input)?);
    let payment_id = take::<32>(&mut input)?;
    let payload_length = u32::from_le_bytes(take(&mut input)?) as usize;
    validate_length(payload_length)?;
    if input.len() != payload_length {
        return Err(Error::InvalidLength);
    }
    if payload_digest(input) != payment_id {
        return Err(Error::DigestMismatch);
    }
    let payment = canonical_payment(network, input)?;
    if payment.context.expires_at != expires_at {
        return Err(Error::InvalidContext);
    }
    if expires_at < current_slot {
        return Err(Error::Expired);
    }
    if expires_at - current_slot > MAX_EXPIRY_WINDOW {
        return Err(Error::InvalidContext);
    }
    Ok(DecodedEnvelope {
        payment_id,
        payment,
    })
}

fn validate_length(length: usize) -> Result<(), Error> {
    if length == 0 || length > MAX_INNER_PAYMENT_BYTES {
        Err(Error::InvalidLength)
    } else {
        Ok(())
    }
}

fn canonical_payment(network: [u8; 32], payload: &[u8]) -> Result<DecodedPayment, Error> {
    let payment = wire::decode(network, payload)?;
    // Native full-payload execution is limited to the already reviewed V3 fee
    // semantics. Deposits and recipient-bound withdrawals keep existing ingress.
    if payment.context.shielded_fee.is_none() {
        return Err(Error::UnsupportedVersion);
    }
    if wire::encode(network, &payment.context, &payment.bundle)? != payload {
        return Err(Error::InvalidEncoding);
    }
    Ok(payment)
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], Error> {
    let (head, tail) = input.split_at_checked(N).ok_or(Error::InvalidLength)?;
    *input = tail;
    head.try_into().map_err(|_| Error::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::{
        authorization_digest, bundle_version, AuthorizationContext, ACTION_COUNT,
    };
    use orchard::{
        builder::{Builder, BundleType},
        bundle::Authorized,
        keys::{FullViewingKey, Scope, SpendingKey},
        primitives::redpallas,
        tree::Anchor,
        value::NoteValue,
        Bundle, Proof,
    };

    const NETWORK: [u8; 32] = [42; 32];
    const EXPIRY_OFFSET: usize = 8 + 2 + 16 + 32;
    const ID_OFFSET: usize = EXPIRY_OFFSET + 8;
    const LENGTH_OFFSET: usize = ID_OFFSET + 32;

    // Real curve/encoding values, deliberately invalid proof/signatures. Framing
    // cannot authenticate them; real-proof execution is tested at the adapter.
    fn unverified_fixture() -> Vec<u8> {
        let version = bundle_version();
        let key = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(
                None,
                FullViewingKey::from(&key).address_at(0u32, Scope::External),
                NoteValue::from_raw(1),
                [0; 512],
            )
            .unwrap();
        let (bundle, _) = builder.build::<i64>(&mut rand::rng()).unwrap().unwrap();
        let bundle: Bundle<Authorized, i64> = bundle.map_authorization(
            &mut (),
            |_, _, _| redpallas::Signature::from([0; 64]),
            |_, _| {
                Authorized::from_parts(
                    Proof::new(vec![0; Proof::expected_proof_size(ACTION_COUNT)]),
                    redpallas::Signature::from([0; 64]),
                )
            },
        );
        let bundle = bundle
            .try_map_value_balance::<_, Error, _>(|_| Ok(7))
            .unwrap();
        wire::encode(
            NETWORK,
            &AuthorizationContext {
                expires_at: 100,
                public_value_balance: 7,
                sponsor: [3; 32],
                withdrawal_recipient: None,
                shielded_fee: Some(7),
            },
            &bundle,
        )
        .unwrap()
    }

    fn error(bytes: &[u8]) -> Error {
        decode(NETWORK, 50, bytes).err().unwrap()
    }

    #[test]
    fn one_frame_keeps_v3_bytes_and_shared_recovery_identity() {
        let payload = unverified_fixture();
        let bytes = encode(NETWORK, &payload).unwrap();
        assert_eq!(payload.len(), 9230);
        assert_eq!(bytes.len(), payload.len() + ENVELOPE_HEADER_BYTES);
        assert!(bytes.len() < MAX_ENVELOPE_BYTES);
        assert_eq!(&bytes[ENVELOPE_HEADER_BYTES..], payload);
        let decoded = decode(NETWORK, 50, &bytes).unwrap();
        assert_eq!(decoded.payment_id, payload_digest(&payload));
        assert_eq!(
            wire::encode(NETWORK, &decoded.payment.context, &decoded.payment.bundle).unwrap(),
            payload
        );
        assert_eq!(encode(NETWORK, &payload).unwrap(), bytes);
        assert_eq!(
            decode(NETWORK, 100, &bytes).unwrap().payment_id,
            decoded.payment_id
        );
        // Decoding retains the deliberately invalid authorization; it never
        // upgrades an unverified packet into proof of accepted execution.
        assert_eq!(
            <[u8; 64]>::from(decoded.payment.bundle.authorization().binding_signature()),
            [0; 64]
        );
        let digest =
            authorization_digest(NETWORK, &decoded.payment.bundle, &decoded.payment.context)
                .unwrap();
        assert!(decoded
            .payment
            .bundle
            .actions()
            .iter()
            .all(|action| action.rk().verify(&digest, action.authorization()).is_err()));
    }

    #[test]
    fn rejects_versions_domain_network_and_signed_expiry_mismatches() {
        let bytes = encode(NETWORK, &unverified_fixture()).unwrap();
        for position in [0, 8, 9] {
            let mut changed = bytes.clone();
            changed[position] ^= 1;
            assert_eq!(error(&changed), Error::UnsupportedVersion);
        }
        let mut changed = bytes.clone();
        changed[10] ^= 1;
        assert_eq!(error(&changed), Error::InvalidContext);
        let mut changed = bytes.clone();
        changed[26] ^= 1;
        assert_eq!(error(&changed), Error::WrongNetwork);
        assert_eq!(decode([1; 32], 50, &bytes).err(), Some(Error::WrongNetwork));
        assert_eq!(decode([0; 32], 50, &bytes).err(), Some(Error::WrongNetwork));
        let mut changed = bytes.clone();
        changed[EXPIRY_OFFSET..ID_OFFSET].copy_from_slice(&101u64.to_le_bytes());
        assert_eq!(error(&changed), Error::InvalidContext);
        assert_eq!(decode(NETWORK, 101, &bytes).err(), Some(Error::Expired));

        let mut inner = unverified_fixture();
        inner[40..48].copy_from_slice(&(MAX_EXPIRY_WINDOW + 1).to_le_bytes());
        let future = encode(NETWORK, &inner).unwrap();
        assert_eq!(
            decode(NETWORK, 0, &future).err(),
            Some(Error::InvalidContext)
        );
        assert!(decode(NETWORK, 1, &future).is_ok());
    }

    #[test]
    fn rejects_all_truncated_prefixes_trailing_bytes_and_unbounded_lengths() {
        let payload = unverified_fixture();
        let bytes = encode(NETWORK, &payload).unwrap();
        for length in 0..bytes.len() {
            assert!(decode(NETWORK, 50, &bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(error(&trailing), Error::InvalidLength);
        for claimed in [0, 1, u32::MAX] {
            let mut changed = bytes.clone();
            changed[LENGTH_OFFSET..ENVELOPE_HEADER_BYTES].copy_from_slice(&claimed.to_le_bytes());
            assert_eq!(error(&changed), Error::InvalidLength);
        }
        for length in [MAX_ENVELOPE_BYTES, MAX_ENVELOPE_BYTES + 1] {
            let mut changed = bytes.clone();
            changed.resize(length, 0);
            assert_eq!(error(&changed), Error::InvalidLength);
        }
        assert_eq!(encode(NETWORK, &[]).err(), Some(Error::InvalidLength));
        assert_eq!(
            encode(NETWORK, &vec![0; MAX_INNER_PAYMENT_BYTES + 1]).err(),
            Some(Error::InvalidLength)
        );
        // The exact bound passes the budget guard, then fails wire decoding.
        assert!(validate_length(MAX_INNER_PAYMENT_BYTES).is_ok());
    }

    #[test]
    fn payload_identity_covers_proof_ciphertext_and_authorization_bytes() {
        let payload = unverified_fixture();
        let bytes = encode(NETWORK, &payload).unwrap();
        for position in [0, 40, 200, payload.len() - 65, payload.len() - 1] {
            let mut changed = bytes.clone();
            changed[ENVELOPE_HEADER_BYTES + position] ^= 1;
            assert_eq!(error(&changed), Error::DigestMismatch);
        }
        let mut changed = bytes.clone();
        changed[ID_OFFSET] ^= 1;
        assert_eq!(error(&changed), Error::DigestMismatch);

        // Reframing a different signature gives a different exact-packet ID;
        // replay prevention must still use shared durable nullifiers.
        let mut other_payload = payload.clone();
        *other_payload.last_mut().unwrap() ^= 1;
        let other = encode(NETWORK, &other_payload).unwrap();
        assert_ne!(
            decode(NETWORK, 50, &other).unwrap().payment_id,
            decode(NETWORK, 50, &bytes).unwrap().payment_id
        );
    }

    #[test]
    fn strict_framing_never_permits_other_inner_versions_or_encodings() {
        let payload = unverified_fixture();
        let payment = wire::decode(NETWORK, &payload).unwrap();
        let plain_context = AuthorizationContext {
            shielded_fee: None,
            ..payment.context
        };
        let v1 = wire::encode(NETWORK, &plain_context, &payment.bundle).unwrap();
        assert_eq!(encode(NETWORK, &v1).err(), Some(Error::UnsupportedVersion));
        assert_eq!(&v1[..8], b"NPAY0001");

        let withdrawal_context = AuthorizationContext {
            withdrawal_recipient: Some([8; 32]),
            ..plain_context
        };
        let v2 = wire::encode(NETWORK, &withdrawal_context, &payment.bundle).unwrap();
        assert_eq!(encode(NETWORK, &v2).err(), Some(Error::UnsupportedVersion));
        assert_eq!(&v2[..8], b"NPAY0002");
        assert_eq!(encode([1; 32], &payload).err(), Some(Error::WrongNetwork));

        let mut bad_anchor = payload;
        // V3 places the anchor after its additional signed fee field.
        bad_anchor[96..128].fill(0xff);
        assert_eq!(
            encode(NETWORK, &bad_anchor).err(),
            Some(Error::InvalidEncoding)
        );
    }
}
