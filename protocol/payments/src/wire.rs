//! Fixed-shape experimental encoding. This format is not a released protocol.

use orchard::{
    bundle::{Authorized, Bundle},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::NoteBytesData,
    primitives::redpallas,
    tree::Anchor,
    value::ValueCommitment,
    Action, Proof,
};

use crate::{
    staging::MAX_PAYLOAD_BYTES,
    verification::{bundle_version, AuthorizationContext, ACTION_COUNT},
    Error,
};

/// Tag of a deposit, a private send or a sponsor withdrawal.
pub const MAGIC: &[u8; 8] = b"NPAY0001";
/// Tag of a withdrawal bound to a recipient: 32 more bytes follow the sponsor.
pub const WITHDRAWAL_MAGIC: &[u8; 8] = b"NPAY0002";
/// Tag of a payment with a shielded fee: 8 more bytes follow the sponsor.
pub const SHIELDED_FEE_MAGIC: &[u8; 8] = b"NPAY0003";
/// Encoded size of one action.
pub const ACTION_BYTES: usize = 884;
/// Bytes before the first action of a [`MAGIC`] payment, from the tag to the action count.
pub const HEADER_BYTES: usize = 122;

#[derive(Debug)]
pub struct DecodedPayment {
    pub context: AuthorizationContext,
    pub bundle: Bundle<Authorized, i64>,
}

pub fn encode(
    genesis: [u8; 32],
    context: &AuthorizationContext,
    bundle: &Bundle<Authorized, i64>,
) -> Result<Vec<u8>, Error> {
    context.validate()?;
    if genesis == [0; 32] || context.sponsor == [0; 32] {
        return Err(Error::InvalidContext);
    }
    if context
        .withdrawal_recipient
        .is_some_and(|key| key == [0; 32] || context.public_value_balance <= 0)
    {
        return Err(Error::InvalidContext);
    }
    if bundle.bundle_version() != bundle_version() {
        return Err(Error::UnsupportedVersion);
    }
    if bundle.actions().len() != ACTION_COUNT
        || *bundle.flags() != bundle_version().default_flags()
        || bundle.authorization().proof().as_ref().len() != Proof::expected_proof_size(ACTION_COUNT)
    {
        return Err(Error::InvalidShape);
    }
    if *bundle.value_balance() != context.public_value_balance {
        return Err(Error::WrongValueBalance);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(if context.shielded_fee.is_some() {
        SHIELDED_FEE_MAGIC
    } else if context.withdrawal_recipient.is_some() {
        WITHDRAWAL_MAGIC
    } else {
        MAGIC
    });
    bytes.extend_from_slice(&genesis);
    bytes.extend_from_slice(&context.expires_at.to_le_bytes());
    bytes.extend_from_slice(&context.public_value_balance.to_le_bytes());
    bytes.extend_from_slice(&context.sponsor);
    if let Some(fee) = context.shielded_fee {
        bytes.extend_from_slice(&fee.to_le_bytes());
    }
    if let Some(recipient) = context.withdrawal_recipient {
        bytes.extend_from_slice(&recipient);
    }
    bytes.extend_from_slice(&bundle.anchor().to_bytes());
    bytes.push(bundle.flag_byte());
    bytes.push(ACTION_COUNT as u8);
    for action in bundle.actions().iter() {
        bytes.extend_from_slice(&action.nullifier().to_bytes());
        bytes.extend_from_slice(&<[u8; 32]>::from(action.rk()));
        bytes.extend_from_slice(&action.cmx().to_bytes());
        bytes.extend_from_slice(&action.encrypted_note().epk_bytes);
        bytes.extend_from_slice(action.encrypted_note().enc_ciphertext.as_ref());
        bytes.extend_from_slice(&action.encrypted_note().out_ciphertext);
        bytes.extend_from_slice(&action.cv_net().to_bytes());
        bytes.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
    }
    let proof = bundle.authorization().proof().as_ref();
    bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    bytes.extend_from_slice(proof);
    bytes.extend_from_slice(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::InvalidLength);
    }
    Ok(bytes)
}

pub fn decode(genesis: [u8; 32], bytes: &[u8]) -> Result<DecodedPayment, Error> {
    let proof_length = Proof::expected_proof_size(ACTION_COUNT);
    let recipient_bound = bytes.get(..8) == Some(WITHDRAWAL_MAGIC.as_slice());
    let shielded_fee = bytes.get(..8) == Some(SHIELDED_FEE_MAGIC.as_slice());
    let expected_length = HEADER_BYTES
        + if shielded_fee { 8 } else { 0 }
        + if recipient_bound { 32 } else { 0 }
        + ACTION_COUNT * ACTION_BYTES
        + 4
        + proof_length
        + 64;
    if bytes.len() != expected_length || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::InvalidLength);
    }
    let mut input = bytes;
    let magic = take::<8>(&mut input)?;
    if &magic != MAGIC && &magic != WITHDRAWAL_MAGIC && &magic != SHIELDED_FEE_MAGIC {
        return Err(Error::UnsupportedVersion);
    }
    if genesis == [0; 32] || take::<32>(&mut input)? != genesis {
        return Err(Error::WrongNetwork);
    }
    let context = AuthorizationContext {
        expires_at: u64::from_le_bytes(take(&mut input)?),
        public_value_balance: i64::from_le_bytes(take(&mut input)?),
        sponsor: take(&mut input)?,
        shielded_fee: if shielded_fee {
            Some(u64::from_le_bytes(take(&mut input)?))
        } else {
            None
        },
        withdrawal_recipient: if recipient_bound {
            Some(take(&mut input)?)
        } else {
            None
        },
    };
    context.validate()?;
    if context.sponsor == [0; 32] {
        return Err(Error::InvalidContext);
    }
    if context
        .withdrawal_recipient
        .is_some_and(|key| key == [0; 32] || context.public_value_balance <= 0)
    {
        return Err(Error::InvalidContext);
    }
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(take(&mut input)?))
        .ok_or(Error::InvalidEncoding)?;
    if take::<1>(&mut input)?[0]
        != bundle_version()
            .default_flags()
            .to_byte(bundle_version())
            .unwrap()
        || take::<1>(&mut input)?[0] as usize != ACTION_COUNT
    {
        return Err(Error::InvalidShape);
    }
    let mut actions = Vec::with_capacity(ACTION_COUNT);
    for _ in 0..ACTION_COUNT {
        let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&take(&mut input)?))
            .ok_or(Error::InvalidEncoding)?;
        let key: redpallas::VerificationKey<redpallas::SpendAuth> = take::<32>(&mut input)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?;
        let commitment = Option::<ExtractedNoteCommitment>::from(
            ExtractedNoteCommitment::from_bytes(&take(&mut input)?),
        )
        .ok_or(Error::InvalidEncoding)?;
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: take(&mut input)?,
            enc_ciphertext: NoteBytesData(take(&mut input)?),
            out_ciphertext: take(&mut input)?,
        };
        let value =
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&take(&mut input)?))
                .ok_or(Error::InvalidEncoding)?;
        let signature = redpallas::Signature::from(take::<64>(&mut input)?);
        actions.push(
            Action::from_parts(nullifier, key, commitment, encrypted_note, value, signature)
                .map_err(|_| Error::InvalidEncoding)?,
        );
    }
    if u32::from_le_bytes(take(&mut input)?) as usize != proof_length {
        return Err(Error::InvalidLength);
    }
    let (proof, remaining) = input
        .split_at_checked(proof_length)
        .ok_or(Error::InvalidLength)?;
    input = remaining;
    let authorization = Authorized::from_parts(
        Proof::new(proof.to_vec()),
        redpallas::Signature::from(take::<64>(&mut input)?),
    );
    if !input.is_empty() {
        return Err(Error::InvalidLength);
    }
    let bundle = Bundle::try_from_parts(
        nonempty::NonEmpty::from_vec(actions).ok_or(Error::InvalidShape)?,
        bundle_version().default_flags(),
        context.public_value_balance,
        anchor,
        authorization,
        bundle_version(),
    )
    .map_err(|_| Error::InvalidEncoding)?;
    Ok(DecodedPayment { context, bundle })
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], Error> {
    let (head, tail) = input.split_at_checked(N).ok_or(Error::InvalidLength)?;
    *input = tail;
    head.try_into().map_err(|_| Error::InvalidLength)
}
