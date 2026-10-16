//! In-process shielded-payment verification primitives.
//!
//! The caller must authenticate state and public funding. This library does not
//! mutate a ledger, authorize a deposit debit, or constitute a deployed chain.
#![forbid(unsafe_code)]

pub mod staging;
pub mod state;
pub mod verification;
pub mod wire;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidContext,
    UnsupportedVersion,
    InvalidShape,
    Expired,
    WrongValueBalance,
    UnknownAnchor,
    DuplicateNullifier,
    SpentNullifier,
    InvalidSpendAuthorization,
    InvalidBindingSignature,
    InvalidProof,
    InvalidLength,
    InvalidChunk,
    IncompletePayload,
    DigestMismatch,
    SealedPayload,
    UnsealedPayload,
    InvalidEncoding,
    WrongNetwork,
    CapacityExceeded,
    InsufficientBacking,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}
