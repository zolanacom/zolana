//! Existing native program identifiers, PDA derivation and staging bytes.
//! Portable host code only; no runtime, ledger, RPC or deposit authorization.
use solana_pubkey::Pubkey;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAccountData,
    InvalidInstructionData,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub const PROGRAM_ID: [u8; 32] = [
    91, 34, 9, 203, 140, 74, 92, 11, 167, 20, 210, 73, 64, 155, 3, 220, 25, 87, 194, 52, 122, 28,
    170, 241, 29, 131, 42, 88, 76, 107, 13, 190,
];
pub const SYSTEM_ID: [u8; 32] = [0; 32];
pub fn pool_address() -> [u8; 32] {
    Pubkey::find_program_address(
        &[b"native-payment-pool-v1"],
        &Pubkey::new_from_array(PROGRAM_ID),
    )
    .0
    .to_bytes()
}
pub fn nullifier_address(nullifier: &[u8; 32]) -> [u8; 32] {
    Pubkey::find_program_address(
        &[b"native-payment-spent-v1", &pool_address(), nullifier],
        &Pubkey::new_from_array(PROGRAM_ID),
    )
    .0
    .to_bytes()
}
use crate::staging::{payload_digest, MAX_CHUNK_BYTES, MAX_PAYLOAD_BYTES};

pub const HEADER: usize = 96;
pub const ACCOUNT_BYTES: usize = HEADER + MAX_PAYLOAD_BYTES;

pub struct Buffer {
    bytes: Vec<u8>,
}

impl Buffer {
    pub fn initialize(
        bytes: &[u8],
        sponsor: [u8; 32],
        length: u32,
        digest: [u8; 32],
        expiry: u64,
    ) -> Result<Self, Error> {
        if bytes.len() != ACCOUNT_BYTES
            || bytes.iter().any(|b| *b != 0)
            || length == 0
            || length as usize > MAX_PAYLOAD_BYTES
        {
            return Err(Error::InvalidAccountData);
        }
        let mut bytes = bytes.to_vec();
        bytes[..8].copy_from_slice(b"NBUF0001");
        bytes[8..40].copy_from_slice(&sponsor);
        bytes[40..44].copy_from_slice(&length.to_le_bytes());
        bytes[48..80].copy_from_slice(&digest);
        bytes[80..88].copy_from_slice(&expiry.to_le_bytes());
        Ok(Self { bytes })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ACCOUNT_BYTES
            || &bytes[..8] != b"NBUF0001"
            || !matches!(bytes[88], 0 | 1 | 3)
            || bytes[89..HEADER].iter().any(|b| *b != 0)
        {
            return Err(Error::InvalidAccountData);
        }
        let value = Self {
            bytes: bytes.to_vec(),
        };
        if value.length() == 0
            || value.length() > MAX_PAYLOAD_BYTES
            || value.received() > value.length()
            || (value.bytes[88] != 0 && value.received() != value.length())
            || value.bytes[HEADER + value.received()..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(Error::InvalidAccountData);
        }
        Ok(value)
    }
    pub fn sponsor(&self) -> [u8; 32] {
        self.bytes[8..40].try_into().unwrap()
    }
    pub fn expiry(&self) -> u64 {
        u64::from_le_bytes(self.bytes[80..88].try_into().unwrap())
    }
    fn length(&self) -> usize {
        u32::from_le_bytes(self.bytes[40..44].try_into().unwrap()) as usize
    }
    fn received(&self) -> usize {
        u32::from_le_bytes(self.bytes[44..48].try_into().unwrap()) as usize
    }
    pub fn write(&mut self, offset: u32, chunk: &[u8]) -> Result<(), Error> {
        let offset = offset as usize;
        if self.bytes[88] != 0
            || offset != self.received()
            || chunk.is_empty()
            || chunk.len() > MAX_CHUNK_BYTES
            || offset
                .checked_add(chunk.len())
                .is_none_or(|end| end > self.length())
        {
            return Err(Error::InvalidInstructionData);
        }
        self.bytes[HEADER + offset..HEADER + offset + chunk.len()].copy_from_slice(chunk);
        self.bytes[44..48].copy_from_slice(&((offset + chunk.len()) as u32).to_le_bytes());
        Ok(())
    }
    pub fn seal(&mut self) -> Result<(), Error> {
        if self.bytes[88] != 0
            || self.received() != self.length()
            || payload_digest(&self.bytes[HEADER..HEADER + self.length()]) != self.bytes[48..80]
        {
            return Err(Error::InvalidAccountData);
        }
        self.bytes[88] = 1;
        Ok(())
    }
    pub fn payload(&self) -> Result<&[u8], Error> {
        if self.bytes[88] != 1 {
            return Err(Error::InvalidAccountData);
        }
        Ok(&self.bytes[HEADER..HEADER + self.length()])
    }
    pub fn consume(&mut self) -> Result<(), Error> {
        self.payload()?;
        self.bytes[88] = 3;
        Ok(())
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
