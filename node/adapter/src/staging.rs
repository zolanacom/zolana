use native_payments::staging::{payload_digest, MAX_CHUNK_BYTES, MAX_PAYLOAD_BYTES};
use solana_instruction::error::InstructionError as Error;

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
