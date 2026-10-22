use native_payments::native_accounts as portable;
pub use portable::{ACCOUNT_BYTES, HEADER};
use solana_instruction::error::InstructionError as Error;
fn mapped(error: portable::Error) -> Error {
    match error {
        portable::Error::InvalidAccountData => Error::InvalidAccountData,
        portable::Error::InvalidInstructionData => Error::InvalidInstructionData,
    }
}
pub struct Buffer(portable::Buffer);
impl Buffer {
    pub fn initialize(
        bytes: &[u8],
        sponsor: [u8; 32],
        length: u32,
        digest: [u8; 32],
        expiry: u64,
    ) -> Result<Self, Error> {
        portable::Buffer::initialize(bytes, sponsor, length, digest, expiry)
            .map(Self)
            .map_err(mapped)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        portable::Buffer::decode(bytes).map(Self).map_err(mapped)
    }
    pub fn sponsor(&self) -> [u8; 32] {
        self.0.sponsor()
    }
    pub fn expiry(&self) -> u64 {
        self.0.expiry()
    }
    pub fn write(&mut self, offset: u32, chunk: &[u8]) -> Result<(), Error> {
        self.0.write(offset, chunk).map_err(mapped)
    }
    pub fn seal(&mut self) -> Result<(), Error> {
        self.0.seal().map_err(mapped)
    }
    pub fn payload(&self) -> Result<&[u8], Error> {
        self.0.payload().map_err(mapped)
    }
    pub fn consume(&mut self) -> Result<(), Error> {
        self.0.consume().map_err(mapped)
    }
    pub fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
}
