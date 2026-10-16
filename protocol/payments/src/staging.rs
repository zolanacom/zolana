//! Sequential, immutable-on-seal staging for public ciphertext/proof payloads.
//! Account ownership, rent, expiry and the wire decoder belong to the node adapter.

use crate::Error;

pub const MAX_PAYLOAD_BYTES: usize = 16_384;
pub const MAX_CHUNK_BYTES: usize = 768;

pub fn payload_digest(bytes: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"NativeStageV1!!!")
        .hash(bytes)
        .as_bytes()
        .try_into()
        .expect("32-byte digest")
}

pub struct StagedPayload {
    expected_length: usize,
    expected_digest: [u8; 32],
    bytes: Vec<u8>,
    sealed: bool,
}

impl StagedPayload {
    pub fn new(length: usize, digest: [u8; 32]) -> Result<Self, Error> {
        if length == 0 || length > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidLength);
        }
        Ok(Self {
            expected_length: length,
            expected_digest: digest,
            bytes: Vec::with_capacity(length),
            sealed: false,
        })
    }

    pub fn append(&mut self, offset: usize, chunk: &[u8]) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::SealedPayload);
        }
        if offset != self.bytes.len() || chunk.is_empty() || chunk.len() > MAX_CHUNK_BYTES {
            return Err(Error::InvalidChunk);
        }
        if chunk.len() > self.expected_length.saturating_sub(self.bytes.len()) {
            return Err(Error::InvalidLength);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    pub fn seal(&mut self) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::SealedPayload);
        }
        if self.bytes.len() != self.expected_length {
            return Err(Error::IncompletePayload);
        }
        if payload_digest(&self.bytes) != self.expected_digest {
            return Err(Error::DigestMismatch);
        }
        self.sealed = true;
        Ok(())
    }

    pub fn into_payload(self) -> Result<Vec<u8>, Error> {
        if !self.sealed {
            return Err(Error::UnsealedPayload);
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_payload_across_packet_sized_chunks_and_freezes_it() {
        let bytes = vec![42; 4_000];
        let mut payload = StagedPayload::new(bytes.len(), payload_digest(&bytes)).unwrap();
        for (i, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            payload.append(i * MAX_CHUNK_BYTES, chunk).unwrap();
        }
        payload.seal().unwrap();
        assert_eq!(payload.append(bytes.len(), &[1]), Err(Error::SealedPayload));
        assert_eq!(payload.seal(), Err(Error::SealedPayload));
        assert_eq!(payload.into_payload().unwrap(), bytes);
    }

    #[test]
    fn rejects_sparse_overwriting_oversized_and_truncated_payloads() {
        let mut payload = StagedPayload::new(10, payload_digest(&[0; 10])).unwrap();
        assert_eq!(payload.append(1, &[0]), Err(Error::InvalidChunk));
        assert_eq!(payload.append(0, &[]), Err(Error::InvalidChunk));
        assert_eq!(
            payload.append(0, &[0; MAX_CHUNK_BYTES + 1]),
            Err(Error::InvalidChunk)
        );
        assert_eq!(payload.append(0, &[0; 11]), Err(Error::InvalidLength));
        payload.append(0, &[0; 5]).unwrap();
        assert_eq!(payload.append(0, &[0]), Err(Error::InvalidChunk));
        assert_eq!(payload.seal(), Err(Error::IncompletePayload));
        assert_eq!(payload.into_payload(), Err(Error::UnsealedPayload));
    }

    #[test]
    fn rejects_modified_bytes_and_unbounded_allocations() {
        assert!(matches!(
            StagedPayload::new(0, [0; 32]),
            Err(Error::InvalidLength)
        ));
        assert!(matches!(
            StagedPayload::new(usize::MAX, [0; 32]),
            Err(Error::InvalidLength)
        ));
        let mut payload = StagedPayload::new(4, payload_digest(&[1; 4])).unwrap();
        payload.append(0, &[2; 4]).unwrap();
        assert_eq!(payload.seal(), Err(Error::DigestMismatch));
        assert_eq!(payload.into_payload(), Err(Error::UnsealedPayload));
    }
}
