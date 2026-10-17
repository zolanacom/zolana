use crate::{id, pool_address};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

pub fn initialize(
    buffer: Pubkey,
    sponsor: Pubkey,
    length: u32,
    digest: [u8; 32],
    expiry: u64,
) -> Instruction {
    let mut data = vec![0];
    data.extend_from_slice(&length.to_le_bytes());
    data.extend_from_slice(&digest);
    data.extend_from_slice(&expiry.to_le_bytes());
    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(buffer, true),
            AccountMeta::new_readonly(sponsor, true),
        ],
        data,
    }
}
pub fn write(buffer: Pubkey, sponsor: Pubkey, offset: u32, chunk: &[u8]) -> Instruction {
    let mut data = vec![1];
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(chunk);
    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(sponsor, true),
        ],
        data,
    }
}
pub fn seal(buffer: Pubkey, sponsor: Pubkey) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(sponsor, true),
        ],
        data: vec![2],
    }
}
pub fn finalize(buffer: Pubkey, sponsor: Pubkey, nullifiers: [[u8; 32]; 2]) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(pool_address(), false),
            AccountMeta::new(buffer, false),
            AccountMeta::new(sponsor, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
            AccountMeta::new(crate::nullifiers::address(&nullifiers[0]), false),
            AccountMeta::new(crate::nullifiers::address(&nullifiers[1]), false),
        ],
        data: vec![3],
    }
}
pub fn close(buffer: Pubkey, sponsor: Pubkey) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(buffer, false),
            AccountMeta::new(sponsor, true),
        ],
        data: vec![4],
    }
}
