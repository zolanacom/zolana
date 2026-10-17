//! Pack ordered writes inside packet bounds; never race dependent RPC uploads.
use native_payment_program::instructions;
use native_payments::staging::MAX_CHUNK_BYTES;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

pub(crate) fn first_write(buffer: Pubkey, sponsor: Pubkey, bytes: &[u8]) -> Instruction {
    instructions::write(
        buffer,
        sponsor,
        0,
        &bytes[..bytes.len().min(MAX_CHUNK_BYTES)],
    )
}

pub(crate) fn remaining(buffer: Pubkey, sponsor: Pubkey, bytes: &[u8]) -> Vec<Vec<Instruction>> {
    let start = bytes.len().min(MAX_CHUNK_BYTES);
    let mut batches = Vec::new();
    for (index, chunk) in bytes[start..].chunks(1000).enumerate() {
        let mut batch = Vec::new();
        for (part, write) in chunk.chunks(500).enumerate() {
            batch.push(instructions::write(
                buffer,
                sponsor,
                (start + index * 1000 + part * 500) as u32,
                write,
            ));
        }
        batches.push(batch);
    }
    let seal = instructions::seal(buffer, sponsor);
    if let Some(last) = batches.last_mut() {
        let mut candidate = last.clone();
        candidate.push(seal.clone());
        if Transaction::new_with_payer(&candidate, Some(&sponsor))
            .message_data()
            .len()
            + 65
            <= 1232
        {
            last.push(seal);
            return batches;
        }
    }
    batches.push(vec![seal]);
    batches
}

#[cfg(test)]
mod tests {
    use super::*;
    use native_payment_program::{
        id,
        staging::{Buffer, ACCOUNT_BYTES},
    };
    use native_payments::staging::{payload_digest, MAX_PAYLOAD_BYTES};
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use solana_system_interface::instruction as system;

    #[test]
    fn packed_uploads_fit_signed_packets_and_replay_in_order_including_seal() {
        for length in [1, 768, 769, 9222, MAX_PAYLOAD_BYTES] {
            let bytes = vec![7; length];
            let sponsor = Keypair::new();
            let buffer = Keypair::new();
            let initialization = vec![
                system::create_account(
                    &sponsor.pubkey(),
                    &buffer.pubkey(),
                    1000,
                    ACCOUNT_BYTES as u64,
                    &id(),
                ),
                instructions::initialize(
                    buffer.pubkey(),
                    sponsor.pubkey(),
                    length as u32,
                    payload_digest(&bytes),
                    100,
                ),
                first_write(buffer.pubkey(), sponsor.pubkey(), &bytes),
            ];
            let tx = Transaction::new_signed_with_payer(
                &initialization,
                Some(&sponsor.pubkey()),
                &[&sponsor, &buffer],
                Default::default(),
            );
            assert!(129 + tx.message_data().len() <= 1232);
            let mut staged = Buffer::initialize(
                &vec![0; ACCOUNT_BYTES],
                sponsor.pubkey().to_bytes(),
                length as u32,
                payload_digest(&bytes),
                100,
            )
            .unwrap();
            staged
                .write(0, &bytes[..length.min(MAX_CHUNK_BYTES)])
                .unwrap();
            let batches = remaining(buffer.pubkey(), sponsor.pubkey(), &bytes);
            if length == 9222 {
                assert_eq!(batches.len(), 9);
            }
            for batch in batches {
                let tx = Transaction::new_signed_with_payer(
                    &batch,
                    Some(&sponsor.pubkey()),
                    &[&sponsor],
                    Default::default(),
                );
                assert!(65 + tx.message_data().len() <= 1232);
                for ix in batch {
                    match ix.data[0] {
                        1 => staged
                            .write(
                                u32::from_le_bytes(ix.data[1..5].try_into().unwrap()),
                                &ix.data[5..],
                            )
                            .unwrap(),
                        2 => staged.seal().unwrap(),
                        _ => unreachable!(),
                    }
                }
            }
            assert_eq!(staged.payload().unwrap(), bytes);
        }
    }
}
