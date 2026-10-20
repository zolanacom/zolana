//! Packet-bounded staging writes and verified repair after a bounded upload burst.
use crate::Result;
use native_payment_program::instructions;
use native_payment_program::staging::Buffer;
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
    remaining_from(buffer, sponsor, bytes, start)
}

fn remaining_from(
    buffer: Pubkey,
    sponsor: Pubkey,
    bytes: &[u8],
    start: usize,
) -> Vec<Vec<Instruction>> {
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

/// A confirmed staging prefix may be repaired only after every burst identity
/// has a confirmed outcome. Never trust an RPC offset without authenticating the
/// original authority, header, digest and every already uploaded byte.
pub(crate) fn repair(
    buffer: Pubkey,
    sponsor: Pubkey,
    bytes: &[u8],
    expiry: u64,
    encoded: &[u8],
) -> Result<Vec<Vec<Instruction>>> {
    let staged = Buffer::decode(encoded)?;
    let received = u32::from_le_bytes(encoded[44..48].try_into()?) as usize;
    if staged.sponsor() != sponsor.to_bytes()
        || staged.expiry() != expiry
        || encoded[40..44] != (bytes.len() as u32).to_le_bytes()
        || encoded[48..80] != native_payments::staging::payload_digest(bytes)
        || received > bytes.len()
        || encoded[native_payment_program::staging::HEADER
            ..native_payment_program::staging::HEADER + received]
            != bytes[..received]
    {
        return Err("confirmed upload differs from the original staging payload".into());
    }
    match encoded[88] {
        1 if staged.payload()? == bytes => Ok(Vec::new()),
        0 => Ok(remaining_from(buffer, sponsor, bytes, received)),
        _ => Err("staging payload was already consumed or has an invalid seal".into()),
    }
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

    fn apply_atomic(staged: &mut Buffer, batch: &[Instruction]) -> bool {
        let mut next = Buffer::decode(staged.bytes()).unwrap();
        for ix in batch {
            let result = match ix.data[0] {
                1 => next.write(
                    u32::from_le_bytes(ix.data[1..5].try_into().unwrap()),
                    &ix.data[5..],
                ),
                2 => next.seal(),
                _ => panic!("unexpected upload instruction"),
            };
            if result.is_err() {
                return false;
            }
        }
        *staged = next;
        true
    }

    #[test]
    fn out_of_order_and_failed_bursts_repair_only_the_original_prefix() {
        for length in [1, 768, 769, 9222, 9254, MAX_PAYLOAD_BYTES] {
            let bytes: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
            let sponsor = Pubkey::new_unique();
            let buffer = Pubkey::new_unique();
            let batches = remaining(buffer, sponsor, &bytes);
            for mode in 0..4 {
                let mut staged = Buffer::initialize(
                    &vec![0; ACCOUNT_BYTES],
                    sponsor.to_bytes(),
                    length as u32,
                    payload_digest(&bytes),
                    100,
                )
                .unwrap();
                staged
                    .write(0, &bytes[..length.min(MAX_CHUNK_BYTES)])
                    .unwrap();
                let mut order: Vec<_> = (0..batches.len()).collect();
                if mode == 1 {
                    order.reverse();
                }
                if mode == 2 && order.len() > 1 {
                    order.rotate_left(1);
                }
                for index in order {
                    if mode != 3 || index % 2 == 1 {
                        apply_atomic(&mut staged, &batches[index]);
                    }
                }
                let repairs = repair(buffer, sponsor, &bytes, 100, staged.bytes()).unwrap();
                assert!(repairs.len() <= batches.len());
                for batch in repairs {
                    assert!(apply_atomic(&mut staged, &batch));
                }
                assert_eq!(staged.payload().unwrap(), bytes);
                assert!(repair(buffer, sponsor, &bytes, 100, staged.bytes())
                    .unwrap()
                    .is_empty());
                assert!(repair(buffer, Pubkey::new_unique(), &bytes, 100, staged.bytes()).is_err());
                assert!(repair(buffer, sponsor, &bytes, 101, staged.bytes()).is_err());
                let mut wrong = bytes.clone();
                wrong[0] ^= 1;
                assert!(repair(buffer, sponsor, &wrong, 100, staged.bytes()).is_err());
                staged.consume().unwrap();
                assert!(repair(buffer, sponsor, &bytes, 100, staged.bytes()).is_err());
            }
        }
    }

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
