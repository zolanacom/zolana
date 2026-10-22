use crate::canonical::{authenticate, LoadedAddresses};
use native_payments::native_accounts::PROGRAM_ID;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{
    compiled_instruction::CompiledInstruction,
    v0::{Message, MessageAddressTableLookup},
    MessageHeader, VersionedMessage,
};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};

fn legacy(program: [u8; 32]) -> VersionedTransaction {
    let payer = Keypair::new_from_array([7; 32]);
    let ix = Instruction {
        program_id: Pubkey::new_from_array(program),
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![5, 1, 2, 3],
    };
    VersionedTransaction::from(Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        Default::default(),
    ))
}
#[test]
fn signed_native_legacy_is_preserved_and_unsigned_mutations_are_rejected() {
    let tx = legacy(PROGRAM_ID);
    let accepted = authenticate(&tx, None).unwrap().unwrap();
    assert_eq!(accepted.signature, tx.signatures[0].to_string());
    assert_eq!(accepted.instructions.len(), 1);
    assert_eq!(accepted.instructions[0].data, vec![5, 1, 2, 3]);
    assert_eq!(
        accepted.instructions[0].accounts,
        vec![(Keypair::new_from_array([7; 32]).pubkey().to_bytes(), true)]
    );
    let mut changed = tx.clone();
    match &mut changed.message {
        VersionedMessage::Legacy(message) => message.instructions[0].data.push(9),
        _ => panic!("legacy fixture"),
    }
    assert!(authenticate(&changed, None).is_err());
    let mut changed = tx;
    changed.signatures[0] = Default::default();
    assert!(authenticate(&changed, None).is_err());
    assert!(authenticate(&legacy([9; 32]), None).unwrap().is_none());
}
#[test]
fn v0_loaded_address_counts_must_match_the_signed_lookup_shape() {
    let payer = Keypair::new_from_array([7; 32]);
    let message = Message {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        },
        account_keys: vec![payer.pubkey(), Pubkey::new_from_array(PROGRAM_ID)],
        recent_blockhash: Default::default(),
        instructions: vec![CompiledInstruction {
            program_id_index: 1,
            accounts: vec![0, 2],
            data: vec![5],
        }],
        address_table_lookups: vec![MessageAddressTableLookup {
            account_key: Pubkey::new_from_array([11; 32]),
            writable_indexes: vec![0],
            readonly_indexes: vec![],
        }],
    };
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&payer]).unwrap();
    assert!(authenticate(&tx, None).is_err());
    assert!(authenticate(
        &tx,
        Some(LoadedAddresses {
            writable: vec![],
            readonly: vec![]
        })
    )
    .is_err());
    let accepted = authenticate(
        &tx,
        Some(LoadedAddresses {
            writable: vec![[12; 32]],
            readonly: vec![],
        }),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        accepted.instructions[0].accounts,
        vec![(payer.pubkey().to_bytes(), true), ([12; 32], false)]
    );
}
