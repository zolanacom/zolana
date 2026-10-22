//! Shared transaction authentication beneath finalized RPC history replay.
//! Signature checks authenticate the transaction, not RPC execution/finality.
//! The host must also check successful metadata, complete ordered blocks and
//! exact finalized pool reconciliation before publishing balances or receipts.
use crate::{replay::HistoryInstruction, Result};
use native_payments::native_accounts::PROGRAM_ID;
use solana_transaction::versioned::VersionedTransaction;

pub struct LoadedAddresses {
    pub writable: Vec<[u8; 32]>,
    pub readonly: Vec<[u8; 32]>,
}
pub struct AuthenticatedNativeTransaction {
    pub signature: String,
    pub instructions: Vec<HistoryInstruction>,
}

pub fn authenticate(
    tx: &VersionedTransaction,
    loaded: Option<LoadedAddresses>,
) -> Result<Option<AuthenticatedNativeTransaction>> {
    tx.sanitize()?;
    let mut keys: Vec<_> = tx
        .message
        .static_account_keys()
        .iter()
        .map(|key| key.to_bytes())
        .collect();
    let lookups = tx.message.address_table_lookups();
    if let Some(lookups) = lookups.filter(|v| !v.is_empty()) {
        let loaded = loaded.ok_or("loaded account addresses are unavailable")?;
        let nw: usize = lookups.iter().map(|v| v.writable_indexes.len()).sum();
        let nr: usize = lookups.iter().map(|v| v.readonly_indexes.len()).sum();
        if loaded.writable.len() != nw || loaded.readonly.len() != nr {
            return Err("loaded account count differs from signed address lookups".into());
        }
        keys.extend(loaded.writable);
        keys.extend(loaded.readonly);
    }
    if !tx
        .message
        .instructions()
        .iter()
        .any(|ix| keys.get(ix.program_id_index as usize) == Some(&PROGRAM_ID))
    {
        return Ok(None);
    }
    tx.verify_and_hash_message()?;
    let mut instructions = Vec::new();
    for ix in tx.message.instructions() {
        if keys.get(ix.program_id_index as usize) != Some(&PROGRAM_ID) {
            continue;
        }
        let accounts = ix
            .accounts
            .iter()
            .map(|index| {
                let index = *index as usize;
                Ok((
                    *keys.get(index).ok_or("invalid archived account index")?,
                    tx.message.is_signer(index),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        instructions.push(HistoryInstruction {
            accounts,
            data: ix.data.clone(),
        });
    }
    Ok(Some(AuthenticatedNativeTransaction {
        signature: tx
            .signatures
            .first()
            .ok_or("missing native transaction signature")?
            .to_string(),
        instructions,
    }))
}
