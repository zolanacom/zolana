//! Native instruction replay beneath authenticated successful canonical blocks.
//! This checks accounts/staging/proof effects, not consensus or public debit receipts.
use crate::{
    history::{AcceptedPayment, WalletState},
    Result, WalletKeys,
};
use native_payments::{
    native_accounts::{self, Buffer, ACCOUNT_BYTES},
    verification::MAX_EXPIRY_WINDOW,
    wire,
};
use solana_pubkey::Pubkey;
use std::collections::HashMap;
pub trait AccountKey {
    fn bytes(&self) -> [u8; 32];
}
impl AccountKey for [u8; 32] {
    fn bytes(&self) -> [u8; 32] {
        *self
    }
}
impl AccountKey for Pubkey {
    fn bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }
}
pub struct HistoryInstruction<A = [u8; 32]> {
    pub accounts: Vec<(A, bool)>,
    pub data: Vec<u8>,
}
pub struct Replay {
    pub state: WalletState,
    pub(crate) buffers: HashMap<[u8; 32], Buffer>,
}

impl Replay {
    pub fn new(wallet: &(impl WalletKeys + ?Sized), rent_floor: u64) -> Result<Self> {
        Ok(Self {
            state: WalletState::new(wallet, rent_floor)?,
            buffers: HashMap::new(),
        })
    }

    pub fn new_slot_anchored(wallet: &(impl WalletKeys + ?Sized), rent_floor: u64) -> Result<Self> {
        Ok(Self {
            state: WalletState::new_slot_anchored(wallet, rent_floor)?,
            buffers: HashMap::new(),
        })
    }

    pub fn staging_count(&self) -> usize {
        self.buffers.len()
    }

    pub fn finish_slot(&mut self, slot: u64) -> Result<()> {
        self.state.finish_slot(slot)
    }

    pub fn apply(&mut self, ix: &HistoryInstruction<impl AccountKey>, slot: u64) -> Result<()> {
        self.apply_verified(ix, slot).map(|_| ())
    }

    pub fn from_state(state: WalletState) -> Self {
        Self {
            state,
            buffers: HashMap::new(),
        }
    }

    pub fn apply_verified(
        &mut self,
        ix: &HistoryInstruction<impl AccountKey>,
        slot: u64,
    ) -> Result<Option<AcceptedPayment>> {
        let (&opcode, rest) = ix
            .data
            .split_first()
            .ok_or("empty native history instruction")?;
        let accounts: Vec<_> = ix
            .accounts
            .iter()
            .map(|(key, signer)| (Pubkey::new_from_array(key.bytes()), *signer))
            .collect();
        if opcode == 5 {
            self.state.ensure_slot_open(slot)?;
            if accounts.len() != 5
                || accounts[0].0 != Pubkey::new_from_array(native_accounts::pool_address())
                || accounts[2].0 != Pubkey::new_from_array(native_accounts::SYSTEM_ID)
                || !accounts[1].1
            {
                return Err("invalid native inline payment in history".into());
            }
            let payment =
                native_payments::envelope::decode(self.state.pool.network, slot, rest)?.payment;
            if payment.context.sponsor != accounts[1].0.to_bytes() {
                return Err("history authorization sponsor mismatch".into());
            }
            for (index, action) in payment.bundle.actions().iter().enumerate() {
                if accounts[3 + index].0
                    != Pubkey::new_from_array(native_accounts::nullifier_address(
                        &action.nullifier().to_bytes(),
                    ))
                {
                    return Err("history nullifier address mismatch".into());
                }
            }
            return Ok(Some(self.state.accept_history_payment(payment, slot)?));
        }
        if opcode == 3 {
            self.state.ensure_slot_open(slot)?;
            if !rest.is_empty()
                || ![6, 7].contains(&accounts.len())
                || accounts[0].0 != Pubkey::new_from_array(native_accounts::pool_address())
                || accounts[3].0 != Pubkey::new_from_array(native_accounts::SYSTEM_ID)
                || !accounts[2].1
            {
                return Err("invalid native finalization in history".into());
            }
            let buffer = self
                .buffers
                .get_mut(&accounts[1].0.to_bytes())
                .ok_or("missing staging history; an archive RPC is required")?;
            if buffer.sponsor() != accounts[2].0.to_bytes() || slot > buffer.expiry() {
                return Err("history sponsor or expiry mismatch".into());
            }
            let payment = wire::decode(self.state.pool.network, buffer.payload()?)?;
            if payment.context.sponsor != accounts[2].0.to_bytes() {
                return Err("history authorization sponsor mismatch".into());
            }
            match payment.context.withdrawal_recipient {
                None if accounts.len() == 6 => (),
                Some(recipient)
                    if accounts.len() == 7
                        && accounts[6].0.to_bytes() == recipient
                        && accounts[6].0.is_on_curve()
                        && accounts[6].0 != accounts[2].0 => {}
                _ => return Err("history withdrawal recipient/account shape mismatch".into()),
            }
            for (index, action) in payment.bundle.actions().iter().enumerate() {
                if accounts[4 + index].0
                    != Pubkey::new_from_array(native_accounts::nullifier_address(
                        &action.nullifier().to_bytes(),
                    ))
                {
                    return Err("history nullifier address mismatch".into());
                }
            }
            let accepted = self.state.accept_history_payment(payment, slot)?;
            buffer.consume()?;
            return Ok(Some(accepted));
        }
        if accounts.len() != 2
            || !accounts[1].1
            || accounts[0].0 == Pubkey::new_from_array(native_accounts::pool_address())
            || accounts[0].0 == accounts[1].0
        {
            return Err("invalid native staging history".into());
        }
        let key = accounts[0].0.to_bytes();
        if opcode == 0 {
            if rest.len() != 44 || !accounts[0].1 || self.buffers.contains_key(&key) {
                return Err("invalid staging initialization history".into());
            }
            let expiry = u64::from_le_bytes(rest[36..44].try_into()?);
            if expiry < slot || expiry.saturating_sub(slot) > MAX_EXPIRY_WINDOW {
                return Err("invalid staging expiry history".into());
            }
            let buffer = Buffer::initialize(
                &vec![0; ACCOUNT_BYTES],
                accounts[1].0.to_bytes(),
                u32::from_le_bytes(rest[..4].try_into()?),
                rest[4..36].try_into()?,
                expiry,
            )?;
            self.buffers.insert(key, buffer);
            return Ok(None);
        }
        let buffer = self
            .buffers
            .get_mut(&key)
            .ok_or("missing staging history; an archive RPC is required")?;
        if buffer.sponsor() != accounts[1].0.to_bytes() || (opcode != 4 && slot > buffer.expiry()) {
            return Err("staging history sponsor or expiry mismatch".into());
        }
        match opcode {
            1 if rest.len() >= 5 => {
                buffer.write(u32::from_le_bytes(rest[..4].try_into()?), &rest[4..])?
            }
            2 if rest.is_empty() => buffer.seal()?,
            4 if rest.is_empty() => {
                self.buffers.remove(&key);
            }
            _ => return Err("unknown native instruction in history".into()),
        }
        Ok(None)
    }
}
