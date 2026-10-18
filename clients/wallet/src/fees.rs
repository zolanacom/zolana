//! Bounded user authorization for the gross debit of one staged payment.
use crate::Result;
use native_payments::verification::AuthorizationContext;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentKind {
    Send,
    Withdraw(Pubkey),
}
impl PaymentKind {
    pub fn from_context(context: &AuthorizationContext) -> Result<Self> {
        match (context.public_value_balance, context.withdrawal_recipient) {
            (0, None) => Ok(Self::Send),
            (value, Some(recipient)) if value > 0 && recipient != [0; 32] => {
                Ok(Self::Withdraw(Pubkey::new_from_array(recipient)))
            }
            _ => Err(
                "user-paid fees support private sends and recipient-bound withdrawals only".into(),
            ),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Withdraw(_) => "withdraw",
        }
    }
    pub fn payload_len(self) -> usize {
        match self {
            Self::Send => 9222,
            Self::Withdraw(_) => 9254,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub maximum: u64,
    pub charged: u64,
    pub cleanup_reserve: u64,
}
impl Authorization {
    pub fn new(maximum: u64, cleanup_reserve: u64) -> Result<Self> {
        let value = Self {
            maximum,
            charged: 0,
            cleanup_reserve,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.cleanup_reserve == 0
            || self.maximum <= self.cleanup_reserve
            || self.charged > self.maximum
        {
            return Err("invalid user fee authorization; recovery record retained".into());
        }
        Ok(())
    }
    pub fn charge(&mut self, debit: u64, cleanup: bool) -> Result<()> {
        self.validate()?;
        let ceiling = if cleanup {
            self.maximum
        } else {
            self.maximum - self.cleanup_reserve
        };
        let charged = self
            .charged
            .checked_add(debit)
            .filter(|n| *n <= ceiling)
            .ok_or(
                "transaction would exceed user fee debit cap; original cleanup allowance retained",
            )?;
        self.charged = charged;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct Quote {
    pub payment: &'static str,
    pub fee_address: String,
    pub public_balance: u64,
    pub refundable_staging_rent: u64,
    pub permanent_nullifier_rent: u64,
    pub transaction_fees: u64,
    pub cleanup_reserve: u64,
    pub maximum_gross_debit: u64,
    pub minimum_remaining_balance: u64,
    pub funding_required: u64,
    pub funding_shortfall: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_fee_shapes_exclude_deposits_and_legacy_public_withdrawals() {
        let context = AuthorizationContext {
            expires_at: 100,
            public_value_balance: 0,
            sponsor: [7; 32],
            withdrawal_recipient: None,
        };
        assert_eq!(
            PaymentKind::from_context(&context).unwrap(),
            PaymentKind::Send
        );
        assert_eq!(PaymentKind::Send.payload_len(), 9222);
        let withdrawal = AuthorizationContext {
            public_value_balance: 1,
            withdrawal_recipient: Some([8; 32]),
            ..context
        };
        assert_eq!(
            PaymentKind::from_context(&withdrawal)
                .unwrap()
                .payload_len(),
            9254
        );
        for (value, recipient) in [
            (-1, None),
            (1, None),
            (0, Some([8; 32])),
            (-1, Some([8; 32])),
            (1, Some([0; 32])),
        ] {
            assert!(PaymentKind::from_context(&AuthorizationContext {
                public_value_balance: value,
                withdrawal_recipient: recipient,
                ..context
            })
            .is_err());
        }
    }
    #[test]
    fn durable_cap_reserves_cleanup_and_never_refunds_or_resets_on_recovery() {
        let mut a = Authorization::new(100, 10).unwrap();
        a.charge(80, false).unwrap();
        let encoded = serde_json::to_vec(&a).unwrap();
        let mut recovered: Authorization = serde_json::from_slice(&encoded).unwrap();
        assert!(recovered.charge(11, false).is_err());
        assert_eq!(recovered.charged, 80);
        recovered.charge(10, false).unwrap();
        assert!(recovered.charge(1, false).is_err());
        recovered.charge(10, true).unwrap();
        assert!(recovered.charge(1, true).is_err());
        assert_eq!(recovered.charged, 100);
        assert!(Authorization::new(10, 10).is_err());
        assert!(Authorization::new(100, 0).is_err());
        assert!(Authorization {
            maximum: 100,
            charged: 101,
            cleanup_reserve: 10
        }
        .validate()
        .is_err());
    }
}
