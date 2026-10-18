//! Bounded user authorization for the gross debit of one staged withdrawal.
use crate::Result;
use serde::{Deserialize, Serialize};

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
