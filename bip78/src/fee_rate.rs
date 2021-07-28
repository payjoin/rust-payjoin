use crate::weight::Weight;
use std::ops::{Mul, Div};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub(crate) struct FeeRate(u64);

impl FeeRate {
    pub(crate) fn from_sat_per_vb(rate: u64) -> Self {
        FeeRate(rate * 4)
    }

    pub(crate) fn from_sat_per_wu(rate: u64) -> Self {
        FeeRate(rate)
    }

    pub(crate) fn to_sat_per_vb(self) -> u64 {
        self.0 * 4
    }

    pub(crate) fn to_sat_per_wu(self) -> u64 {
        self.0
    }
}

// Note that Add and Sub are meaningless when it comes to fee rates

impl Mul<Weight> for FeeRate {
    type Output = bitcoin::Amount;

    fn mul(self, rhs: Weight) -> Self::Output {
        bitcoin::Amount::from_sat(self.0 * u64::from(rhs))
    }
}

impl Mul<u64> for FeeRate {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        FeeRate(self.0 * rhs)
    }
}

impl Mul<FeeRate> for u64 {
    type Output = FeeRate;

    fn mul(self, rhs: FeeRate) -> Self::Output {
        FeeRate(self * rhs.0)
    }
}

impl Div<u64> for FeeRate {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        FeeRate(self.0 / rhs)
    }
}
