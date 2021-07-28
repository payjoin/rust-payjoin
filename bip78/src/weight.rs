use bitcoin::{Transaction, Script, TxOut, TxIn, OutPoint};

pub(crate) use inner::Weight;

// ensure explicit constructor
mod inner {
    use std::ops::{Add, Sub, AddAssign, SubAssign, Mul, Div};
    use crate::fee_rate::FeeRate;

    /// Represents virtual transaction size
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
    pub(crate) struct Weight(u64);

    impl Weight {
        pub(crate) const ZERO: Weight = Weight(0);

        pub(crate) fn from_witness_data_size(size: u64) -> Self {
            Weight(size)
        }

        pub(crate) fn from_non_witness_data_size(size: u64) -> Self {
            Weight(size * 4)
        }

        pub(crate) fn manual_from_u64(weight: u64) -> Self {
            Weight(weight)
        }
    }

    impl From<Weight> for u64 {
        fn from(value: Weight) -> Self {
            value.0
        }
    }

    impl Add for Weight {
        type Output = Weight;

        fn add(self, rhs: Weight) -> Self::Output {
            Weight(self.0 + rhs.0)
        }
    }

    impl Sub for Weight {
        type Output = Weight;

        fn sub(self, rhs: Weight) -> Self::Output {
            Weight(self.0 - rhs.0)
        }
    }

    impl AddAssign for Weight {
        fn add_assign(&mut self, rhs: Weight) {
            self.0 += rhs.0
        }
    }

    impl SubAssign for Weight {
        fn sub_assign(&mut self, rhs: Weight) {
            self.0 -= rhs.0
        }
    }

    impl Mul<u64> for Weight {
        type Output = Weight;

        fn mul(self, rhs: u64) -> Self::Output {
            Weight(self.0 * rhs)
        }
    }

    impl Div<Weight> for bitcoin::Amount {
        type Output = FeeRate;

        fn div(self, rhs: Weight) -> Self::Output {
            FeeRate::from_sat_per_wu(self.as_sat() / rhs.0)
        }
    }
}

fn witness_weight(witness: &Vec<Vec<u8>>) -> Weight {
    if witness.is_empty() {
        return Weight::ZERO;
    }
    let mut size = varint_size(witness.len() as u64);

    for item in witness {
        size += varint_size(item.len() as u64) + item.len() as u64;
    }

    Weight::from_witness_data_size(size)
}

pub(crate) trait ComputeWeight {
    fn weight(&self) -> Weight;
}

pub(crate) trait ComputeSize {
    fn encoded_size(&self) -> u64;
}

fn varint_size(number: u64) -> u64 {
    match number {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffffffff => 5,
        0x100000000..=0xffffffffffffffff => 9,
    }
}

impl ComputeSize for Script {
    fn encoded_size(&self) -> u64 {
        self.len() as u64 + varint_size(self.len() as u64)
    }
}

impl ComputeWeight for TxOut {
    fn weight(&self) -> Weight {
        Weight::from_non_witness_data_size(self.script_pubkey.encoded_size() + 8 /* bytes encoding u64 value */)
    }
}

impl ComputeWeight for TxIn {
    fn weight(&self) -> Weight {
        Weight::from_non_witness_data_size(self.script_sig.encoded_size() + 4 /* bytes encoding u32 sequence number */) + self.previous_output.weight() + witness_weight(&self.witness)
    }
}

impl ComputeWeight for OutPoint {
    fn weight(&self) -> Weight {
        Weight::from_non_witness_data_size(32 /* bytes encoding previous hash */ + 4 /* bytes encoding u32 output index */)
    }
}

impl ComputeWeight for Transaction {
    fn weight(&self) -> Weight {
        Weight::manual_from_u64(self.get_weight() as u64)
    }
}
