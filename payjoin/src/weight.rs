//! Implements advanced weight calculations for fee estimation.
use bitcoin::{OutPoint, Script, TxIn, Weight, Witness};

pub(crate) trait ComputeWeight {
    fn weight(&self) -> Weight;
}

pub(crate) trait ComputeSize {
    fn encoded_size(&self) -> u64;
}

pub(crate) fn varint_size(number: u64) -> u64 {
    match number {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffffffff => 5,
        0x100000000..=0xffffffffffffffff => 9,
    }
}

pub(crate) fn witness_weight(witness: &Witness) -> Weight {
    if witness.is_empty() {
        return Weight::ZERO;
    }
    let mut size = varint_size(witness.len() as u64);

    for item in witness.iter() {
        size += varint_size(item.len() as u64) + (item.len() as u64);
    }

    Weight::from_witness_data_size(size)
}

impl ComputeSize for Script {
    fn encoded_size(&self) -> u64 {
        (self.len() as u64) + varint_size(self.len() as u64)
    }
}

impl ComputeWeight for TxIn {
    fn weight(&self) -> Weight {
        Weight::from_non_witness_data_size(
            self.script_sig.encoded_size() + 4, /* bytes encoding u32 sequence number */
        ) + self.previous_output.weight()
            + witness_weight(&self.witness)
    }
}

impl ComputeWeight for OutPoint {
    fn weight(&self) -> Weight {
        Weight::from_non_witness_data_size(
            32 /* bytes encoding previous hash */ + 4, /* bytes encoding u32 output index */
        )
    }
}
