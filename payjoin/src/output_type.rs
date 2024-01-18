crate::weight::Weight;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum OutputType {
    P2Pkh,
    P2Sh,
    SegWitV0 {
        ty: SegWitV0Type,
        nested: bool,
    },
    Taproot,
}

impl OutputType {
    pub(crate) fn output_only_weight(&self) -> Weight {
        use OutputType::*;

        match self {
            P2Pkh =>
                Weight::from_non_witness_data_size(
                    1 /* OP_DUP */ +
                        1 /* OP_HASH160 */ +
                        1 /* OP_PUSH */ +
                        160 / 8 /* ripemd160 hash size */ +
                        1 /* OP_EQUALVERIFY */ +
                        1 /* OP_CHECKSIG */
                ),
            P2Sh =>
                Weight::from_non_witness_data_size(
                    1 /* OP_HASH160 */ +
                        1 /* OP_PUSH */ +
                        160 / 8 /* ripemd160 hash size */ +
                        1 /* OP_EQUAL */
                ),
            SegWitV0 { ty: _, nested: true } =>
                Weight::from_non_witness_data_size(
                    1 /* OP_HASH160 */ +
                        1 /* OP_PUSH */ +
                        160 / 8 /* ripemd160 hash size */ +
                        1 /* OP_EQUAL */
                ),
            SegWitV0 { ty: SegWitV0Type::Pubkey, nested: false } =>
                Weight::from_non_witness_data_size(
                    1 /* OP_PUSH0 */ + 1 /* OP_PUSH */ + 160 / 8 /* ripemd160 hash size */
                ),
            SegWitV0 { ty: SegWitV0Type::Script, nested: false } =>
                Weight::from_non_witness_data_size(
                    1 /* OP_PUSH0 */ + 1 /* OP_PUSH */ + 256 / 8 /* ripemd160 hash size */
                ),
            Taproot =>
                Weight::from_non_witness_data_size(
                    1 /* OP_PUSH0 */ + 1 /* OP_PUSH */ + 256 / 8 /* ripemd160 hash size */
                ),
        }
    }
}