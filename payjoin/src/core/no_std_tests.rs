use core::str::FromStr;

use bitcoin::psbt::Psbt;
extern crate alloc;
use bitcoin::{consensus, Amount, FeeRate, Weight};

#[test]
fn test_fallback_tx_extracts_and_is_nonempty() {
    let psbt_str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

    let psbt = Psbt::from_str(psbt_str).expect("psbt parse");
    let tx = psbt.extract_tx().expect("tx extract");

    assert_eq!(tx.version.0, 2);
    assert!(!tx.input.is_empty());
    assert!(!tx.output.is_empty());
}

#[cfg(feature = "v2")]
#[test]
fn test_uri_parsing_sets_amount() {
    use core::convert::TryFrom;

    use crate::Uri;

    let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01&pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ%23RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-EX1C4UC6ES";
    let parsed = Uri::try_from(uri).expect("uri parse");
    assert!(parsed.amount.is_some());
}

#[cfg(feature = "v2")]
#[test]
fn v2_uri_rejects_invalid_amount() {
    use core::convert::TryFrom;

    use crate::Uri;

    let uri =
        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=not_a_number&pj=https://example.com/x";
    assert!(Uri::try_from(uri).is_err());
}

#[cfg(feature = "v2")]
#[test]
fn v2_uri_parsing_sets_amount() {
    use core::convert::TryFrom;

    use crate::Uri;

    let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01&pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ%23RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-EX1C4UC6ES";
    let parsed = Uri::try_from(uri).expect("uri parse");
    assert!(parsed.amount.is_some());
    assert_eq!(parsed.amount.unwrap(), Amount::from_btc(0.01).unwrap());
}

#[test]
fn alloc_vec_smoke() {
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(&[1u8, 2, 3, 4]);
    assert_eq!(v.len(), 4);
    assert_eq!(v[0], 1);
    assert_eq!(v[3], 4);
}

#[test]
fn fee_math_is_deterministic() {
    let w = Weight::from_wu(400); // 100 vbytes
    let fr = FeeRate::from_sat_per_vb_u32(2);

    // 100 vbytes * 2 sat/vb = 200 sats
    let fee = w * fr;
    assert_eq!(fee, Amount::from_sat(200));
}

#[test]
fn psbt_extract_tx_has_expected_shape() {
    let psbt_str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

    let psbt = Psbt::from_str(psbt_str).expect("psbt parse");
    let tx = psbt.extract_tx().expect("tx extract");

    assert_eq!(tx.version.0, 2);
    assert!(!tx.input.is_empty());
    assert!(!tx.output.is_empty());

    let enc = consensus::encode::serialize(&tx);
    let dec: bitcoin::Transaction = consensus::encode::deserialize(&enc).expect("tx decode");
    assert_eq!(tx, dec);
}
