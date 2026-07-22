//! Assertions on payjoin's public BIP 21 URI surface.
//!
//! Every type named in these tests is payjoin's own. No `bitcoin_uri` type may appear in a
//! signature a downstream crate can observe, so that the BIP 21 parser can be upgraded or
//! swapped without forcing a payjoin major release. This is the downstream-visible
//! counterpart to the in-crate unit tests.

use std::error::Error;

use payjoin::bitcoin::address::{NetworkChecked, NetworkUnchecked};
use payjoin::bitcoin::{Amount, Network};
use payjoin::{PjParseError, Uri, UriParseError};

const NO_PJ: &str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1";

#[test]
fn parse_error_is_a_payjoin_type() {
    // The type annotation is the assertion: a malformed BIP 21 URI fails with payjoin's own
    // error, not with the parser's. The underlying cause stays reachable via the source chain.
    let err: UriParseError = Uri::try_from("bitcoin:this is not a valid uri &&&").unwrap_err();
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_some(), "the underlying cause should stay reachable");
}

#[test]
fn payjoin_param_error_is_recoverable_from_the_source_chain() {
    // A well-formed BIP 21 URI with a bad `pjos` value fails in payjoin's own extras parser.
    // Downstream recovers the concrete payjoin error by downcasting the source, without
    // naming or matching on any foreign type.
    let err: UriParseError =
        Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=2").unwrap_err();
    let source = err.source().expect("payjoin parameter errors have a source");
    assert!(
        source.downcast_ref::<PjParseError>().is_some(),
        "expected a payjoin::PjParseError, got: {source}"
    );
}

#[test]
fn accessors_replace_public_fields() {
    let uri: Uri<NetworkUnchecked> = NO_PJ.parse().expect("valid BIP 21 uri");
    let uri: Uri<NetworkChecked> = uri.assume_checked();

    assert_eq!(uri.address().to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
    assert_eq!(uri.amount(), Some(Amount::ONE_BTC));
    assert_eq!(uri.label(), None);
    assert_eq!(uri.message(), None);
    assert!(!uri.extras().pj_is_supported());
}

#[test]
fn label_and_message_decode_to_strings() {
    let uri = Uri::try_from(
        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?label=Luke-Jr&message=Donation%20for%20xyz",
    )
    .expect("valid BIP 21 uri")
    .assume_checked();

    assert_eq!(uri.label().as_deref(), Some("Luke-Jr"));
    assert_eq!(uri.message().as_deref(), Some("Donation for xyz"));
}

#[test]
fn payjoin_uri_exposes_bip21_fields() {
    // A payjoin URI carries the same BIP 21 fields as a plain one. The accessors read them
    // back through payjoin's own types, and `set_amount` overrides the requested amount.
    let mut pjuri = Uri::try_from(
        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&label=Luke-Jr&message=Donation%20for%20xyz&pjos=1&pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ%23EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV",
    )
    .expect("valid payjoin uri")
    .assume_checked()
    .check_pj_supported()
    .expect("this uri requests payjoin");

    assert_eq!(pjuri.address().to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
    assert_eq!(pjuri.amount(), Some(Amount::ONE_BTC));
    assert_eq!(pjuri.label().as_deref(), Some("Luke-Jr"));
    assert_eq!(pjuri.message().as_deref(), Some("Donation for xyz"));

    pjuri.set_amount(Amount::from_sat(10_000));
    assert_eq!(pjuri.amount(), Some(Amount::from_sat(10_000)));
}

#[test]
fn require_network_reports_a_payjoin_error() {
    let err: UriParseError = Uri::try_from(NO_PJ)
        .expect("valid BIP 21 uri")
        .require_network(Network::Testnet)
        .expect_err("mainnet address must not satisfy testnet");
    assert!(!err.to_string().is_empty());
}

#[test]
fn check_pj_supported_hands_back_a_payjoin_uri() {
    // The unsupported branch returns payjoin's own URI, boxed, so the caller keeps a usable
    // value without ever naming a foreign type. It round-trips back to the input.
    let returned: Box<Uri<NetworkChecked>> = Uri::try_from(NO_PJ)
        .expect("valid BIP 21 uri")
        .assume_checked()
        .check_pj_supported()
        .expect_err("this uri has no pj parameter");
    assert_eq!(returned.to_string(), NO_PJ);
}
