//! Payjoin URI parsing and validation

use std::fmt;
use std::str::FromStr;

use bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bitcoin::{Address, Amount};
pub use error::{PjParseError, UriParseError};

#[cfg(feature = "v2")]
pub(crate) use crate::directory::ShortId;
use crate::output_substitution::OutputSubstitution;
use crate::uri::error::InternalPjParseError;

mod error;
#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;

/// The `pj` endpoint of a BIP21 URI, parsed into the payjoin version it speaks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[cfg_attr(feature = "v2", allow(clippy::large_enum_variant))]
pub enum PjParam {
    #[cfg(feature = "v1")]
    V1(v1::PjParam),
    #[cfg(feature = "v2")]
    V2(v2::PjParam),
}

impl PjParam {
    pub fn parse(endpoint: impl super::IntoUrl) -> Result<Self, PjParseError> {
        let endpoint = endpoint.into_url().map_err(InternalPjParseError::IntoUrl)?;

        #[cfg(feature = "v2")]
        match v2::PjParam::parse(endpoint.clone()) {
            Err(v2::PjParseError::NotV2) => (), // continue
            Ok(v2) => return Ok(PjParam::V2(v2)),
            Err(e) => return Err(InternalPjParseError::V2(e).into()),
        }

        #[cfg(feature = "v1")]
        return Ok(PjParam::V1(v1::PjParam::parse(endpoint)?));

        #[cfg(all(not(feature = "v1"), feature = "v2"))]
        return Err(InternalPjParseError::V2(v2::PjParseError::NotV2).into());

        #[cfg(all(not(feature = "v1"), not(feature = "v2")))]
        compile_error!("Either v1 or v2 feature must be enabled");
    }

    pub fn endpoint(&self) -> String { self.endpoint_url().to_string() }

    pub(crate) fn endpoint_url(&self) -> crate::core::Url {
        match self {
            #[cfg(feature = "v1")]
            PjParam::V1(url) => url.endpoint(),
            #[cfg(feature = "v2")]
            PjParam::V2(url) => url.endpoint(),
        }
    }
}

impl std::fmt::Display for PjParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // normalizing to uppercase enables QR alphanumeric mode encoding
        // unfortunately Url normalizes these to be lowercase
        let endpoint = &self.endpoint_url();
        let scheme = endpoint.scheme();
        let host = endpoint.host_str();
        let endpoint_str = self
            .endpoint()
            .as_str()
            .replacen(scheme, &scheme.to_uppercase(), 1)
            .replacen(&host, &host.to_uppercase(), 1);
        write!(f, "{endpoint_str}")
    }
}

/// The payjoin parameters of a BIP21 URI, which may not request payjoin at all.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MaybePayjoinExtras {
    Supported(PayjoinExtras),
    Unsupported,
}

impl MaybePayjoinExtras {
    pub fn pj_is_supported(&self) -> bool {
        match self {
            MaybePayjoinExtras::Supported(_) => true,
            MaybePayjoinExtras::Unsupported => false,
        }
    }
}

/// Validated payjoin parameters
#[derive(Debug, Clone)]
pub struct PayjoinExtras {
    /// pj parameter
    pub(crate) pj_param: PjParam,
    /// pjos parameter
    pub(crate) output_substitution: OutputSubstitution,
}

impl PayjoinExtras {
    pub fn pj_param(&self) -> &PjParam { &self.pj_param }
    pub fn endpoint(&self) -> String { self.pj_param.endpoint() }
    pub fn output_substitution(&self) -> OutputSubstitution { self.output_substitution }
}

/// A BIP21 URI that may or may not request payjoin.
///
/// This newtype wraps [`bitcoin_uri::Uri`] so that a breaking change in that
/// crate does not force a breaking change in this crate's public API. Parse one
/// with [`Uri::try_from`] or [`str::parse`], validate the address network with
/// [`assume_checked`](Self::assume_checked) or
/// [`require_network`](Self::require_network), then check for payjoin support
/// with [`check_pj_supported`](Self::check_pj_supported).
///
/// The URI is always owned, so it carries no lifetime parameter. `bitcoin_uri`
/// is a plain tokenizer: it parses the BIP 321 shape and this crate reads the
/// `pj`/`pjos` parameters off it, so the payjoin validation lives here rather
/// than inside the parser.
///
/// # Examples
///
/// Parse a URI, validate its address against the network you are paying on, and check
/// whether it requests payjoin at all:
///
/// ```
/// use payjoin::bitcoin::{Amount, Network};
/// use payjoin::{PjUri, Uri};
///
/// const EXAMPLE_URI: &str = "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?amount=0.02\
///     &pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ\
///     %23EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC\
///     -RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";
///
/// // Parsing leaves the address unchecked: it is not yet tied to a network.
/// let uri = Uri::try_from(EXAMPLE_URI)?;
///
/// // Refuse an address that belongs to another network before paying it.
/// let uri = uri.require_network(Network::Testnet)?;
///
/// // A BIP21 URI need not request payjoin. The error variant hands the plain URI back,
/// // so a caller that gets one can still pay it normally.
/// let pj_uri: PjUri = uri.check_pj_supported().expect("this URI requests payjoin");
///
/// assert_eq!(pj_uri.address().to_string(), "2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7");
/// assert_eq!(pj_uri.amount(), Some(Amount::from_sat(2_000_000)));
/// # Ok::<(), payjoin::UriParseError>(())
/// ```
///
/// See [`PjUri`] for dispatching on the payjoin version and initializing the sender
/// state machine.
#[derive(Clone, Debug)]
pub struct Uri<NetVal: NetworkValidation> {
    inner: bitcoin_uri::Uri<NetVal>,
    extras: MaybePayjoinExtras,
}

impl<NetVal: NetworkValidation> Uri<NetVal> {
    /// The address the URI pays to.
    pub fn address(&self) -> &Address<NetVal> {
        self.inner.body().expect("a payjoin BIP21 URI always carries an address")
    }

    /// The amount the URI requests, if any.
    pub fn amount(&self) -> Option<Amount> { self.inner.amount() }

    /// The label describing the URI, if present and valid UTF-8.
    pub fn label(&self) -> Option<String> { self.inner.label().and_then(Result::ok) }

    /// The message describing the URI, if present and valid UTF-8.
    pub fn message(&self) -> Option<String> { self.inner.message().and_then(Result::ok) }

    /// The payjoin parameters carried by the URI.
    pub fn extras(&self) -> &MaybePayjoinExtras { &self.extras }
}

impl Uri<NetworkUnchecked> {
    /// Marks the URI's address as validated without checking the network.
    pub fn assume_checked(self) -> Uri<NetworkChecked> {
        Uri { inner: self.inner.assume_checked(), extras: self.extras }
    }

    /// Validates that the URI's address is valid for the given network.
    pub fn require_network(
        self,
        network: bitcoin::Network,
    ) -> Result<Uri<NetworkChecked>, UriParseError> {
        let extras = self.extras;
        let inner = self.inner.require_network(network).map_err(UriParseError::from_network)?;
        Ok(Uri { inner, extras })
    }
}

impl Uri<NetworkChecked> {
    /// Converts this URI into a [`PjUri`] if it supports payjoin.
    ///
    /// If payjoin is unsupported the URI is handed back unchanged in the error
    /// variant. It is boxed to reduce the size of the `Result` (see
    /// <https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err>).
    pub fn check_pj_supported(self) -> Result<PjUri, Box<Self>> {
        match self.extras {
            MaybePayjoinExtras::Supported(extras) => {
                // Rebuild the inner URI so its parameters are emitted in this
                // crate's canonical order (standard BIP21 params, then `pjos`,
                // then `pj`) regardless of the order they were parsed in.
                let address = self
                    .inner
                    .body()
                    .expect("a payjoin BIP21 URI always carries an address")
                    .clone();
                let amount = self.inner.amount();
                let label = self.inner.label().and_then(Result::ok);
                let message = self.inner.message().and_then(Result::ok);
                let inner = build_pj_uri(address, amount, label, message, &extras);
                Ok(PjUri { inner, extras })
            }
            MaybePayjoinExtras::Unsupported => Err(Box::new(self)),
        }
    }
}

impl FromStr for Uri<NetworkUnchecked> {
    type Err = UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner: bitcoin_uri::Uri<NetworkUnchecked> =
            s.parse().map_err(UriParseError::from_bip21)?;
        if inner.body().is_none() {
            return Err(UriParseError::missing_address());
        }
        // BIP 321: a URI with a `req-` parameter we cannot handle MUST be
        // rejected. `bitcoin_uri` only reports these, so enforce it here.
        if let Some(entry) = inner.unsatisfied_requirements(UNDERSTOOD_PARAMS).next() {
            return Err(UriParseError::unsatisfied_requirement(entry.key.clone()));
        }
        let extras = parse_payjoin_extras(&inner)?;
        Ok(Uri { inner, extras })
    }
}

impl TryFrom<&str> for Uri<NetworkUnchecked> {
    type Error = UriParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> { s.parse() }
}

impl TryFrom<String> for Uri<NetworkUnchecked> {
    type Error = UriParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> { s.parse() }
}

impl fmt::Display for Uri<NetworkChecked> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.inner.fmt(f) }
}

/// A BIP21 URI that is known to request payjoin, with validated payjoin parameters.
///
/// Obtained from [`Uri::check_pj_supported`]. Like [`Uri`], this newtype
/// insulates the public API from [`bitcoin_uri`] and is always owned.
///
/// # Examples
///
/// Dispatch on the payjoin version carried by the `pj` parameter, then initialize a BIP 77
/// sender. The [`PjParam`] variant *is* the version; there is no `version()` to call.
///
/// ```
/// use payjoin::bitcoin::{FeeRate, Network};
/// use payjoin::persist::InMemoryPersister;
/// use payjoin::send::v2::SenderBuilder;
/// use payjoin::{PjParam, Uri};
/// # use payjoin_test_utils::PARSED_ORIGINAL_PSBT;
///
/// const EXAMPLE_URI: &str = "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?amount=0.02\
///     &pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ\
///     %23EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC\
///     -RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";
///
/// let pj_uri = Uri::try_from(EXAMPLE_URI)?
///     .require_network(Network::Testnet)?
///     .check_pj_supported()
///     .expect("this URI requests payjoin");
///
/// // The Original PSBT is funded and signed already; a real sender builds it with its
/// // own wallet.
/// let psbt = PARSED_ORIGINAL_PSBT.clone();
///
/// match pj_uri.extras().pj_param() {
///     PjParam::V2(pj_param) => {
///         // A real integration supplies its own `SessionPersister` instead.
///         let persister = InMemoryPersister::default();
///         let _sender =
///             SenderBuilder::from_parts(psbt, pj_param, pj_uri.address(), pj_uri.amount())
///                 .build_recommended(FeeRate::BROADCAST_MIN)?
///                 .save(&persister)?;
///         // `_sender` is a `Sender<WithReplyKey>`: call `create_v2_post_request` next.
///     }
///     // A BIP 78 (v1) endpoint cannot be paid by a v2 sender. Real senders fall back to
///     // `send::v1` here; the example URI is BIP 77, so this arm is unreachable.
///     _ => unreachable!("example URI carries a BIP 77 endpoint"),
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct PjUri {
    inner: bitcoin_uri::Uri<NetworkChecked>,
    extras: PayjoinExtras,
}

impl PjUri {
    /// Builds a payjoin URI from a checked address and validated payjoin parameters.
    pub(crate) fn from_extras(address: Address<NetworkChecked>, extras: PayjoinExtras) -> Self {
        let inner = build_pj_uri(address, None, None, None, &extras);
        PjUri { inner, extras }
    }

    /// The address the URI pays to.
    pub fn address(&self) -> &Address<NetworkChecked> {
        self.inner.body().expect("a payjoin BIP21 URI always carries an address")
    }

    /// The amount the URI requests, if any.
    pub fn amount(&self) -> Option<Amount> { self.inner.amount() }

    /// Sets the amount the URI requests.
    pub fn set_amount(&mut self, amount: Amount) {
        self.inner = build_pj_uri(
            self.address().clone(),
            Some(amount),
            self.label(),
            self.message(),
            &self.extras,
        );
    }

    /// The label describing the URI, if present and valid UTF-8.
    pub fn label(&self) -> Option<String> { self.inner.label().and_then(Result::ok) }

    /// The message describing the URI, if present and valid UTF-8.
    pub fn message(&self) -> Option<String> { self.inner.message().and_then(Result::ok) }

    /// The validated payjoin parameters carried by the URI.
    pub fn extras(&self) -> &PayjoinExtras { &self.extras }
}

impl fmt::Display for PjUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.inner.fmt(f) }
}

/// The extension parameters this crate handles, so `req-pj` and `req-pjos`
/// are accepted while any other `req-` parameter rejects the URI.
const UNDERSTOOD_PARAMS: &[&str] = &["pj", "pjos"];

/// Serializes the payjoin BIP21 query parameters (`pj` and optional `pjos`).
fn serialize_payjoin_params(extras: &PayjoinExtras) -> Vec<(&'static str, String)> {
    let mut params = Vec::with_capacity(2);
    if extras.output_substitution == OutputSubstitution::Disabled {
        params.push(("pjos", String::from("0")));
    }
    params.push(("pj", extras.pj_param.to_string()));
    params
}

/// Reads and validates the `pj`/`pjos` parameters off a parsed BIP 321 URI.
///
/// `bitcoin_uri` hands back the raw parameters without interpreting them, so
/// the payjoin-specific validation (endpoint parsing, `pjos` values, the
/// no-duplicate and `pjos`-without-`pj` rules) is done here.
fn parse_payjoin_extras<V: NetworkValidation>(
    uri: &bitcoin_uri::Uri<V>,
) -> Result<MaybePayjoinExtras, PjParseError> {
    let pj = at_most_one(uri, "pj")?;
    let pjos_entry = at_most_one(uri, "pjos")?;

    let pjos = match pjos_entry {
        Some(entry) => {
            let value = decoded(entry).ok_or(InternalPjParseError::BadPjOs)?;
            match value.as_str() {
                "0" => Some(OutputSubstitution::Disabled),
                "1" => Some(OutputSubstitution::Enabled),
                _ => return Err(InternalPjParseError::BadPjOs.into()),
            }
        }
        None => None,
    };

    match (pj, pjos) {
        (None, None) => Ok(MaybePayjoinExtras::Unsupported),
        (None, Some(_)) => Err(InternalPjParseError::MissingEndpoint.into()),
        (Some(entry), pjos) => {
            let endpoint = decoded(entry).ok_or(InternalPjParseError::NotUtf8)?;
            let pj_param = PjParam::parse(endpoint.as_str())?;
            Ok(MaybePayjoinExtras::Supported(PayjoinExtras {
                pj_param,
                output_substitution: pjos.unwrap_or(OutputSubstitution::Enabled),
            }))
        }
    }
}

/// The single parameter with base key `key`, or an error if it repeats.
fn at_most_one<'a, V: NetworkValidation>(
    uri: &'a bitcoin_uri::Uri<V>,
    key: &'static str,
) -> Result<Option<&'a bitcoin_uri::ParamEntry>, PjParseError> {
    let mut matches = uri.get_all(key);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(InternalPjParseError::DuplicateParams(key).into());
    }
    Ok(first)
}

/// Percent-decodes a parameter value to a UTF-8 string, or `None` if it is
/// value-less or not valid UTF-8.
fn decoded(entry: &bitcoin_uri::ParamEntry) -> Option<String> {
    entry.decoded_value().and_then(Result::ok)
}

/// Assembles a checked payjoin `bitcoin_uri::Uri` from its parts.
///
/// The address is already checked and the payjoin params always encode, so
/// the build never fails.
fn build_pj_uri(
    address: Address<NetworkChecked>,
    amount: Option<Amount>,
    label: Option<String>,
    message: Option<String>,
    extras: &PayjoinExtras,
) -> bitcoin_uri::Uri<NetworkChecked> {
    let mut builder = bitcoin_uri::UriBuilder::new().address(address);
    if let Some(amount) = amount {
        builder = builder.amount(amount);
    }
    if let Some(label) = &label {
        builder = builder.label(label);
    }
    if let Some(message) = &message {
        builder = builder.message(message);
    }
    for (key, value) in serialize_payjoin_params(extras) {
        builder = builder.param(key, &value);
    }
    builder.build().expect("a checked address and valid payjoin params always build")
}

#[cfg(all(test, feature = "v1"))]
pub(crate) fn pj_uri(uri: &str) -> PjUri {
    Uri::try_from(uri)
        .expect("uri should parse")
        .assume_checked()
        .check_pj_supported()
        .expect("uri should support payjoin")
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn test_short() {
        assert!(Uri::try_from("").is_err());
        assert!(Uri::try_from("bitcoin").is_err());
        assert!(Uri::try_from("bitcoin:").is_err());
    }

    #[ignore]
    #[test]
    fn test_todo_url_encoded() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        assert!(Uri::try_from(uri).is_err(), "pj url should be url encoded");
    }

    #[test]
    fn test_valid_url() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=this_is_NOT_a_validURL";
        assert!(Uri::try_from(uri).is_err(), "pj is not a valid url");
    }

    #[test]
    fn test_unencrypted() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");

        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=ftp://foo.onion";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");
    }

    #[test]
    fn test_unsupported() {
        assert!(
            !Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
                .unwrap()
                .extras()
                .pj_is_supported(),
            "Uri expected a failure with missing pj extras, but it succeeded"
        );
    }

    #[test]
    fn test_pj_and_pjos_round_trip() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ%23EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";
        let pjuri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        let params = serialize_payjoin_params(pjuri.extras());
        assert_eq!(params.last().expect("pj key").0, "pj");
        // pjos=1 is the default (output substitution enabled), so it is not
        // re-serialized.
        assert!(params.iter().all(|(key, _)| *key != "pjos"));
    }

    /// Tests pinning how this crate consumes `bitcoin_uri`'s BIP 321
    /// tokenizer: which URIs it must reject, and that whatever it accepts
    /// re-serializes to one canonical form.
    mod bip321 {
        use super::*;

        const ADDRESS: &str = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        /// A v2 endpoint, which also parses as a plain https v1 endpoint,
        /// so these tests run under either feature.
        const PJ: &str = "HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ\
                          %23EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC\
                          -RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

        fn uri(query: &str) -> String { format!("bitcoin:{ADDRESS}?{query}") }

        fn parse_pj(s: &str) -> PjUri {
            Uri::try_from(s)
                .unwrap_or_else(|e| panic!("{s} should parse: {e}"))
                .assume_checked()
                .check_pj_supported()
                .unwrap_or_else(|_| panic!("{s} should support payjoin"))
        }

        fn assert_same_payment(a: &PjUri, b: &PjUri) {
            assert_eq!(a.address(), b.address());
            assert_eq!(a.amount(), b.amount());
            assert_eq!(a.label(), b.label());
            assert_eq!(a.message(), b.message());
            assert_eq!(a.extras().endpoint(), b.extras().endpoint());
            assert_eq!(a.extras().output_substitution(), b.extras().output_substitution());
        }

        /// Every ordering of `items`, by Heap's algorithm.
        fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
            fn heap<T: Clone>(k: usize, items: &mut Vec<T>, out: &mut Vec<Vec<T>>) {
                if k <= 1 {
                    out.push(items.clone());
                    return;
                }
                for i in 0..k {
                    heap(k - 1, items, out);
                    let j = if k % 2 == 0 { i } else { 0 };
                    items.swap(j, k - 1);
                }
            }
            let mut out = Vec::new();
            heap(items.len(), &mut items.to_vec(), &mut out);
            out
        }

        #[test]
        fn rejects_unsatisfied_required_params() {
            // BIP 321: a client MUST reject a URI with a req- param it does
            // not understand, whether or not it requests payjoin.
            for query in [
                "req-foo=1".to_string(),
                format!("pj={PJ}&req-foo=1"),
                format!("req-sp=sp1qq&pj={PJ}"),
            ] {
                let err =
                    Uri::try_from(uri(&query)).expect_err("unknown req- param must be rejected");
                assert!(err.to_string().contains("req-"), "{query}: unexpected error {err}");
            }
        }

        #[test]
        fn understands_required_payjoin_params() {
            let pjuri = parse_pj(&uri(&format!("req-pj={PJ}")));
            assert_eq!(pjuri.extras().output_substitution(), OutputSubstitution::Enabled);

            let pjuri = parse_pj(&uri(&format!("req-pjos=0&pj={PJ}")));
            assert_eq!(pjuri.extras().output_substitution(), OutputSubstitution::Disabled);

            // `pj` and `req-pj` share a base key, so together they repeat it.
            let err = Uri::try_from(uri(&format!("pj={PJ}&req-pj={PJ}"))).expect_err("pj repeated");
            assert!(err.to_string().contains("Multiple instances of parameter 'pj'"), "{err}");
        }

        #[test]
        fn keys_are_case_insensitive() {
            let lower = parse_pj(&uri(&format!("amount=0.01&pjos=0&pj={PJ}")));
            let upper = parse_pj(&format!("BITCOIN:{ADDRESS}?AMOUNT=0.01&PJOS=0&PJ={PJ}"));
            assert_same_payment(&lower, &upper);
            assert_eq!(lower.to_string(), upper.to_string());

            let err = Uri::try_from(uri(&format!("pj={PJ}&PJ={PJ}"))).expect_err("pj repeated");
            assert!(err.to_string().contains("Multiple instances of parameter 'pj'"), "{err}");
        }

        #[test]
        fn output_is_independent_of_param_order() {
            let params = [
                "amount=0.01".to_string(),
                "label=Coffee%20%26%20cake".to_string(),
                "message=Pay%20in%20%E2%82%BF".to_string(),
                "pjos=0".to_string(),
                format!("pj={PJ}"),
            ];
            let orderings = permutations(&params);
            assert_eq!(orderings.len(), 120);

            let canonical = parse_pj(&uri(&params.join("&")));
            for ordering in orderings {
                let pjuri = parse_pj(&uri(&ordering.join("&")));
                assert_same_payment(&pjuri, &canonical);
                assert_eq!(pjuri.to_string(), canonical.to_string(), "ordering {ordering:?}");
            }
        }

        #[test]
        fn display_is_a_fixpoint() {
            let inputs = [
                uri(&format!("pj={PJ}")),
                uri(&format!("pjos=1&pj={PJ}")),
                uri(&format!("pj={PJ}&amount=21&label=%F0%9F%A5%A9")),
                uri(&format!("message=a+b%2Bc&pj={PJ}")),
                format!("BITCOIN:{ADDRESS}?Label=x&PJ={PJ}&Amount=0.00000001"),
                format!("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?pj={PJ}"),
            ];
            for input in inputs {
                let first = parse_pj(&input);
                let printed = first.to_string();
                let second = parse_pj(&printed);
                assert_same_payment(&first, &second);
                assert_eq!(second.to_string(), printed, "{input} did not settle after one round");
            }
        }

        #[test]
        fn uri_decodes_standard_params_before_pj_check() {
            // The BIP 21 example query: no payjoin, so it stays a plain `Uri`.
            let query = "amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz";
            let parsed = Uri::try_from(uri(query)).unwrap().assume_checked();
            assert_eq!(parsed.amount(), Some(Amount::from_btc(50.0).unwrap()));
            assert_eq!(parsed.label().as_deref(), Some("Luke-Jr"));
            assert_eq!(parsed.message().as_deref(), Some("Donation for project xyz"));
            assert!(!parsed.extras().pj_is_supported());

            // A value that is not UTF-8 reads as absent rather than failing.
            let parsed = Uri::try_from(uri(&format!("label=%FF&message=%C3&pj={PJ}"))).unwrap();
            assert_eq!(parsed.amount(), None);
            assert_eq!(parsed.label(), None);
            assert_eq!(parsed.message(), None);
        }

        #[test]
        fn extension_params_leave_payjoin_alone() {
            let plain = parse_pj(&uri(&format!("pj={PJ}")));
            let unified = parse_pj(&uri(&format!(
                "lightning=lnbc1pvjluezpp5qqqsyq&sp=sp1qqgste7&lno=lno1qcp4&pj={PJ}"
            )));
            assert_eq!(unified.extras().endpoint(), plain.extras().endpoint());
            assert_eq!(
                unified.extras().output_substitution(),
                plain.extras().output_substitution()
            );
        }

        #[test]
        fn requires_an_on_chain_address() {
            // BIP 321 makes the body optional; a payjoin sender needs it.
            let err = Uri::try_from(format!("bitcoin:?pj={PJ}&lightning=lnbc1pvjluezpp5qqqsyq"))
                .expect_err("payjoin needs an address");
            assert!(err.to_string().contains("no on-chain address"), "{err}");
        }

        #[test]
        fn every_network_round_trips() {
            use bitcoin::Network;
            let cases = [
                (ADDRESS, Network::Bitcoin),
                ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Network::Testnet),
                ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Network::Signet),
                ("bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x", Network::Regtest),
            ];
            for (address, network) in cases {
                let input = format!("bitcoin:{address}?amount=1&pj={PJ}");
                let pjuri = Uri::try_from(input.as_str())
                    .unwrap()
                    .require_network(network)
                    .unwrap_or_else(|e| panic!("{address} on {network}: {e}"))
                    .check_pj_supported()
                    .unwrap_or_else(|_| panic!("{input} should support payjoin"));
                let reparsed = Uri::try_from(pjuri.to_string())
                    .unwrap()
                    .require_network(network)
                    .expect("re-serialized URI keeps its network");
                assert_eq!(reparsed.address(), pjuri.address());
            }
        }

        #[test]
        fn reports_network_mismatch() {
            let err = Uri::try_from(uri(&format!("pj={PJ}")))
                .unwrap()
                .require_network(bitcoin::Network::Testnet)
                .expect_err("mainnet address on testnet");
            assert!(err.to_string().contains("Invalid network"), "{err}");
        }

        #[test]
        fn set_amount_keeps_payjoin_params() {
            let mut pjuri = parse_pj(&uri(&format!("label=tip&message=thanks&pjos=0&pj={PJ}")));
            pjuri.set_amount(Amount::from_sat(2_100));

            let reparsed = parse_pj(&pjuri.to_string());
            assert_eq!(reparsed.amount(), Some(Amount::from_sat(2_100)));
            assert_eq!(reparsed.label().as_deref(), Some("tip"));
            assert_eq!(reparsed.message().as_deref(), Some("thanks"));
            assert_eq!(reparsed.extras().output_substitution(), OutputSubstitution::Disabled);
            assert_eq!(reparsed.extras().endpoint(), pjuri.extras().endpoint());
        }
    }
}
