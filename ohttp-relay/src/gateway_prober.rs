use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap};
use std::error::Error;
use std::io::{ErrorKind, Read};
use std::time::Duration;

use byteorder::{BigEndian, ReadBytesExt};
use bytes::BytesMut;
use futures::future::{self, FutureExt};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::sync::{oneshot, RwLock};
use tokio::time::Instant;

use crate::gateway_uri::GatewayUri;

// these are only pub for the integration test
pub const MAGIC_BIP77_PURPOSE: &[u8] = b"BIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e";
pub const ALLOWED_PURPOSES_CONTENT_TYPE: &str = "application/x-ohttp-allowed-purposes";
const DEFAULT_CAPACITY: usize = 1000;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) struct Policy {
    pub(crate) bip77_allowed: bool,
    pub(crate) expires: Instant,
}

impl Policy {
    fn always(bip77_allowed: bool) -> Self {
        // Rationale for thirty years is same as tokio's Instant::far_future,
        // this value is portable and will not overflow for foreseeable future
        const THIRTY_YEARS: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);
        let expires = Instant::now() + THIRTY_YEARS;
        Self { bip77_allowed, expires }
    }
}

#[derive(Debug)]
enum Status {
    InFlight(future::Shared<oneshot::Receiver<Policy>>),
    Known(Policy),
}

#[derive(Default, Debug)]
pub(crate) struct Prober {
    gateways: RwLock<KnownGateways>,
    ttl_config: TTLConfig,
    client: super::HttpClient,
}

#[derive(Debug)]
struct KnownGateways {
    capacity: usize,
    by_url: HashMap<GatewayUri, Status>,
    by_expiry: BinaryHeap<HeapEntry>,
}

#[derive(PartialEq, Eq, Debug)]
struct HeapEntry {
    expires: Instant,
    key: GatewayUri,
}

impl Ord for HeapEntry {
    /// Reverse ordering by expires for min-heap semantics
    fn cmp(&self, other: &Self) -> Ordering { Reverse(self.expires).cmp(&Reverse(other.expires)) }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Default for KnownGateways {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            by_url: HashMap::default(),
            by_expiry: BinaryHeap::default(),
        }
    }
}

impl KnownGateways {
    fn get(&mut self, url: &GatewayUri) -> Option<&Status> {
        // eager pruning because the borrow checker gets upset by the commented
        // out lazy version below
        self.prune();

        let status = self.by_url.get(url);

        // if let Some(GatewayStatus::Known(policy)) = status {
        //    status = None; // does not appease borrow checker
        //    if !policy.expires.elapsed().is_zero() {
        //        self.prune();
        //        return None;
        //    }
        // }

        status
    }

    fn prune(&mut self) {
        debug_assert!(self.by_expiry.len() <= self.by_url.len());
        while let Some(entry) = self.by_expiry.peek() {
            if entry.expires.elapsed().is_zero() {
                break;
            }

            self.by_url.remove(&entry.key);
            self.by_expiry.pop();
        }
        debug_assert!(self.by_expiry.len() <= self.by_url.len());
    }

    fn has_capacity(&mut self) -> bool {
        self.prune();

        self.by_url.len() < self.capacity
    }

    fn no_capacity_for(&mut self) -> Duration {
        if self.has_capacity() {
            return Duration::ZERO;
        }

        self.by_expiry
            .peek()
            .map(|e| e.expires.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::ZERO)
    }

    fn allocate_in_flight(&mut self, uri: &GatewayUri) -> Option<oneshot::Sender<Policy>> {
        if !self.has_capacity() {
            return None;
        }

        if self.by_url.contains_key(uri) {
            return None;
        }

        let (sender, receiver) = oneshot::channel::<Policy>();
        _ = self.by_url.insert(uri.clone(), Status::InFlight(receiver.shared()));

        Some(sender)
    }

    fn insert(&mut self, url: &GatewayUri, policy: Policy) -> Option<()> {
        // could use try_insert()? but that's an unstable feature
        // we want to avoid duplicate insertions because updating TTL requires
        // scanning the heap, or having multiple heap entries per key, which
        // complicates things unnecessarily.
        // however if the existing entry is inflight, that can and should be
        // overwritten exactly once.
        if let Some(Status::Known(_)) = self.by_url.get(url) {
            return None;
        }

        debug_assert!(self.by_expiry.len() <= self.by_url.len());

        // a more robust approach might be to keep the sender in the map as
        // well, send() to it here, and ensure that it is the right interface,
        // this should be possible since oneshot does not require the sender to
        // be async so that should be possible, but still requires using this
        // method externally.
        // making the entries some kind of atomic pointer implementing the
        // equivalent of a haskell LVar can ensure that the state machine per
        // entry is always inflight -> inserted, but that seems much more
        // complex, so instead we just overwrite any existing entry and tolerate
        // inflight ones not being in the map for simplicity.
        _ = self.by_url.insert(url.clone(), Status::Known(policy));
        self.by_expiry.push(HeapEntry { expires: policy.expires, key: url.clone() });

        Some(())
    }
}

impl Prober {
    pub(crate) fn new_with_client(client: super::HttpClient) -> Self {
        Self { client, ..Self::default() }
    }

    /// Permanently mark a gateway authority as allowed.
    pub(crate) async fn assert_opt_in(&self, url: &GatewayUri) -> Option<()> {
        let mut locked_map = self.gateways.write().await;
        locked_map.insert(url, Policy::always(true))
    }

    /// Check whether a gateway is allowed. If the policy is not known,
    /// the gateway will be probed.
    pub(crate) async fn check_opt_in(&self, url: &GatewayUri) -> Option<Policy> {
        let inflight = {
            let mut locked_map = self.gateways.write().await;
            match locked_map.get(url) {
                Some(Status::Known(policy)) => return Some(*policy),
                Some(Status::InFlight(receiver)) => Ok(receiver.clone()),
                None => {
                    // Only actually query the url if this is the first
                    // lookup and the map is not over capacity
                    let sender = locked_map.allocate_in_flight(url)?;
                    Err(sender)
                }
            }
        };

        Some(match inflight {
            Ok(receiver) => receiver.await.expect("probe task should never be dropped"),
            Err(sender) => {
                let policy = self.probe(url).await;

                {
                    let mut locked_map = self.gateways.write().await;
                    locked_map.insert(url, policy);
                }

                _ = sender.send(policy);

                policy
            }
        })
    }

    async fn is_explicit_opt_in(res: &mut hyper::Response<Incoming>) -> Option<()> {
        if res.status() != hyper::StatusCode::OK {
            return None;
        }

        let mut body = BytesMut::new();
        while let Some(next) = res.frame().await {
            let frame = next.ok()?;
            if let Some(chunk) = frame.data_ref() {
                body.extend_from_slice(chunk)
            }
        }

        if res.headers().get(hyper::header::CONTENT_TYPE)?
            != hyper::header::HeaderValue::from_static(ALLOWED_PURPOSES_CONTENT_TYPE)
        {
            return None;
        }

        let allowed_purposes = parse_alpn_encoded(&body).ok()?;
        if allowed_purposes.contains(&MAGIC_BIP77_PURPOSE.to_vec()) {
            return Some(());
        }

        None
    }

    /// Probes a target gateway by attempting to send a GET request.
    async fn probe(&self, base_url: &GatewayUri) -> Policy {
        // Create a GET request without a body
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(base_url.probe_url())
            .body(http_body_util::combinators::BoxBody::<bytes::Bytes, hyper::Error>::new(
                http_body_util::Empty::new().map_err(|_| {
                    panic!("infallible error type should never produce an actual error to map")
                }),
            ))
            .expect("creating GET request must succeed");

        let mut res = self.client.request(req).await;

        // opt-in is tracked via a separate mutable variable since it only
        // occurs in the first sub-branch of this large conditional, which is
        // largely concerned with determining the TTL
        let mut bip77_allowed = false;

        let ttls = &self.ttl_config;
        let ttl = match &mut res {
            Ok(res) => {
                // TODO handle Cache-Control
                let status = res.status();

                if status.is_success() {
                    bip77_allowed = Self::is_explicit_opt_in(res).await.is_some();

                    if bip77_allowed {
                        ttls.opt_in
                    } else {
                        ttls.http_2xx
                    }
                } else if status == hyper::StatusCode::GATEWAY_TIMEOUT {
                    ttls.http_504_gateway_timeout
                } else if status.is_client_error() {
                    // TODO handle Retry-After for 429 too many requests
                    ttls.http_4xx
                } else if status.is_server_error() {
                    // TODO handle Retry-After for 503 service unavailable
                    ttls.http_5xx
                } else {
                    ttls.default
                }
            }
            Err(err) => {
                if let Some(io_error) =
                    err.source().and_then(|source| source.downcast_ref::<std::io::Error>())
                {
                    match io_error.kind() {
                        ErrorKind::NotFound => ttls.dns,
                        ErrorKind::TimedOut => ttls.timedout,
                        ErrorKind::ConnectionReset => ttls.reset_by_peer,
                        _ => ttls.default,
                    }
                } else {
                    ttls.default
                }
            }
        };

        Policy { bip77_allowed, expires: Instant::now() + ttl }
    }

    pub(crate) async fn unavailable_for(&self) -> Duration {
        let mut locked_map = self.gateways.write().await;
        locked_map.no_capacity_for()
    }
}

fn parse_alpn_encoded(input: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
    let mut input = input;
    let mut output: Vec<Vec<u8>> = Vec::with_capacity(input.read_u16::<BigEndian>()?.into());

    while output.capacity() != output.len() {
        let mut buf = vec![0u8; input.read_u8()?.into()];
        input.read_exact(&mut buf)?;
        output.push(buf);
    }

    if !input.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected trailing data",
        ));
    }

    Ok(output)
}

#[derive(Debug)]
struct TTLConfig {
    /// Explicit opt-in, defaults to LONG.
    opt_in: Duration,

    // everything else is an opt-out
    /// Any other 2xx response, for example ohttp-keys which indicate no
    /// opt-in. Defaults to LONG to avoid spamming servers.
    http_2xx: Duration,
    /// Any 4xx response, for example 404. Defaults to LONG to avoid
    /// spamming servers.
    http_4xx: Duration,
    /// TTL for 504 gateway timeout. Defaults to NONE assuming that is transient.
    http_504_gateway_timeout: Duration,
    /// Any other 5xx response, for example internal server error. Defaults to
    /// SHORT.
    http_5xx: Duration,

    // io errors, should be ephemeral
    ///  TTL for host not found. Defaults to NONE assuming host name resolution and/or DNS resolver cache negative results.
    dns: Duration,
    ///  TTL for reset by peer errors. Defaults to NONE as that is transient.
    reset_by_peer: Duration,
    ///  TTL for tcp timeout. Defaults to NONE as that is transient.
    timedout: Duration,

    /// For other errors, default to SHORT enforce rudimentary rate limiting
    default: Duration,
}

/// Different probing results/conditions and the time to live when caching that
/// information.
impl Default for TTLConfig {
    fn default() -> Self {
        /// A week
        const LONG: Duration = Duration::from_secs(7 * 24 * 60 * 60);
        /// 5 seconds
        const SHORT: Duration = Duration::from_secs(5);
        /// 0 seconds
        const NONE: Duration = Duration::ZERO;

        Self {
            opt_in: LONG,
            http_2xx: LONG,
            http_4xx: LONG,
            http_504_gateway_timeout: NONE,
            http_5xx: SHORT,
            dns: NONE,
            reset_by_peer: NONE,
            timedout: NONE,
            default: SHORT,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use mockito::Server;
    use tokio::time::advance;

    use super::*;
    use crate::gateway_uri::RFC_9540_GATEWAY_PATH;

    const BIP77_OPT_IN_RESPONSE: &[u8] = b"\x00\x01\x2aBIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e";
    const TIMESTEP: Duration = Duration::from_secs(1); // only used with advance()
    const EPSILON: Duration = Duration::from_millis(1); // only used with advance()

    #[tokio::test(start_paused = true)]
    async fn test_known_gateways() {
        let mut db = KnownGateways::default();

        db.capacity = 1;

        let url = GatewayUri::from_static("https://payjo.in");

        assert!(db.has_capacity(), "known gateway set should be empty");
        assert!(db.no_capacity_for().is_zero(), "capacity should be available right now");
        assert!(db.get(&url).is_none(), "mock gateway should not yet be known");

        let policy = Policy { bip77_allowed: true, expires: Instant::now() + TIMESTEP };

        // see comment in implementation of insert(), arguably this should not
        // be allowed as the state machine should start with inflight, but this
        // behavior is simpler and given that's what's implemented it should be
        // tested.
        assert!(db.insert(&url, policy).is_some(), "insertion of gateway policy should succeed");
        if let Some(Status::Known(got)) = db.get(&url) {
            assert_eq!(*got, policy, "initially inserted policy should be retrievable");
        } else {
            panic!("initially inserted policy should be retrievable");
        }

        // No overwriting
        assert!(
            db.allocate_in_flight(&url).is_none(),
            "allocating inflight future for known gateway should fail"
        );
        assert!(
            db.insert(&url, Policy { bip77_allowed: false, expires: Instant::now() + TIMESTEP })
                .is_none(),
            "inserting a duplicate policy entry should fail"
        );
        if let Some(Status::Known(got)) = db.get(&url) {
            assert_eq!(*got, policy, "initially inserted policy should be retrievable");
        } else {
            panic!("initially inserted policy should be retrievable");
        }

        // Pruning
        assert!(!db.has_capacity(), "known gateway set should be at capacity");
        assert!(
            !db.no_capacity_for().is_zero(),
            "next capacity availability should be in the future"
        );
        advance(TIMESTEP + EPSILON).await;
        assert!(db.has_capacity(), "after waiting for expiry capacity should be available");
        assert!(db.no_capacity_for().is_zero(), "capacity should be available right now",);

        // Insert expired
        assert!(
            db.insert(&url, Policy { bip77_allowed: false, expires: Instant::now() }).is_some(),
            "inserting an expired entry should not fail"
        );
        assert!(
            db.get(&url).is_some(),
            "inserted expired entry should be retrievable in same instant"
        );
        advance(EPSILON).await;
        assert!(db.get(&url).is_none(), "inserted expired entry should not be retrievable");
        assert!(
            db.has_capacity(),
            "after inserting expired entry capacity should still be available"
        );

        let inflight =
            db.allocate_in_flight(&url).expect("allocating inflight entry should succeed");

        if let Some(Status::InFlight(got)) = db.get(&url) {
            assert!(got.peek().is_none(), "inflight entry future should still be pending");

            inflight.send(policy).expect("oneshot channel should accept a value");

            assert_eq!(
                got.clone().await.expect("inflight future should have been resolved"),
                policy
            );
        } else {
            panic!("inflight entry should be retrievable");
        }

        // Upgrade in-flight to known entry... this too kind of violates encapsulation
        assert!(
            !db.has_capacity(),
            "with an inflight entry, known gateway set should be at capacity"
        );
        assert!(
            db.insert(&url, Policy { bip77_allowed: true, expires: Instant::now() + TIMESTEP })
                .is_some(),
            "inserting known entry to overwrite inflight one should succeed even at capacity"
        );

        // Test heap behavior
        assert!(!db.has_capacity(), "after inserting known entry set should still be at capacity");
        assert!(
            !db.no_capacity_for().is_zero(),
            "and next capacity availability should be in the future"
        );
        db.capacity = 2;
        assert!(db.has_capacity(), "after raising limit, set should no longer be at capacity");
        assert!(db.no_capacity_for().is_zero(), "capacity should be available right now",);

        let url_2 = GatewayUri::from_static("https://payspl.it");

        assert!(db.get(&url).is_some(), "previously inserted entry should still be in the set");
        assert!(db.get(&url_2).is_none(), "unknown entry should not be in the set");

        assert!(
            db.insert(
                &url_2,
                Policy { bip77_allowed: false, expires: Instant::now() + (2 * TIMESTEP) }
            )
            .is_some(),
            "inserting second entry should succeed"
        );
        assert!(!db.has_capacity(), "after insertion gateway set should be at capacity");

        assert!(db.get(&url).is_some(), "retrieving initially inserted entry should succeed");
        assert!(db.get(&url_2).is_some(), "retrieving second inserted entry should succeed");

        advance(TIMESTEP + EPSILON).await;

        assert!(db.get(&url).is_none(), "after delay initially inserted entry should have expired");
        assert!(db.get(&url_2).is_some(), "second inserted entry should still be retrievable");

        assert!(db.has_capacity(), "after expiry, capacity should be available");
        db.capacity = 1;
        assert!(
            !db.has_capacity(),
            "after reducing the limit capacity should no longer be available"
        );

        advance(TIMESTEP + EPSILON).await;
        assert!(
            db.has_capacity(),
            "after waiting for 2nd entry to expire, capacity should be available again"
        );
        assert!(db.no_capacity_for().is_zero(), "capacity should be available right now");

        assert!(db.get(&url).is_none(), "initial entry should have expired");
        assert!(db.get(&url_2).is_none(), "second entry should have expired");
    }

    #[tokio::test]
    async fn test_mock_opt_in() {
        let mut server = Server::new_async().await;
        let url =
            GatewayUri::from_str(&server.url()).expect("must be able to parse mock server URL");

        let prober = Prober::default();

        let mock_opt_in = server
            .mock("GET", RFC_9540_GATEWAY_PATH)
            .match_query(mockito::Matcher::Regex("^allowed_purposes$".into()))
            .with_header(hyper::header::CONTENT_TYPE.as_str(), ALLOWED_PURPOSES_CONTENT_TYPE)
            .with_body(BIP77_OPT_IN_RESPONSE)
            .create();

        // test happy path
        let status = prober.check_opt_in(&url).await.expect("probing must succeed");
        assert!(status.bip77_allowed, "mock gateway opt-in should have been detected");
        mock_opt_in.assert();
        drop(mock_opt_in);

        // test cached result, mockit server will cause failure if another GET query is sent
        let status = prober.check_opt_in(&url).await.expect("second probe must succeed");
        assert!(status.bip77_allowed, "gateway opt-in should be cached");
    }

    #[tokio::test]
    async fn test_assert_opt_in() {
        // no mock handlers, so any request should fail
        let server = Server::new_async().await;
        let url =
            GatewayUri::from_str(&server.url()).expect("must be able to parse mock server URL");

        let prober = Prober::default();

        prober.assert_opt_in(&url).await.expect("asserting opt in should succeed");
        assert!(
            prober.assert_opt_in(&url).await.is_none(),
            "asserting opt in a second time should fail"
        );

        // test happy path
        let status = prober.check_opt_in(&url).await.expect("probing must succeed");
        assert!(status.bip77_allowed, "asserte opt-in should be cached");
    }

    #[tokio::test]
    async fn test_mock_no_opt_in() {
        let mut server = Server::new_async().await;
        let url =
            GatewayUri::from_str(&server.url()).expect("must be able to parse mock server URL");

        let prober = Prober::default();

        let mock_only_rfc_9540 = server
            .mock("GET", RFC_9540_GATEWAY_PATH)
            .match_query(mockito::Matcher::Regex("^allowed_purposes$".into()))
            .with_header(hyper::header::CONTENT_TYPE.as_str(), "application/ohttp-keys")
            .with_body(b"\x00") // note: not actually a valid ohttp-keys encoding
            .create();

        let status = prober.check_opt_in(&url).await.expect("probing must succeed");
        mock_only_rfc_9540.assert();
        assert!(
            !status.bip77_allowed,
            "RFC 9540 gateway which doesn't signal should not be considered opted-in"
        );
    }

    #[tokio::test]
    async fn test_mock_404() {
        let mut server = Server::new_async().await;
        let url =
            GatewayUri::from_str(&server.url()).expect("must be able to parse mock server URL");

        let prober = Prober::default();

        let mock_not_found = server
            .mock("GET", RFC_9540_GATEWAY_PATH)
            .match_query(mockito::Matcher::Regex("^allowed_purposes$".into()))
            .with_status(404)
            .with_body("not found")
            .create();

        let status = prober.check_opt_in(&url).await.expect("probing must succeed");
        mock_not_found.assert();
        assert!(!status.bip77_allowed, "non-existent gateway should not be considered opt-in");
    }

    #[tokio::test]
    async fn test_inflight_deduplication() {
        let mut server = Server::new_async().await;
        let url =
            GatewayUri::from_str(&server.url()).expect("must be able to parse mock server URL");

        let prober = Prober::default();

        let counter = Arc::new(Mutex::new(0));
        let condvar = Arc::new(std::sync::Condvar::new());
        let cvmutex = Arc::new(Mutex::new(false));

        let mock_delayed = {
            let counter = counter.clone();
            let condvar = condvar.clone();
            let cvmutex = cvmutex.clone();

            server
                .mock("GET", RFC_9540_GATEWAY_PATH)
                .match_query(mockito::Matcher::Regex("^allowed_purposes$".into()))
                .with_header(hyper::header::CONTENT_TYPE.as_str(), ALLOWED_PURPOSES_CONTENT_TYPE)
                .with_chunked_body(move |w| {
                    // track how many requests have been received
                    let mut c = counter.lock().unwrap();
                    *c += 1;

                    // wait until both probe tasks were started
                    let mut guard = cvmutex.lock().unwrap();
                    while !*guard {
                        guard = condvar.wait(guard).unwrap();
                    }

                    w.write_all(BIP77_OPT_IN_RESPONSE)
                })
                .create()
        };

        let check_a = prober.check_opt_in(&url);
        let check_b = prober.check_opt_in(&url);

        let ensure_both_inflight = async {
            // wait until both probe tasks are in flight
            loop {
                std::thread::yield_now();
                let mut guard = prober.gateways.write().await;
                if let Some(Status::InFlight(fut)) = guard.get(&url) {
                    if fut.strong_count().expect("inflight future should not yet be resolved") == 2
                    {
                        break;
                    }
                }

                // avoid spinlock, let probe tasks make progress
                tokio::time::sleep(Duration::from_micros(10)).await;
            }

            // release the server
            {
                let mut guard = cvmutex.lock().unwrap();
                *guard = true; // Set the condition to true
            }
            condvar.notify_one();
        };

        let (a, b, _) = tokio::join!(check_a, check_b, ensure_both_inflight);

        mock_delayed.assert();
        assert!(
            a.expect("probe must succeed").bip77_allowed,
            "first concurrent request should detect opt-in"
        );
        assert!(
            b.expect("probe must succeed").bip77_allowed,
            "second concurrent request should detect opt-in"
        );
        assert_eq!(*counter.lock().unwrap(), 1, "requests should have been deduplicated");
    }

    #[test]
    fn test_parse_alpn_encoded() {
        let result = parse_alpn_encoded(b"");
        assert!(result.is_err(), "empty string should not be valid");

        let result = parse_alpn_encoded(b"\x00");
        assert!(result.is_err(), "null byte should not be valid");

        let result = parse_alpn_encoded(b"\x00\x00");
        assert_eq!(
            result.expect("a list of length 0 should parse without error").len(),
            0,
            "empty list should have len 0"
        );

        let result = parse_alpn_encoded(b"\x00\x00\x00");
        assert!(result.is_err(), "trailing data should be invalid");

        let result = parse_alpn_encoded(b"\x00\x01");
        assert!(result.is_err(), "a truncated list of length 1 should be invalid");

        let result = parse_alpn_encoded(b"\x00\x01\x00")
            .expect("a list with one empty element should parse without error");
        assert_eq!(result.len(), 1, "should contain 1 element");
        assert_eq!(result[0].len(), 0, "the single element should be of length 0");

        let result = parse_alpn_encoded(b"\x00\x01\x01a")
            .expect("a list with one element of length 1 should parse without error");
        assert_eq!(result.len(), 1, "should contain 1 element");
        assert_eq!(result[0].len(), 1, "element length should be 1");
        assert_eq!(result[0][0], b'a', "the element value should be the single byte 'a'");

        let result = parse_alpn_encoded(b"\x00\x02\x01\x00\x00")
            .expect("list with two elements should parse correctly");
        assert_eq!(result.len(), 2, "two element list should be valid");
        assert_eq!(result[0].len(), 1, "the first element should be a 1 byte long");
        assert_eq!(result[0][0], 0, "the first element should be a null byte");
        assert_eq!(result[1].len(), 0, "the second element should be empty");

        let result = parse_alpn_encoded(BIP77_OPT_IN_RESPONSE)
            .expect("stock BIP 77 opt in response should parse correctly");
        assert_eq!(result.len(), 1, "pre canned BIP 77 opt-in response should have 1 element");
        assert_eq!(
            result[0], MAGIC_BIP77_PURPOSE,
            "the element should be the bip77 opt-in magic string"
        );
    }
}
