#![no_main]

use std::str;

use libfuzzer_sys::fuzz_target;
// Adjust this path to wherever your Url module lives in your crate.
use payjoin::Url;

fn do_test(data: &[u8]) {
    let Ok(s) = str::from_utf8(data) else { return };

    let Ok(mut url) = Url::parse(s) else { return };

    let _ = url.scheme();
    let _ = url.domain();
    let _ = url.port();
    let _ = url.path();
    let _ = url.query();
    let _ = url.fragment();
    let _ = url.as_str();
    let _ = url.to_string();
    if let Some(segs) = url.path_segments() {
        let _ = segs.collect::<Vec<_>>();
    }

    // Cross-check IPv4/IPv6 parsing against std::net
    let host_str = url.host_str();
    if let Ok(std_addr) = host_str.parse::<std::net::Ipv4Addr>() {
        assert!(url.domain().is_none(), "domain() must be None for IPv4 host");
        let _ = std_addr.octets();
    }
    let bracketed = host_str.trim_start_matches('[').trim_end_matches(']');
    if let Ok(std_addr) = bracketed.parse::<std::net::Ipv6Addr>() {
        assert!(url.domain().is_none(), "domain() must be None for IPv6 host");
        let _ = std_addr.segments();
    }

    let raw = url.as_str().to_owned();
    if let Ok(reparsed) = Url::parse(&raw) {
        assert_eq!(
            reparsed.as_str(),
            raw,
            "round-trip mismatch: first={raw:?} second={:?}",
            reparsed.as_str()
        );
    }

    url.set_port(Some(8080));
    url.set_port(None);
    url.set_fragment(Some("fuzz"));
    url.set_fragment(None);
    url.query_pairs_mut().append_pair("k", "v");
    url.clear_query();
    url.query_pairs_mut().append_pair("fuzz_key", "fuzz_val");

    if let Some(mut segs) = url.path_segments_mut() {
        segs.push("fuzz_segment");
    }

    let _ = url.join("relative/path");
    let _ = url.join("/absolute/path");
    let _ = url.join("../dotdot");
    let _ = url.join("https://other.example.com/new");
}

fuzz_target!(|data| {
    do_test(data);
});
