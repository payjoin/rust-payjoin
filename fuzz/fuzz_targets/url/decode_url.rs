#![no_main]

use std::str;

use libfuzzer_sys::fuzz_target;
// Adjust this path to wherever your Url module lives in your crate.
use payjoin::Url;

fn do_test(data: &[u8]) {
    let Ok(s) = str::from_utf8(data) else { return };

    let Ok(mut url) = Url::parse(s) else { return };

    let _ = url.scheme();
    let _ = url.has_host();
    let _ = url.domain();
    let _ = url.host_str();
    let _ = url.port();
    let _ = url.path();
    let _ = url.query();
    let _ = url.fragment();
    let _ = url.as_str();
    let _ = url.to_string();
    if let Some(segs) = url.path_segments() {
        let _ = segs.collect::<Vec<_>>();
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
    url.set_query(Some("k=v"));
    url.set_query(None);
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
