#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use payjoin::Url;

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    if let Ok(mut url) = Url::arbitrary(&mut u) {
        if let Ok(port) = u.arbitrary::<Option<u16>>() {
            url.set_port(port);
        }
        if let Ok(fragment) = u.arbitrary::<Option<&str>>() {
            url.set_fragment(fragment);
        }
        if let Ok((key, value)) = u.arbitrary::<(&str, &str)>() {
            url.query_pairs_mut().append_pair(key, value);
            url.clear_query();
        }
        if let Some(mut segs) = url.path_segments_mut() {
            if let Ok(segment) = u.arbitrary::<&str>() {
                segs.push(segment);
            }
        }
        if let Ok(segment) = String::arbitrary(&mut u) {
            let _ = url.join(&segment);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_crash() {
        let data = b"\x00";
        super::do_test(&data[..]);
    }
}
