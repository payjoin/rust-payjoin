#![cfg_attr(feature = "libfuzzer_fuzz", no_main)]

#[cfg(feature = "afl_fuzz")]
use afl::fuzz;
#[cfg(feature = "honggfuzz_fuzz")]
use honggfuzz::fuzz;
#[cfg(feature = "libfuzzer_fuzz")]
use libfuzzer_sys::fuzz_target;

fn do_test(_data: &[u8]) {
    // fuzzed code goes here
}

#[cfg(feature = "afl_fuzz")]
fn main() {
    fuzz!(|data| {
        //do_test(data);
    });
}

#[cfg(feature = "honggfuzz_fuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            //do_test(data);
        });
    }
}

#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|_data: &[u8]| {
    //do_test(data);
});
