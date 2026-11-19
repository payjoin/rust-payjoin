# Payjoin-Fuzz

Fuzz tests work by generating a ton of random noise that is morphed into parameter arguments for tests to run and validate that none of it causes unhandled crashes.

## Bootstrapping

This fuzzer uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). To get started, enter the nix dev shell and run the fuzzer:

```shell
nix develop
cd fuzz/
./fuzz.sh
```

## Running fuzzers

The `fuzz.sh` and `cycle.sh` shell scripts allow for single-pass fuzzing and continuous long-term fuzzing respectively.

#### Using `fuzz.sh`

This script accepts an optional fuzz target. It runs all available targets when this option is omitted.

`./fuzz.sh [fuzz-target]`

For example, `./fuzz.sh uri-deserialize-pjuri` runs only the `uri-deserialize-pjuri` target for 30 seconds.

#### Using `cycle.sh`

This command will run over all targets continuously, changing targets every hour. It fuzzes without a sanitizer for throughput. Pass a fork count and `true` as the second argument to replay each target's corpus under AddressSanitizer after it is fuzzed.

`./cycle.sh [forks] [asan]`

Without a sanitizer, libFuzzer warns that it cannot find `__sanitizer_*` functions at startup. These warnings are harmless.

#### Using `asan.sh`

This script replays fuzz corpora once under AddressSanitizer without fuzzing, catching memory errors in inputs found by `cycle.sh`. It accepts an optional target name and replays every target's corpus when it is omitted.

`./asan.sh [target-name]`

---

Typically running `./fuzz.sh` alone is enough when testing out a new fuzz target to prove that it compiles and runs properly.
