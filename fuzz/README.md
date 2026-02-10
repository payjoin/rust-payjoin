<h1 align="center">
  <img src="https://github.com/benalleng/rust-payjoin/blob/fuzzing/static/monad-fuzz.gif" alt="payjoin-fuzz logo" width="150" />
  <br>
  Payjoin-fuzz
</h1>

Fuzz tests work by generating a ton of random noise that is morphed into parameter arguments for tests to run and validate that none of it causes unhandled crashes.

### Bootstrapping

This fuzzer uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). To get started, enter the nix dev shell and run the fuzzer:

```shell
nix develop
cd fuzz/
./fuzz.sh
```

### Running fuzzers

The `fuzz.sh` and `cycle.sh` shell scripts allow for single pass fuzzing and continuous long term fuzzing respectively.

#### Using `fuzz.sh`

This script accepts an optional fuzz target. It runs all available targets when this option is omitted.

`./fuzz.sh [fuzz-target]`

For example, `./fuzz.sh uri_deserialize_pjuri` runs only the `uri_deserialize_pjuri` target for 30 seconds.

#### Using `cycle.sh`

This command will run over all targets continuously, changing targets every hour.

`./cycle.sh`

---

Typically running `./fuzz.sh` alone is enough when testing out a new fuzz target to prove that it compiles and runs properly.
