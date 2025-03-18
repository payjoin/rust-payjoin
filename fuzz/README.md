<h1 align="center">
  <img src="https://github.com/benalleng/rust-payjoin/blob/fuzzing/static/monad-fuzz.gif" alt="payjoin-fuzz logo" width="150" />
  <br>
  Payjoin-fuzz
</h1>

Fuzz tests work by generating a ton of random noise that is morhped into parameter arguments for tests to run and validate that none of it causes it to have unhandled crashes.

### Bootstrapping

#### cargo-fuzz / libFuzzer

To use simply start a nix dev shell

```shell
nix develop
cd fuzz/
./fuzz.sh
```

### Running fuzzers

Note for some users the fuzz engine optionality is limited as there may not be any active maintenance for a fuzzer on that system. Namely MacOS and NixOS users should prefer `libfuzzer` as `honggfuzz` is not actively maintained for those systems.

The `fuzz.sh` and `cycle.sh` shell scripts allow for single pass fuzzing and continuous long term fuzzing resepctively.

#### Using `fuzz.sh`

This scripts accepts an optional fuzz target. It run all available targets when this option is omitted.

`./fuzz.sh <fuzz-target>`

for example the command `.fuzz.sh afl uri_deserialize_pjuri` selects the afl engine and runs only the `uri_deserialize_pjuri` for 30 seconds.

#### Using `cycle.sh`

This command will run over all targets continuously changing targets every hour.

`./cycle.sh`

---

Typically running `./fuzz.sh` alone is enough when testing out a new fuzz target to prove that it compiles and runs properly.
