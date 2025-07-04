# Payjoin Dart Integration Tests

This directory contains the Dart integration test framework for Payjoin FFI bindings, mirroring the Python integration test patterns from [rust-payjoin](https://github.com/payjoin/rust-payjoin).


## Quick Start

1. **Start Bitcoin Core in regtest mode:**
   ```sh
   bitcoind -regtest -daemon -rpcuser=test -rpcpassword=test
   ```

2. **Run the Dart integration tests:**
   ```sh
   dart pub get && dart test
   ```

## Note on V2 Integration Tests & testcontainers

- The V2 integration tests (which require Docker/testcontainers to spin up payjoin-directory and OHTTP relay) are currently **commented out**.
- **Why?**
  - When the Dart VM loads `libpayjoin_ffi.dylib` (via `import 'package:payjoin_dart/payjoin_ffi.dart'`), UniFFI's static initializer sets the process-wide handler for `SIGCHLD` to `SIG_IGN`.
  - Later, when testcontainers tries to launch Docker and calls `waitpid()` on the child process, it fails with `ECHILD` because `SIGCHLD` is ignored, causing a panic.
- **Workaround:**
  - By commenting out the V2-specific test code that relies on testcontainers, you can still run the rest of the tests. This confirms the FFI bridge and Bitcoin Core connection are working, unblocking further development.
  - The V2 integration test will remain disabled until the SIGCHLD issue is resolved upstream or a more robust workaround is implemented.

---

**Summary:**
- Start Bitcoin Core in regtest mode.
- Run `dart pub get && dart test`.
- V2 integration tests are disabled due to a known UniFFI/testcontainers signal handling issue.
- All other tests should pass, confirming the core FFI and Bitcoin Core integration.

