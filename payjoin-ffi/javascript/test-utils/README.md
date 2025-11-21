# Native Test Utils (NAPI-RS)

This directory contains native Node.js bindings for payjoin test utilities using NAPI-RS.

The JavaScript bindings use WASM (via uniffi-bindgen-react-native) for production code. However, WASM cannot access OS-level functionality like spawning Bitcoin Core processes or creating TCP servers. This NAPI-RS addon provides native test infrastructure while the integration tests run against the actual WASM production code.

All implementations directly wrap `payjoin-test-utils` Rust crate.
