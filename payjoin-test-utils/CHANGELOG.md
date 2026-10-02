# payjoin-test-utils Changelog

## 0.0.2

- Replace payjoin-directory and ohttp-relay test services with payjoin-mailroom
- Allow any number of relay instances (within u8) for tests
- Replace bitcoind and bitcoincore-rpc with corepc-node
- Remove redis feature and dependencies
- Remove the url crate in favor of payjoin's Url type
- Promote InMemoryTestPersister to InMemoryPersister from payjoin
- Take cert_der by reference in fetch_ohttp_keys_with_cert
- Add Spec-related consts for readability in tests
- Bump payjoin dependency to 1.2.0
- Bump MSRV to 1.85
- Update Cargo.toml edition to 2024 [#1874](https://github.com/payjoin/rust-payjoin/pull/1874)

## 0.0.1

- Export InMemoryTestPersister under \_test-utils [#761](https://github.com/payjoin/rust-payjoin/pull/761)
- Introduce constructors for SegWit input pairs [#712](https://github.com/payjoin/rust-payjoin/pull/712)
- Move testing constants to payjoin-test-utils [#613](https://github.com/payjoin/rust-payjoin/pull/613)
- Specify the versions for deps more precisely in the cargo toml [#696](https://github.com/payjoin/rust-payjoin/pull/696)
- Extend tests for rest of receive module [#632](https://github.com/payjoin/rust-payjoin/pull/632)
- Fix uninline format clippy violations [#667](https://github.com/payjoin/rust-payjoin/pull/667)

## 0.0.0

- Release initial payjoin-test-utils to spin up payjoin test services
