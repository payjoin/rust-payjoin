## [0.3.0]

- Bindings for payjoin-1.2.0, which adds the non-blocking receive
  interface and its related methods alongside the existing
  callback-based ones
- Add FFI bindings for the non-blocking receive interface, including
  session event replay, in favor of synchronous callbacks
- Paying a BIP 78-only (v1) receiver from a v2 `SenderBuilder` now
  returns an `UnsupportedPjVersion` error instead of panicking across
  the FFI boundary
- **Breaking:** builder errors are renamed to match the payjoin crate:
  `SenderBuilderError` to `BuildSenderError` and
  `ReceiverBuilderError` to `BuildReceiverError`
- Replace the `url` crate with payjoin's native Url type, validating
  URLs as a precondition to URI validation
- Build bindings with a release build resolved against the lockfile
