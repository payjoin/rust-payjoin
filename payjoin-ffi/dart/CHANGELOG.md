## [0.3.0+payjoin-1.2.0]

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
- Pin `yoke-derive` for pub.dev consumers to respect the MSRV

## [0.2.2+payjoin-1.0.0]

- Bindings for payjoin-1.0.0, the first stable payjoin release. No Dart
  API changes since 0.2.1+payjoin-1.0.0-rc.8
- The package description no longer carries the EXPERIMENTAL disclaimer

## [0.2.1+payjoin-1.0.0-rc.8]

- Sender inputs must declare a sighash type that commits to all inputs and
  outputs. Only ECDSA `SIGHASH_ALL`, taproot `SIGHASHDEFAULT`/`SIGHASH_ALL`,
  and an unset type are accepted, both when building the sender context and
  when validating the receiver's proposal
- Versions now carry the wrapped payjoin release as build metadata

## [0.2.0]

- Bindings for payjoin-1.0.0-rc.7
- **Breaking:** `checkInputsNotOwned` takes an `IsInputOwned` callback keyed on
  an `OutPoint` in place of `IsScriptOwned`

## [0.1.2]

- Bindings for payjoin-1.0.0-rc.4

## [0.1.1]

- Initial functional release published to pub.dev.
- Bindings for payjoin-0.25.0

## [0.1.0]

- Internal release published to pub.dev to reserve the `payjoin` name.
