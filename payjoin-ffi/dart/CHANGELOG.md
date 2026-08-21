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
