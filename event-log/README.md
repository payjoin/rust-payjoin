# event-log

Append-only event logs for typestate machines.

A state machine built on this crate records each transition as an event and
rebuilds its state by replaying the log. Two pieces are provided:

- `Persister` and `AsyncPersister`, the storage contract an application
  implements. Three methods: append an event, load every event in order, and
  close the log.
- The `Maybe*Transition` family, the values a state machine returns from a
  transition. Each one knows whether its outcome should be logged, whether
  the log should be closed, and whether the caller gets the next state,
  the current state back for a retry, or an error.

`InMemoryPersister` and `InMemoryAsyncPersister` are included for tests and
replay.

The crate has no dependencies. It was extracted from the
[payjoin](https://crates.io/crates/payjoin) crate, where it persists BIP 77
sender and receiver sessions.

## API notes

This is the API payjoin 1.0 froze, published as it stands. Two parts of it are
known to be awkward. Each is a breaking change for every persister
implementation, so they wait for a 2.0 rather than being changed here.

- `load` returns a boxed iterator. That forces an allocation and gives an
  implementation no way to report an error part way through a replay.
- The storage error type carries `Send + Sync + 'static` bounds that a
  single-threaded implementation does not need.

## Minimum Supported Rust Version (MSRV)

This crate supports Rust 1.85 and above.
