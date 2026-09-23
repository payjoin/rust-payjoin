# Changelog

## 1.0.0

Initial release, extracted from `payjoin::persist` as of payjoin 1.0.0.

- `SessionPersister` and `AsyncSessionPersister` are named `Persister` and
  `AsyncPersister` here.
- Transition constructors are public so state machines outside this crate can
  build them.
- `InMemoryAsyncPersister` is always available and does not need tokio.
