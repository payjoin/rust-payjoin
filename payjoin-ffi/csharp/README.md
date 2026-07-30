# Payjoin C# Bindings

Welcome to the C# language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

Payjoin lets the receiver of a Bitcoin transfer contribute inputs to the sender's transaction. The result looks like any other transaction, which preserves privacy by poisoning the common-input-ownership heuristic that chain surveillance depends on, and it lets the receiver batch its own operations into the same transaction. These bindings implement both [BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) (synchronous payjoin) and [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md) (asynchronous payjoin, where sender and receiver exchange the transaction through an untrusted directory and never need to be online at the same time), and ship with native libraries for every supported platform, so no Rust toolchain is required.

## Install

```shell
dotnet add package Payjoin --prerelease
```

Requires .NET 10.0 or later, on one of:

| OS      | RIDs                       |
| ------- | -------------------------- |
| Linux   | `linux-x64`, `linux-arm64` |
| macOS   | `osx-arm64`, `osx-x64`     |
| Windows | `win-x64`, `win-arm64`     |

## Receive a payjoin

A receiver session produces a BIP 21 URI to show the sender. It works with every wallet: a payjoin-aware sender upgrades to a payjoin, any other wallet simply sends to the address as usual.

A session starts with the directory's OHTTP keys, fetched through an OHTTP relay so the directory never learns your IP address, then builds a receiver for your address and persists every step to an event log so your app can crash or restart and resume where it left off. From there the session advances through a typestate flow: each state hands you a request to relay with your own HTTP client, and the response moves you to the next state, through checking the sender's original transaction, contributing inputs, and posting the proposal.

The code for this flow lives in [`samples/`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-ffi/csharp/samples), compiled on every change so it cannot go stale. Start with [`ReceiveSample.cs`](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/samples/ReceiveSample.cs), which also shows a minimal session persister. The [integration tests](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/IntegrationTests.cs) walk the complete loop.

## Send a payjoin

A sender session starts from a BIP 21 URI scanned from the receiver and the wallet's signed PSBT, posts the original PSBT, and polls for the receiver's proposal through the same request/response flow. See [`SendSample.cs`](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/samples/SendSample.cs).

## Resume after a restart

Replay a persisted event log to recover the current state of a session: [`ResumeSample.cs`](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/samples/ResumeSample.cs). Every `Save` has a `SaveAsync` counterpart, with async persister interfaces for database-backed storage.

## Preview status

The package is in preview while the C# API stabilizes alongside the Rust core's 1.0 release candidates. Expect breaking changes between previews; the package version tracks the underlying `payjoin-ffi` crate.

## Documentation and help

- [Payjoin Dev Kit](https://payjoindevkit.org/) for protocol background and guides
- [rust-payjoin](https://github.com/payjoin/rust-payjoin) is the Rust core these bindings are generated from, with the [issue tracker](https://github.com/payjoin/rust-payjoin/issues) for bugs and feature requests

To build the bindings from source, run the tests, or produce the NuGet package locally, see [`CONTRIBUTING.md`](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/CONTRIBUTING.md).
