<div align="center">
  <h1>Payjoin</h1>

  <img src="../static/monad.svg" width="150" />

  <p>
    <strong>Supercharged payment batching to save fees and preserve privacy</strong>
  </p>

  <p>
    <a href="https://crates.io/crates/payjoin"><img alt="Crates" src="https://img.shields.io/crates/v/payjoin.svg?logo=rust"></a>
    <a href="https://docs.rs/payjoin"><img alt="Crates" src="https://img.shields.io/static/v1?logo=read-the-docs&label=docs.rs&message=payjoin&color=f75390"></a>
    <a href="https://github.com/payjoin/rust-payjoin/actions/workflows/rust.yml"><img alt="CI Status" src="https://github.com/payjoin/rust-payjoin/actions/workflows/rust.yml/badge.svg"></a>
    <a href="https://coveralls.io/github/payjoin/rust-payjoin?branch=master"><img src="https://coveralls.io/repos/github/payjoin/rust-payjoin/badge.svg?branch=master"/></a>
    <a href="https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/"><img alt="Rustc Version 1.85.0+" src="https://img.shields.io/badge/rustc-1.85.0%2B-lightgrey.svg"/></a>
  </p>

  <h4>
    <a href="https://payjoindevkit.org">Project Homepage</a>
  </h4>
</div>

This crate is the main Payjoin Dev Kit (PDK) library which provides Rust constructs for implementing both Payjoin V2 (Asynchronous) and V1 (Synchronous). For Payjoin V2, the library also contains Payjoin session persistence support and IO utilities for interacting with OHTTP relays.

## Cargo Features

- `v2`: all constructs for Payjoin V2 (Asynchronous) send and receive operations. Note that IO for fetching OHTTP keys from the Payjoin directory is not enabled here, and require the `io` flag.
- `v1`: all constructs for Payjoin V1 (Synchronous) send and receive operations.
- `io`: helper functions for fetching and parsing OHTTP keys.
- `directory`: type for identifying Payjoin Directory entries as defined in BIP 77.

Only the `v2` feature is enabled by default.

## Overview

The sections below give an overview of how different parts of the PDK library have been designed to streamline both the collaborative transaction construction and communication with the Payjoin directory through OHTTP relays.

### Receiver and Sender Constructs

Both V1 and V2 receiver and sender construct design follow the [The Typestate Pattern in Rust](https://cliffle.com/blog/rust-typestate/), where higher-level `Sender<...>` and `Receiver<...>` structs are transitioned through consecutive states with represents a specific step they can be on over the course of a Payjoin session.

For example, `Receiver<UncheckedOriginalProposal>` is the first state of the Receiver state machine after it gets the sender's original proposal from the Payjoin directory. The state exposes the `Receiver<UncheckedOriginalProposal>::check_proposal` to check if the original proposal can be broadcast as a fallback in case the Payjoin session fails. A successful validation of the fallback (and the saving of the state in the persister) returns the next state, `Receiver<MaybeInputsOwned>`. In this state, the receiver state machine has access to functions to confirm if the inputs in the original proposal are not owned by them.

See the example in code below.

```rust
// let recv_state: Receiver<UncheckedOriginalProposal> = ... (successful poll of the proposal)
let recv_next_state: Receiver<MaybeInputsOwned> = recv_state
    .check_broadcast_suitability(None, |tx| {
        // ... (check for if original proposal is finalized)
    })
    .save(persister)?;
// At this point, `recv_next_state` cannot make a `.check_broadcast_suitability` call
// at the function is only implemented for the `Receiver<MaybeInputsOwned>` state.
```

See the source code documentation for detailed explanation of all states.

### Persistence

The provided `SessionPersister` trait should be implemented by a persister to store Payjoin session events. The state machines use the event log to determine the current state of an asynchronous Payjoin V2 session when a party comes back online and can continue the Payjoin session from where they left off.

Every time a state machine moves to the next state is considered a `SessionEvent`, which must be saved in the persister before moving on to the next state. Since the sender and receiver's validations and mutations over the course of a Payjoin session differ, each define their own collection of possible `SessionEvent`.

PDK provides session-related tooling for the sender and receiver to replay the event log of a session, and retrieve information for the session like the Payjoin URI, the original unchecked proposal, or the fallback transaction which either party can broadcast at any time.

### Oblivious HTTP (OHTTP) and Directory IO for Payjoin V2

Payjoin V2 allows asynchronous Payjoin sessions where both parties can go offline at any time over the course of a session. For each session, the receiver selects a Payjoin directory server which both the receiver and sender will relay the in-construction Payjoin transaction to when they are done with their part of the Payjoin process. All requests to the Payjoin directory go through Oblivious HTTP relays to prevent the directory and other Payjoin clients from linking the requests to the clients' IP addresses.

For more information on the Payjoin directory and OHTTP, see [BIP 77: Payjoin V2 (Asynchronous)](https://github.com/bitcoin/bips/blob/master/bip-0077.md).

PDK streamlines the client's interaction with both the OHTTP relay and the Payjoin directory. Functions for fetching the OHTTP keys from the Payjoin directory are provided under the `io` feature. Payjoin directory identifier is provided under the `directory` feature.

OHTTP keys and server identifiers are passed to the sender and receiver state machines at the beginning of the sessions. Afterwards, PDK handles the OHTTP encapsulation of all communication with the directory when creating the requests for the clients to send.

## Minimum Supported Rust Version (MSRV)

All crates in this repository should always compile with any combination of features on Rust **1.85.0**.

## Contributing

See [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## License

MIT
