# payjoin-relay

## Payjoin v2 Relay

Payjoin v2 peers relay HTTP client messages in order to cordinate an asynchronous Payjoin transaction. Version 1 Requires the receiver to host a public HTTP server and to set up security using either HTTPS or Onion Services above and beyond typical HTTP client operation.

V2 clients use Hybrid Pubkey Encryption established in the bitcoin URI payment request for security instead, allowing lightweight clients secure communication without the burden of setup, which is done by the operator of this third-party relay server. This relay only sees OHTTP encapsulated, encrypted requests to prevent it from collecting metadata to break the privacy benefits of payjoin for messages who follow the spec.

This relay *only* accepts v2 payloads via Oblivious HTTP (OHTTP), preventing it from identifying IP addresses of clients.

## Architecture

The relay is a simple mailbox. Receivers may enroll by making a request to a pubkey identified subdirectory. After success response, they may share this subdirectory as payjoin endpoint to the sender in a bitcoin URI. The sender may poll the subdirectory with a request posting their encrypted Fallback PSBT expecting a Payjoin Proposal PSBT response. The receiver may poll the enroll endpoint to await a request, later posting their Payjoin Proposal PSBT for the sender to receive, sign, and broadcast.

The relay does depend on a second independent Oblivious HTTP Relay to help secure request/response metadata from the Payjoin Relay.
