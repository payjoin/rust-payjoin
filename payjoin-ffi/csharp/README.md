# Payjoin C# Bindings

Welcome to the C# language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

Payjoin lets the receiver of a Bitcoin payment contribute inputs to the sender's transaction, improving privacy and enabling batching in an ordinary-looking payment. These bindings implement both [BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) (synchronous payjoin) and [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md) (asynchronous payjoin, where sender and receiver exchange the transaction through an untrusted directory and never need to be online at the same time), and ship with native libraries for every supported platform, so no Rust toolchain is required.

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

A receiver session produces a BIP 21 URI to show the sender. It works with every wallet: a payjoin-aware sender upgrades the payment, any other wallet simply pays the address.

```csharp
using Payjoin;
using Payjoin.Http;

// Fetch the directory's OHTTP keys through an OHTTP relay, which keeps
// the directory from learning your IP address.
using var keysClient = new OhttpKeysClient(new System.Uri("https://pj.bobspacebkk.com"));
var ohttpKeys = await keysClient.GetOhttpKeysAsync(new System.Uri("https://payjo.in"));

var persister = new InMemoryPersister();
var receiver = new ReceiverBuilder(
        "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", // your receiving address
        "https://payjo.in",                           // payjoin directory
        ohttpKeys)
    .Build()
    .Save(persister);

Console.WriteLine(receiver.PjUri().AsString());
```

Sessions persist each step to an event log so your app can crash or restart and resume where it left off. Implement the persister over your own storage; a minimal in-memory version:

```csharp
class InMemoryPersister : JsonReceiverSessionPersister
{
    private readonly List<string> _events = new();
    public void Save(string @event) => _events.Add(@event);
    public string[] Load() => _events.ToArray();
    public void Close() { }
}
```

From here the session advances through a typestate flow: each state hands you a request to relay with your own HTTP client and the response moves you to the next state, through checking the sender's original transaction, contributing inputs, and posting the proposal. The [integration tests](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/IntegrationTests.cs) walk the complete loop.

## Send a payjoin

```csharp
using Payjoin;

var uri = Payjoin.Uri.Parse("bitcoin:...?amount=0.01&pj=..."); // scanned from the receiver
var pjUri = uri.CheckPjSupported(); // throws if the URI carries no payjoin parameters

var sender = new SenderBuilder(originalPsbtBase64, pjUri) // your wallet's signed PSBT
    .BuildRecommended(minFeeRateSatPerKwu: 250)           // 250 sat/kWU = 1 sat/vB floor
    .Save(persister); // JsonSenderSessionPersister, same shape as the receiver's
```

The sender session then posts the original PSBT and polls for the receiver's proposal through the same request/response flow.

## Resume after a restart

Replay a persisted event log to recover the current state of a session:

```csharp
var replayed = PayjoinMethods.ReplayReceiverEventLog(persister);
var state = replayed.State(); // e.g. ReceiveSession.Initialized
```

Every `Save` has a `SaveAsync` counterpart, with async persister interfaces for database-backed storage.

## Preview status

The package is in preview while the C# API stabilizes alongside the Rust core's 1.0 release candidates. Expect breaking changes between previews; the package version tracks the underlying `payjoin-ffi` crate.

## Documentation and help

- [Payjoin Dev Kit](https://payjoindevkit.org/) for protocol background and guides
- [rust-payjoin](https://github.com/payjoin/rust-payjoin) is the Rust core these bindings are generated from, with the [issue tracker](https://github.com/payjoin/rust-payjoin/issues) for bugs and feature requests

To build the bindings from source, run the tests, or produce the NuGet package locally, see [`DEVELOPMENT.md`](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/DEVELOPMENT.md).
