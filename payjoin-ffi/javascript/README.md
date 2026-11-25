# Payjoin JavaScript Bindings

Welcome to the JavaScript language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

<!-- concept:begin (synced from payjoin-ffi/CONCEPT.md; edit there and run payjoin-ffi/contrib/sync-concept.sh) -->

Payjoin lets Bitcoin senders and receivers interact to make batched
transactions. The cooperating peers choose the inputs and outputs of the
transfer together, so the result looks like any other transaction — which
preserves privacy by poisoning the common-input-ownership heuristic that
chain surveillance depends on — and the receiver can batch its own
operations into the same transaction.

These bindings implement both
[BIP 78 Simple Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki)
and
[BIP 77 Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md),
in which sender and receiver exchange the transaction through an
untrusted directory and never need to be online at the same time.

Learn more at [payjoindevkit.org](https://payjoindevkit.org/).

<!-- concept:end -->

## Usage

### Install

```shell
npm install payjoin
```

### Import

For node environments:

```js
import { uniffiInitAsync, payjoin } from "payjoin";

// initialize before usage
await uniffiInitAsync();
```

For web browser environments:

```js
import * as payjoin from "payjoin/web";
// or for usage with Vite
import * as payjoin from "payjoin/web-vite";

// initialize before usage
await payjoin.uniffiInitAsync();
```

Made with [uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native)
