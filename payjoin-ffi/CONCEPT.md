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
