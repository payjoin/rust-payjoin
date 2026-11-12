### Bug Fixes

- Fix `Receiver<WantsInputs>::contribute_inputs` crediting a second
  contribution to fees instead of the change output, so splitting the
  receiver's inputs across calls lost funds to the miner and could
  reject a smaller later batch as below the minimum.
- Reject a drain script that a sender output carries. It let the change
  index resolve to that sender output, crediting the receiver's change to
  the sender and then panicking in `apply_fee_range`.
- Keep inputs contributed through `contribute_inputs` unsigned in the
  proposal. A `scriptSig` or witness left on the `TxIn` could make the
  proposal fail to parse or stop matching the persisted session.
