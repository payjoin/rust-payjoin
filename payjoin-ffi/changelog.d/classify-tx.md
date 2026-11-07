- Add `classify_tx` to every receiver state that holds a fallback transaction
  and is advancing the Payjoin protocol, from `MaybeInputsOwned` through
  `Monitor`. Pass every consensus-encoded transaction the wallet receives to
  `classify_tx` on each open session, or to `classify_receiver_tx` with a
  session in any state. It returns a `Resolution` whose `resolved_by` is a
  `ResolvedBy` of `Payjoin`, `Fallback` or `Unrecognized`, or none for a
  transaction that spends none of the sender's original inputs, and never
  reports `Payjoin` before `PayjoinProposal`.
- Add `close_session` to the same states, and `close_receiver_session` for a
  session in any state. Each takes a `Resolution` and returns a
  `CloseTransition` that ends the session once the wallet decides the
  transaction has enough confirmations. Saving it fails with a transient
  error, without persisting, if the resolution was classified from another
  session, or, for `close_receiver_session`, if the session state cannot be
  closed via resolution. Closing classifies the transaction again against
  the session's current state.
- Remove `Monitor.check_for_transaction`, with its `TransactionFinder`
  callback and `MonitorTransition`. It closed the session on first sight of
  a predicted txid and never saw a spend that is neither the proposal nor
  the fallback. Use `classify_tx` and `close_session` instead.
- Remove `proposal_txid_is_stable` from every receiver state. It checked
  only the sender's inputs, so a legacy or P2SH-wrapped receiver input could
  change the txid even when it returned true. Use `classify_tx` instead.
