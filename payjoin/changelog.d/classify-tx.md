- Deprecate `Receiver<Monitor>::check_for_transaction`. It closes the
  session on first sight of a predicted txid, never sees a spend that is
  neither the proposal nor the fallback, and closes a session with
  non-SegWit sender inputs without checking. Use `classify_tx` and `close`
  instead. It now probes a txid that includes the script_sig of a legacy or
  P2SH-wrapped receiver input. It used to probe a txid that never appears
  on chain for such a session.
- Deprecate `Receiver::proposal_txid_is_stable`. It checks only the
  sender's inputs, so a legacy or P2SH-wrapped receiver input can change
  the txid even when it returns true. Use `classify_tx` instead.

### API Additions

- Add `classify_tx` to every `receive::v2::Receiver` state that holds a
  fallback transaction and is advancing the Payjoin protocol, from
  `MaybeInputsOwned` through `Monitor`. For a transaction spending the
  sender's original inputs it returns a `Resolution`, whose `resolved_by` is a
  `ResolvedBy` saying whether that transaction is the Payjoin proposal, the
  fallback, or neither. `ReceiveSession::classify_tx` does the same for a
  session in any state. Wallets should pass every transaction they receive to
  `classify_tx` on each open session. It recognizes the proposal even after a
  non-SegWit sender's signature changes its txid, and never reports `Payjoin`
  before `PayjoinProposal`
- Add `close` to the same states and to `ReceiveSession`. It takes a
  `Resolution` and ends the session once the wallet decides the transaction
  has enough confirmations, without broadcasting the fallback. Only
  `classify_tx` makes a `Resolution`, and `close` rejects one classified from
  another session. `ReceiveSession::close` also rejects a session state
  that cannot be closed via resolution. `close` classifies the transaction
  again against the session's current state, and records
  `PayjoinProposalSent` from `Monitor`, and from `PayjoinProposal` when the
  Payjoin resolved it, and `Aborted` otherwise
