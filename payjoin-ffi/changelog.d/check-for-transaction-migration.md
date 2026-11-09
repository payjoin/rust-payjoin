- To migrate from `Monitor.check_for_transaction`:
  - `close_session` on a `Monitor` records `PayjoinProposalSent` whichever
    transaction resolved the session, where `check_for_transaction` recorded
    `Success(txid)` or `FallbackBroadcasted`. Store `resolved_by` and the
    txid yourself if the app needs them.
  - `classify_tx` also classifies unconfirmed transactions. Call
    `close_session` only once the transaction reaches the wallet's
    confirmation depth.
  - Non-SegWit senders no longer need special handling.
  - A `Resolution` can't be persisted, so classify the transaction again
    after a restart.
  - `classify_tx` raises `TransactionParseError` for bytes that don't decode
    as a transaction.
