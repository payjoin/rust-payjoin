- Deprecate `Receiver<MaybeInputsOwned>::extract_tx_to_schedule_broadcast`.
  Schedule the fallback broadcast by cancelling the session when the payjoin
  fails: `cancel` yields a `Receiver<PendingFallback>` whose `fallback_tx`
  is the transaction to broadcast.
