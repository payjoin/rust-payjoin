- Deprecate `MaybeInputsOwned.extract_tx_to_schedule_broadcast`. Cancel the
  session when the payjoin fails and broadcast the `fallback_tx` of the
  resulting `ReceiverPendingFallback` instead.
