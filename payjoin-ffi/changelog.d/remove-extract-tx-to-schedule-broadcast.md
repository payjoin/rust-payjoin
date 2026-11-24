- Remove `MaybeInputsOwned.extract_tx_to_schedule_broadcast`, deprecated in
  0.26.0. When the payjoin fails, cancel the session and broadcast the
  `fallback_tx` of the resulting `ReceiverPendingFallback` instead.
