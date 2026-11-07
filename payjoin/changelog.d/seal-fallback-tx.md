- Close a leak in the `HasFallbackTx` seal. Generic code bounded on the trait
  could call the sealed `fallback_tx` method, which was never part of the
  documented API; such code no longer compiles. Read the fallback transaction
  from `Receiver<PendingFallback>::fallback_tx` after `cancel`, or from
  `SessionHistory::fallback_tx`.
