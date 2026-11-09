- `resume` checks the wallet once for transactions settling each open receiver
  session, in any state, and closes a session once its settling transaction
  has one confirmation. It reports whether the Payjoin, the fallback, or
  another transaction settled it. Sessions with non-SegWit senders are now
  tracked too. The receiver no longer polls the mempool after posting the
  proposal.
