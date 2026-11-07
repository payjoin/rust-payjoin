- The v2 receiver no longer prints the fallback transaction hex when the
  Original PSBT arrives. The message now points to
  `payjoin-cli cancel <session-id>`, which broadcasts the fallback transaction
  if the payjoin fails.
