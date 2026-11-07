- When `cancel` fails to broadcast the fallback transaction, it now says the
  session is still open and points to `cancel --no-broadcast` to close it.
  The hint for a cancelled session awaiting its fallback mentions the flag
  too.
