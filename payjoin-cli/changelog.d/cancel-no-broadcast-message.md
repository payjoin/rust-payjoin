- `cancel --no-broadcast` now says the session closed without broadcasting
  the fallback transaction, and to broadcast it only if it isn't already on
  chain and its inputs are unspent.
