### Dependencies

- Upgrade `bitcoin_uri` from 0.1 to 0.2, which parses BIP 321 URIs. The `Uri`
  and `PjUri` API is unchanged.

### Bug Fixes

- Accept URIs that mark the payjoin parameters as required with `req-pj` or
  `req-pjos`. BIP 321 lets a URI require any parameter the payer must
  understand, and payjoin understands both, but they were rejected as unknown
  required parameters. Any other unknown `req-` parameter is still rejected.
- Match URI keys case-insensitively, as BIP 321 requires. Upper-case keys used
  to be ignored, so a URI with `PJ=` did not request payjoin and one with
  `AMOUNT=` parsed without an amount. Both are read now.

### Stricter URI Parsing

- Some URIs that parsed before are now rejected under BIP 321's rules. Code
  that relied on them parsing could see this as a breaking change, though it
  is unlikely that anyone depends on it:
  - A repeated `amount`, `label`, `message` or `pop` is an error, including
    the same key in another case (`amount=1&AMOUNT=1`). The last value used to
    win, and a key in another case was ignored.
  - `pj` or `pjos` repeated in another case (`pj=...&PJ=...`) is an error, as
    repeating them in the same case already was.
  - An address parameter (`bc`, `tb` or `bcrt`) whose value is not a segwit
    address of the network its key names, such as `bc=tb1...`, is an error.
    These parameters used to be ignored.
- A `PjUri` now leaves out a `label` or `message` that is not valid UTF-8 when
  it prints, where it used to print the raw value.
