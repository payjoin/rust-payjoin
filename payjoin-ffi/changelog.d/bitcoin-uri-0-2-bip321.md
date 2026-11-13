- `Uri.parse` follows BIP 321: keys match case-insensitively, `req-pj` and
  `req-pjos` are accepted, and a URI with any other unknown `req-` parameter
  is rejected. Some URIs that parsed before, such as one with a repeated
  `amount`, are now rejected; see the payjoin changelog for the full list.
- `PjUri.as_string` returns the URI it was parsed from unchanged, keeping
  parameters payjoin does not read, such as `lightning` or `sp`.
  `PjUri.set_amount_sats` still rebuilds the URI and drops them.
