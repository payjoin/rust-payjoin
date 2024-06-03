# payjoin-cli Changelog

## 0.0.6-alpha

- fetch ohttp keys from `payjoin/io` feature
- add example.config.toml
- Rename config.toml & CLI argument field pj_host to port (#253)
- add `--version` & `-V` CLI arguments
- replace dependency on `ureq` with `reqwest`
- Unify `pj_host`, `--host-port` arguments to `port` for v1 receivers
- remove `sub_only` CLI argument and config option
- Include more verbose context when bitcoind fails (#251)
- Use `*rpcpassword` instead of `*rpcpass` config and option to match bitcoind
- Test with JoinMarket
- respect `disableoutputsubtitution` send parameter
- depend on `payjoin-0.16.0`

Contributors:

@jbesraa, @grizznaut, @thebrandonlucas, @DanGould

## 0.0.5-alpha

- fetch ohttp keys through CONNECT tunnel (#194) instead of manual configuration
- Name payjoin-directory and OHTTP relay according to BIP 77 (#203)

## 0.0.4-alpha

- Remove annoying duplicate code in tests. (#197)
- Refactor payjoin-cli v1, v2 features into modules (#198)
- Parse AppConfig types when they're passed (#195)
- Use spec OHTTP media types (#160)
- Handle ResponseError version-unsupported variant supported field (#165)

## 0.0.3-alpha

- Parse `WellKnownError` `ResponseError` from receivers (#120)
- Show OHTTP Config issue was unclear (#153)
- Better compatibility for `receive` on taproot wallets (#147)

## 0.0.2-alpha

- New `v2` oblivious, asynchronous, serverless payjoin support

## 0.0.1-alpha

- Release initial payjoin-cli to send and receive payjoin from bitcoind
