# payjoin-cli Changelog

## 0.0.8-alpha

This release attempts to stabilize the Payjoin V2 Bitcoin URI format. That includes placing v2-specific parameters in the URI's pj parameter's fragment and including the exp expiration parameter.

- Update to `payjoin-0.19.0`
  - Error if send or receive session expires with `exp` parameter [#299](https://github.com/payjoin/rust-payjoin/pull/299)
  - Encode `&ohttp=` and `&exp=` parameters in the `&pj=` URL as a fragment instead of as URI params [#298](https://github.com/payjoin/rust-payjoin/pull/298)
  - Allow receivers to make payjoins out of sweep transactions [#259](https://github.com/payjoin/rust-payjoin/pull/259)

## 0.0.7-alpha

- Resume multiple payjoins easily with the `resume` subcommand. A repeat `send`
  subcommand will also resume an existing session ([#283](https://github.com/payjoin/rust-payjoin/pull/283))
- Normalize dash-separated long args ([#295](https://github.com/payjoin/rust-payjoin/pull/295))
- Use sled database. Old .json storage files will no longer be read and should be deleted.
- read Network::from_core_arg ([#304](https://github.com/payjoin/rust-payjoin/pull/304))
- Don't needlessly substitute outputs for v2 receivers ([#277](https://github.com/payjoin/rust-payjoin/pull/277))
- Print instructions and info on interrupt ([#303](https://github.com/payjoin/rust-payjoin/pull/303))

### Contributors:

@DanGould, @grizznaut, @thebrandonlucas

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
- separate V1 `pj_endpoint` and V2 `pj_directory` config params / cli arguments

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
