# payjoin-cli Changelog

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
