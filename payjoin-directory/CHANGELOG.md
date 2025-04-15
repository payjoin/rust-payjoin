# payjoin-directory Changelog

## 0.0.2

- Do not log ERROR on directory validation errors [#628](https://github.com/payjoin/rust-payjoin/pull/628)
- Use payjoin 0.23.0 (056a39b8a8849451ee605dc7ae786f9cda31ace5)
- Announce allowed purposes (6282ffb2c76a93e1849ecc1a84c9f54ccf152cc5)
- Serve `/.well-known/ohttp-gateway` as per RFC 9540 (6282ffb2c76a93e1849ecc1a84c9f54ccf152cc5)
- Rely on `payjoin/directory` feature module [#502](https://github.com/payjoin/rust-payjoin/pull/502)
- Introduce db-module-specific `Result` [#488](https://github.com/payjoin/rust-payjoin/pull/488)
- Return bound port on listen for test stability (d4fa3d440abd102fcbb061b721480dee14ff91dc)

## 0.0.1

- Release initial payjoin-directory to store and forward payjoin payloads using secp256k1 hpke
