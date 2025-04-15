# Payjoin Directory

[BIP 77](https://github.com/bitcoin/bips/pull/1483) Async Payjoin (v2)
peers store and forward HTTP client messages via a directory server in order to
make asynchronous Payjoin transactions. This is a reference implementation of
such a server

V2 clients encapsulate requests using
[Oblivious HTTP](https://www.ietf.org/rfc/rfc9458.html) (OHTTP) which allows
them to make payjoins without the directory being able to link payjoins to
specific client IP. Payjoin Directory is therefore an [Oblivious Gateway
Resource](https://www.ietf.org/rfc/rfc9458.html#dfn-gateway).

Payjoin Directory also behaves as an [unsecured public-facing HTTP
server](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#unsecured-payjoin-server)
in order to provide backwards-compatible support for [BIP
78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) Payjoin (v1)
clients.
