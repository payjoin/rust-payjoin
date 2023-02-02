# Payjoin Relay

This is a simple TURN relay for payjoin clients to connect peer-to-peer.

The payjoin client sends and receives payjoins for a configured bitcoin rpc client wallet. In its current form it demonstrates Serverless Payjoin capabilities by communicating over p2p UDP extablished using TURN.

## Demo

Follow along to see how it works

### Start a relay

This relay has permission for a "receiver" user to request an allocation with password "test"

```console
RUST_LOG=trace cargo run --bin payjoin-relay -- --public-ip 0.0.0.0 --users receiver=test
```

### Start the recipient

Connect the server to a bitcoind rpc host and specify the amount you would like to request, in sats

```console
RUST_LOG=trace cargo run --bin payjoin-client -- --port=18444 --cookie-file="/Users/dan/.polar/networks/1/volumes/bitcoind/backend2/regtest/.cookie"  --amount=200000 --relay=0.0.0.0:3478
```

The server should output arguments for the client

```console
--endpoint=0.0.0.0:61629 --psk="EFA92zD3PjUlUg5uX/rsQ/+SFkJi3V3HGKi3H6WWw8I=" --bip21="BITCOIN:BCRT1QG8ZWJWLT640CJ076VLTDLKS2GJCF596XLYER95?amount=0.002&pj=https://example.com"
```

### Send the payjoin

With the sender arguments in hand, we can send from a second funded bitcoind rpc host

```console
RUST_LOG=trace cargo run --bin payjoin-client -- --port=18443 --cookie-file="/Users/dan/.polar/networks/1/volumes/bitcoind/backend1/regtest/.cookie"  --endpoint=0.0.0.0:61629 --psk="EFA92zD3PjUlUg5uX/rsQ/+SFkJi3V3HGKi3H6WWw8I=" --bip21="BITCOIN:BCRT1QG8ZWJWLT640CJ076VLTDLKS2GJCF596XLYER95?amount=0.002&pj=https://example.com"
```

When the chain advances, the new payjoin transaction should confirm.
