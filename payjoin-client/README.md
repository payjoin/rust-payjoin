# Payjoin Relay

This is a simple TURN relay for payjoin clients to connect peer-to-peer.

The payjoin client sends and receives payjoins for a configured bitcoin rpc client wallet. In its current form it demonstrates Serverless Payjoin capabilities by communicating over p2p UDP extablished using TURN.

## Demo

Follow along to see how it works

### The relay

This demo relies on the default rendesvous and transit relay servers operated by magic-wormhole maintainer: "lothar.com/wormhole/text-or-file-xfer

### Start the recipient

Connect the server to a bitcoind rpc host and specify the amount you would like to request, in sats

```console
sudo docker run --network host --mount type=bind,source=/home/bob/.bitcoin/testnet3/,target=/testnet3/  dangould/payjoin-client:0.1.0.1 --port=18332 --cookie-file='/testnet3/.cookie' --amount=20000
```

The server should output arguments for the client, e.g.

```console
--code="4-combustion-standard" --psk="px9wvb+p38dCB1nGIHoQaECn9EXxRHxDSAecVfhqb1E=" --bip21="BITCOIN:TB1QA82L7NTU2UV0DV8UM3H204X7VPKVNY8QQCMZXU?amount=0.0002&pj=https://example.com"
```

### Send the payjoin

With the sender arguments in hand, we can send from a second funded bitcoind rpc host

```console
sudo docker run --network host --mount type=bind,source=/home/alice/.bitcoin/testnet3/,target=/testnet3/  dangould/payjoin-client:0.1.0.1 --port=18332 --cookie-file='/testnet3/.cookie' --code="4-combustion-standard" --psk="px9wvb+p38dCB1nGIHoQaECn9EXxRHxDSAecVfhqb1E=" --bip21="BITCOIN:TB1QA82L7NTU2UV0DV8UM3H204X7VPKVNY8QQCMZXU?amount=0.0002&pj=https://example.com"
```

When the chain advances, the new payjoin transaction should confirm.
