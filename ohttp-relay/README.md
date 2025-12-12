# OHTTP Relay

A rust implementation of an [Oblivious
HTTP](https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html) relay resource.

This work is undergoing active revision in the IETF and so are these
implementations. Use at your own risk.

## Usage

Run ohttp-relay by setting `PORT` and `GATEWAY_ORIGIN` environment variables. For example, to relay from port 3000 to an OHTTP Gateway Resource at `https://payjo.in`, run the following.

```console
PORT=3000 GATEWAY_ORIGIN='https://payjo.in' cargo run
```

Alternatively, set `UNIX_SOCKET` to bind to a unix socket path instead of a TCP port.

This crate is intended to be run behind a reverse proxy like NGINX that can handle TLS for you. Tests specifically cover this integration using `nginx.conf.template`.

## Bootstrap Feature

The Oblivious HTTP specification requires clients obtain a [Key Configuration](https://www.ietf.org/rfc/rfc9458.html#name-key-configuration) from the OHTTP Gateway but leaves a mechanism for doing so explicitly unspecified. This feature hosts HTTPS-in-WebSocket and HTTPS-in-CONNECT proxies to allow web clients to GET a gateway's ohttp-keys via [Direct Discovery](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-key-consistency-01#name-direct-discovery) in an end-to-end-encrypted, authenticated manner using the OHTTP relay as a tunnel so as not to reveal their IP address. The `bootstrap` feature to host these proxies is enabled by default. The `ws-bootstrap` and `connect-bootstrap` features enable each proxy individually.

### How does it work?

Both bootstrap features enable the server to forward packets directly to and from the OHTTP Gateway's TCP socket to negotiate a TLS session between the client and gateway. By doing so, the OHTTP Relay is prevented from conducting a [man-in-the-middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) to compromise the TLS session.
