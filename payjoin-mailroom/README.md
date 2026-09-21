# Payjoin Mailroom

payjoin-mailroom is a single, lightweight binary that bundles the two server-side roles required by BIP 77 Async Payjoin:

- **Payjoin Directory**: a store-and-forward mailbox that holds small, ephemeral, end-to-end encrypted payloads so a sender and receiver can complete a payjoin asynchronously (they don't need to be online at the same time).
- **OHTTP Relay**: an [Oblivious HTTP](https://en.wikipedia.org/wiki/Oblivious_HTTP) proxy that separates client IP addresses from the directory, preventing the directory from correlating users with their network identity.

Note that this binary is under active development and thus the CLI and configuration file may be unstable.

## Configuration

payjoin-mailroom reads configuration from `config.toml` (or the path given with `--config`). Every setting can also be supplied via environment variables prefixed with `PJ_`, using double underscores for nesting (e.g., `PJ_TELEMETRY__ENDPOINT`).

Logs go to stdout. `log_format = "text"`, the default, writes one readable line per event; `log_format = "json"` writes one JSON object per line for log collectors. `RUST_LOG` filters either.

## Usage

### Cargo

```sh
cargo run
```

### Docker Compose

A simple [docker-compose.yml](docker-compose.yml) is provided for convenience.

```sh
docker compose up
```

### Nix

The rust-payjoin flake also provides `payjoin-mailroom` as a package.

```sh
nix run .#payjoin-mailroom -- --config payjoin-mailroom/config.toml
```

### systemd

```sh
# A minimal [payjoin-mailroom.example.service](payjoin-mailroom.example.service) unit file is provided for convenience. Edit paths and User= as your setup requires.
vim /etc/systemd/system/payjoin-mailroom.service
systemctl daemon-reload
systemctl enable --now payjoin-mailroom
```

## Telemetry

payjoin-mailroom supports **optional** OpenTelemetry-based telemetry (metrics).
Build with `--features telemetry` and configure via the [`[telemetry]`](config.example.com) config section.
Without that section nothing is exported. Logs are never exported either way; `log_format` chooses how they are written.

## Access Control

Build with `--features access-control` to enable:

### IP Screening

Configured via the [`[access_control]`](config.example.toml) config section for IP- and region-based filtering.

The auto-fetched GeoLite2 database is provided by [MaxMind](https://www.maxmind.com) and distributed under the [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.

### V1 Address Screening

When the V1 protocol is enabled, payjoin-mailroom can screen PSBTs for blocked Bitcoin addresses.
Configure a local blocklist, a remote URL, or both via the [`[v1]`](config.example.toml) config section.
