# Payjoin Mailroom

The Payjoin Mailroom is a unified Payjoin Directory and OHTTP Relay server. Combines [payjoin-directory](../payjoin-directory/README.md) and [ohttp-relay](../ohttp-relay/README.md) into a single binary.

Note that this binary is under active development and thus the CLI and configuration file may be unstable.

## Configuration

payjoin-mailroom reads configuration from `config.toml` (or the path given with `--config`). Every setting can also be supplied via environment variables prefixed with `PJ_`, using double underscores for nesting (e.g., `PJ_TELEMETRY__ENDPOINT`).

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

## Telemetry

payjoin-mailroom supports **optional** OpenTelemetry-based telemetry (metrics).
Build with `--features telemetry` and configure via the [`[telemetry]`](config.example.com) config section.
When no telemetry configuration is present, it falls back to local-only console tracing.

## Access Control

Build with `--features access-control` to enable:

### IP Screening

Configured via the [`[access_control]`](config.example.toml) config section for IP- and region-based filtering.

The auto-fetched GeoLite2 database is provided by [MaxMind](https://www.maxmind.com) and distributed under the [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.

### V1 Address Screening

When the V1 protocol is enabled, payjoin-mailroom can screen PSBTs for blocked Bitcoin addresses.
Configure a local blocklist, a remote URL, or both via the [`[v1]`](config.example.toml) config section.
