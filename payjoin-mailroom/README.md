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

We also provide a nix module for the payjoin-mailroom to be run as a standalone payjoin-mailroom node through the use of a nix flake.

This repo includes an [example flake](./flake.example.nix) to be used as a starting point in creating a standalone payjoin-mailroom service.

To use it copy it to be alongside your nixos configuration, in our case it is best suited in.

`/etc/nixos/payjoin-mailroom/flake.nix`

Add any necessary configs you deem necessary to this flake, we recommend following our [example config toml](./config.example.toml) for suggestions and then run this command to start the flake.

```
nixos-rebuild switch --flake /etc/nixos/payjoin-mailroom#payjoin-mailroom
```

That's it! you should be able to observe the service running via the systemctl with

```
systemctl status payjoin-mailroom.service
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
