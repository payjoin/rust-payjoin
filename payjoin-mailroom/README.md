# Payjoin Mailroom

payjoin-mailroom is a single, lightweight binary that bundles the two server-side roles required by BIP 77 Async Payjoin:

- **Payjoin Directory**: a store-and-forward mailbox that holds small, ephemeral, end-to-end encrypted payloads so a sender and receiver can complete a payjoin asynchronously (they don't need to be online at the same time).
- **OHTTP Relay**: an [Oblivious HTTP](https://en.wikipedia.org/wiki/Oblivious_HTTP) proxy that separates client IP addresses from the directory, preventing the directory from correlating users with their network identity.

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

### systemd

```sh
# A minimal [payjoin-mailroom.example.service](payjoin-mailroom.example.service) unit file is provided for convenience. Edit paths and User= as your setup requires.
vim /etc/systemd/system/payjoin-mailroom.service
systemctl daemon-reload
systemctl enable --now payjoin-mailroom
```

## Telemetry

payjoin-mailroom supports **optional** OpenTelemetry-based telemetry (metrics).
Build with `--features telemetry` and configure via the [`[telemetry]`](config.example.toml) config section.
When no telemetry configuration is present, it falls back to local-only console tracing.
Metrics are local-only by default: nothing is exported unless a `[telemetry]` section is configured.

### What leaves the operator boundary

Precise metrics (per-request counters, live in-flight and tunnel gauges) never
leave the process. When export is configured, the only metrics pushed to the
OTLP endpoint are unlabelled coarse weekly gauges, designed to support
ecosystem traction measurement without providing per-request telemetry:

- **Settled weekly windows.** Each exported count covers one completed
  Monday-to-Monday UTC week (`EXPORT_WINDOW_DAYS` in `src/metrics.rs`). The
  in-progress week is never exported, preventing live probing and daily
  differencing of overlapping windows.
- **Small-count suppression.** Windows whose raw count is below
  `suppression_threshold` (default 10) are dropped entirely, not rounded: a
  small operator's weekly count of 1-2 could be tied to a known real-world
  event.
- **Quantization.** Surviving counts are rounded to the nearest
  `quantization_bin` (default 5), so exported values carry no small-integer
  precision to subtract against.
- **Attribute minimization.** Exported metric points carry no attributes. The
  resource carries only `service.name` and a Foundation-issued opaque
  `reporter.id`; its operator mapping belongs outside Grafana. Tests fail if
  any other metric or resource attribute appears.
- **Reliable coarse delivery.** The exporter pushes daily, but every push in a
  reporting week carries the same frozen aggregate for the preceding completed
  week. This provides retry opportunities without exposing daily traffic
  volume; daily delivery time remains liveness metadata.

The Foundation should restrict raw reporter-labelled series to its telemetry
operators, retain them briefly, and publish aggregate dashboards only. A future
collector can aggregate across reporters and remove `reporter.id` before data
reaches Grafana.

`export_enabled = false` keeps the `[telemetry]` section's structured JSON
logging while disabling the metrics export entirely.

## Access Control

Build with `--features access-control` to enable:

### IP Screening

Configured via the [`[access_control]`](config.example.toml) config section for IP- and region-based filtering.

The auto-fetched GeoLite2 database is provided by [MaxMind](https://www.maxmind.com) and distributed under the [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.

### V1 Address Screening

When the V1 protocol is enabled, payjoin-mailroom can screen PSBTs for blocked Bitcoin addresses.
Configure a local blocklist, a remote URL, or both via the [`[v1]`](config.example.toml) config section.
