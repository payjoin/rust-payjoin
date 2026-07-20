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

payjoin-mailroom supports **optional** OpenTelemetry-based metrics export.
Build with `--features telemetry` and configure the [`[telemetry]`](config.example.toml) config section.
Without that section nothing is exported. Logs are never exported either way; `log_format` chooses how they are written.

### What leaves the operator boundary

Five integers a week. Each covers the most recently completed
Monday-to-Monday UTC week:

| Gauge                           | Meaning                                                |
| ------------------------------- | ------------------------------------------------------ |
| `http_requests_weekly`          | HTTP requests completed                                |
| `http_requests_started_weekly`  | HTTP requests started                                  |
| `db_entries_weekly`             | mailbox entries written                                |
| `bootstrap_tunnel_sheds_weekly` | OHTTP bootstrap tunnels refused at the concurrency cap |
| `unique_short_ids_weekly`       | distinct mailbox IDs touched, exact, capped            |

`unique_short_ids_weekly` is the size of the set of mailbox IDs touched
that week. A mailbox ID is the short ID in the request path, the first
eight bytes of a SHA-256, and a mailbox is touched by any request that
posts to it or waits on it. Each week's set holds at most ten million IDs;
past that it stops collecting and the week reports the cap, so a week
exporting exactly that value was flooded rather than counted.

The rules, each pinned by a unit test in `src/metrics.rs` or `src/telemetry.rs`:

- Only the settled week is exported. The week in progress is never visible,
  so there is no live value to watch and no overlapping windows to
  difference for daily traffic.
- Counts are exported exactly, including zero. They are not rounded and
  small values are not withheld: either would hide at most a few units
  from a passive viewer, and anyone able to send traffic can add a known
  amount and subtract it back out.
- Data points carry no attributes. No endpoint, method, status code,
  protocol version, IP address, hostname, or mailbox ID is exported.
- The resource carries exactly `service.name` and `operator.domain`. It is
  built from an empty resource, so `OTEL_RESOURCE_ATTRIBUTES` cannot add
  anything to it.

Values are pushed once an hour. Every push in a week carries the same
settled value, so the hourly cadence adds delivery attempts, not detail. A
restarted node reports within the hour.

Precise metrics (per-request counters, in-flight and tunnel gauges) are
registered on a provider with no reader while export is on. They are not
exported, and this release gives them no local sink either. The logs on
stdout are the operator's per-request view.

### Identifying yourself

`operator_domain` is chosen by you. Using your public domain is expected;
it is the label the Foundation's dashboards group by, and the section is
rejected without it.

Run one mailroom process per `operator_domain`. Two processes with the
same value each hold part of the week and write the same series, so the
export shows one process's share rather than the total.

### What the Foundation does with it

The Foundation publishes aggregate dashboards from this export. Per-operator
weekly series are visible to Foundation dashboard editors and kept at the
stack's default retention.

### Restarts and outages

The four counters are kept in `weekly_counts.txt` under `storage_dir`:
eight integers, the current and previous week's count of each counter,
keyed by week. The sets of mailbox IDs behind `unique_short_ids_weekly` are kept
next to it in `unique_short_ids.bin`, one set for each of the same two
weeks. Both files are written on every hourly export and on SIGINT or
SIGTERM, and loaded at boot, so a redeploy keeps the week and its IDs.
Deleting them loses only those two weeks. Two processes sharing a
`storage_dir` cannot corrupt either file, but the last writer wins.

Up to two weeks of touched mailbox IDs therefore live on disk under
`storage_dir`, 80 MB per week at the cap, next to the mailbox files that
already carry those IDs as names.

Counts recorded since the last hourly write are lost if the process is
killed without a signal. A node that is down across a Monday exports, once
back, whatever it recorded of that week before it went down, including 0
for a week it was fully down. A node that stays down until the Monday after
that never exports the week its outage began in: by the time it is back,
that week is no longer the settled one.

## Access Control

Build with `--features access-control` to enable:

### IP Screening

Configured via the [`[access_control]`](config.example.toml) config section for IP- and region-based filtering.

The auto-fetched GeoLite2 database is provided by [MaxMind](https://www.maxmind.com) and distributed under the [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.

### V1 Address Screening

When the V1 protocol is enabled, payjoin-mailroom can screen PSBTs for blocked Bitcoin addresses.
Configure a local blocklist, a remote URL, or both via the [`[v1]`](config.example.toml) config section.
