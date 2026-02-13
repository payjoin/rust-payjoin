# payjoin-service

Unified Payjoin Directory and OHTTP Relay service. Combines [payjoin-directory](../payjoin-directory/README.md) and [ohttp-relay](../ohttp-relay/README.md) into a single binary.

Note that this binary is under active development and thus the CLI and configuration file may be unstable.

## Configuration

payjoin-service reads configuration from `config.toml` (or the path given with `--config`). Every setting can also be supplied via environment variables prefixed with `PJ_`, using double underscores for nesting (e.g., `PJ_TELEMETRY__ENDPOINT`).

## Running the service

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

The rust-payjoin flake also provides `payjoin-service` as a package.

```sh
nix run .#payjoin-service -- --config payjoin-service/config.toml
```

## Telemetry

payjoin-service supports **optional** OpenTelemetry-based telemetry (metrics, traces, and logs). Build with `--features telemetry` and add a `[telemetry]` section to your config:

```toml
[telemetry]
endpoint = "https://otlp-gateway-prod-us-west-0.grafana.net/otlp"
auth_token = "<base64 instanceID:token>"
operator_domain = "your-domain.example.com"
```

Or set the equivalent environment variables:

```sh
export PJ_TELEMETRY__ENDPOINT="https://otlp-gateway-prod-us-west-0.grafana.net/otlp"
export PJ_TELEMETRY__AUTH_TOKEN="<base64 instanceID:token>"
export PJ_TELEMETRY__OPERATOR_DOMAIN="your-domain.example.com"
```

When no `[telemetry]` section is present and no `PJ_TELEMETRY__*` variables are set, the service uses local-only console tracing.
