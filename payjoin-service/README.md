# payjoin-service

Unified Payjoin Directory and OHTTP Relay service. Combines [payjoin-directory](../payjoin-directory/README.md) and [ohttp-relay](../ohttp-relay/README.md) into a single binary.

Note that this binary is under active development and thus the CLI and configuration file may be unstable.

## Running with Telemetry

payjoin-service supports optional OpenTelemetry-based telemetry (metrics, traces, and logs) via an [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) sidecar. The bundled `otel-collector-config.yaml` is pre-configured to export to Grafana Cloud, but can be adapted to any OTLP-compatible backend.

1. Copy the example environment file and fill in your values:

   ```sh
   cp .env.example .env
   ```

2. Update the `OPERATOR_DOMAIN` and `GRAFANA_OTEL_EXPORTER_TOKEN` in `.env` with your domain name and Grafana token.

### Docker Compose

3. Run with the `telemetry` profile:

   ```sh
   docker compose --profile telemetry up
   ```

   Without the profile flag, only `payjoin-service` starts (no collector):

   ```sh
   docker compose up
   ```

### Nix

The flake provides `payjoin-service` as a package. Run it alongside `opentelemetry-collector-contrib` from nixpkgs.

3. Start the OTel Collector (first terminal):

   ```sh
   set -a && source .env && set +a
   export PAYJOIN_SERVICE_METRICS_TARGET=localhost:9090  # override Docker hostname

   nix run nixpkgs#opentelemetry-collector-contrib -- --config payjoin-service/otel-collector-config.yaml
   ```

4. Start payjoin-service (second terminal):

   ```sh
   nix run .#payjoin-service -- --config payjoin-service/config.toml
   ```

   Without telemetry, skip the collector. The service works the same either way.
