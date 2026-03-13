# Payjoin Mailroom Changelog

## 0.1.1

- Implement Directory and its db as a tower-service (#1361)
- Add ACME section for mailroom example config (#1382)
- Add an example `systemd` service (#1393)
- Add mailroom landing page (#1401)
- Update mailroom README description (#1402)
- Make git commit hash optional in landing page (#1408)
- Fold ohttp relay into mailroom (#1409)

## 0.1.0

Initial release of payjoin-mailroom (combining payjoin-directory and ohttp-relay).

- Implement unified service routing via axum (#1232)
- Prevent relay/gateway self-loop detection (#1232)
- Use tokio_listener for flexible binding (#1232)
- Add testing coverage (#1285)
- Add standalone metrics service (#1296)
- Add ACME certificate management (#1315)
- Fix metrics spawn in `serve_acme` (#1317)
- Replace Prometheus metrics with OpenTelemetry API (#1327)
- Add support for release tags when publishing a docker image (#1331)
- Clear V1 payload from memory after first read (#1335)
- Gate V1 protocol behind runtime feature flag (#1336)
- Add GeoIP region filtering and address blocklist (#1337)
- Add payjoin-mailroom to test_local.sh (#1339)
- Add supported versions to /health response (#1348)
