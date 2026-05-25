"""Fetch OHTTP keys from a payjoin directory through an OHTTP relay.

When multiple relays are configured, callers **should pick one at random per request**
to avoid a fixed contact pattern at the network layer.

Random selection only helps if the relay list itself is not identifying: prefer a shared
relay list and discourage isolated infrastructure that other apps don't use, since a
distinctive list fingerprints the client regardless of how a relay is picked from it.

Sender and receiver have distinct request patterns:
- Receiver: long-poll GETs, then a POST
- Sender: a POST, then long-poll GETs

OHTTP does not hide the client IP from the relay. A relay that sees the same
client repeatedly can observe its access patterns to infer whether
the IP is associated with a sender or receiver, potentially linking to identity or
location. Based on when a session ends it may be easier to correctly guess
whether a transaction is a PayJoin. The IP address linked information may
additionally aid in cluster analysis, for example whether a cluster's temporal
patterns are consistent with a location guess for the IP address.

## Health checks

Some clients call `fetch_ohttp_keys` periodically to verify that the
directory and relay infrastructure is reachable. Given the threat model
above, this is acceptable only when:

- The call is **not** triggered on any deterministic, recurring event
  (e.g. app startup, periodic timer). Prefer user-initiated actions
  (e.g. opening a settings/status screen) or piggybacking on operations
  the user already triggered (e.g. resuming an existing session).
- The caller throttles invocations so they don't produce a recurring
  timing pattern observable by the relay.

A health check has a distinct traffic pattern from a real payjoin request
and is not temporally tied to any onchain broadcast, but repeated calls
still expose the client IP to the relay.
"""

import ssl
from urllib.parse import urljoin

import httpx

from .payjoin import OhttpKeys


async def fetch_ohttp_keys(
    ohttp_relay_url: str,
    directory_url: str,
    certificate: bytes,
) -> OhttpKeys:
    keys_url = urljoin(directory_url, "/.well-known/ohttp-gateway")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    pem_certificate = ssl.DER_cert_to_PEM_cert(certificate)
    ssl_context.load_verify_locations(cadata=pem_certificate)
    async with httpx.AsyncClient(
        proxy=ohttp_relay_url, verify=ssl_context, timeout=30.0
    ) as client:
        response = await client.get(
            keys_url,
            headers={"Accept": "application/ohttp-keys"},
        )
        response.raise_for_status()
        return OhttpKeys.decode(response.content)
