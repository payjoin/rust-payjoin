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
