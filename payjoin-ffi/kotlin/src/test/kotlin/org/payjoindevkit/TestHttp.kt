package org.payjoindevkit

import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Duration
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * HTTP client for the v2 integration harness.
 *
 * The in-process directory serves HTTPS with a self-signed certificate from
 * `payjoin-test-utils` (`local_cert_key()`, SANs `localhost` and `0.0.0.0`).
 * This client trusts that one certificate and nothing else, and sends every
 * request through the OHTTP relay as an HTTP proxy.
 */
class TestHttp(services: TestServices) : AutoCloseable {
    private val requestTimeout: Duration = Duration.ofSeconds(30)
    private val client: HttpClient = buildClient(services)

    fun post(request: Request): ByteArray {
        val httpRequest = HttpRequest.newBuilder(URI.create(request.url))
            .timeout(requestTimeout)
            .header("Content-Type", request.contentType)
            .POST(HttpRequest.BodyPublishers.ofByteArray(request.body))
            .build()
        val response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray())
        val status = response.statusCode()
        if (status < 200 || status >= 300) {
            throw IllegalStateException("HTTP $status posting to ${request.url}")
        }
        return response.body()
    }

    override fun close() {
        client.close()
    }

    companion object {
        private fun buildClient(services: TestServices): HttpClient {
            val timeout = Duration.ofSeconds(30)
            val relay = URI.create(services.ohttpRelayUrl())
            val port = if (relay.port == -1) 80 else relay.port
            return HttpClient.newBuilder()
                .connectTimeout(timeout)
                .sslContext(sslContextTrusting(services.cert()))
                .proxy(ProxySelector.of(InetSocketAddress(relay.host, port)))
                .build()
        }

        private fun sslContextTrusting(certDer: ByteArray): SSLContext {
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certDer))
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(null, null)
            keyStore.setCertificateEntry("directory", cert)
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(keyStore)
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, tmf.trustManagers, null)
            return sslContext
        }
    }
}

internal inline fun <T : Disposable, R> T.useDisposable(block: (T) -> R): R =
    try { block(this) } finally { destroy() }
