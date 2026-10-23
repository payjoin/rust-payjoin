package org.payjoindevkit;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * HTTP client for the v2 integration harness. A near-direct Java port of the Kotlin bindings'
 * {@code TestHttp.kt} (same class, same behavior) - that file is itself already close to plain
 * Java, so this only adjusts syntax, not approach.
 *
 * <p>The in-process directory serves HTTPS with a self-signed certificate from
 * {@code payjoin-test-utils} ({@code local_cert_key()}, SANs {@code localhost} and
 * {@code 0.0.0.0}). This client trusts that one certificate and nothing else, and sends every
 * request through the OHTTP relay as an HTTP proxy.
 */
final class TestHttp implements AutoCloseable {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private final HttpClient client;

    TestHttp(TestServices services) throws Exception {
        this.client = buildClient(services);
    }

    byte[] post(Request request) throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder(URI.create(request.url()))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", request.contentType())
                .POST(HttpRequest.BodyPublishers.ofByteArray(request.body()))
                .build();
        HttpResponse<byte[]> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            throw new IllegalStateException("HTTP " + status + " posting to " + request.url());
        }
        return response.body();
    }

    @Override
    public void close() {
        client.close();
    }

    private static HttpClient buildClient(TestServices services) throws Exception {
        Duration timeout = Duration.ofSeconds(30);
        URI relay = URI.create(services.ohttpRelayUrl());
        int port = relay.getPort() == -1 ? 80 : relay.getPort();
        return HttpClient.newBuilder()
                .connectTimeout(timeout)
                .sslContext(sslContextTrusting(services.cert()))
                .proxy(ProxySelector.of(new InetSocketAddress(relay.getHost(), port)))
                .build();
    }

    private static SSLContext sslContextTrusting(byte[] certDer) throws Exception {
        var cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("directory", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        return sslContext;
    }
}
