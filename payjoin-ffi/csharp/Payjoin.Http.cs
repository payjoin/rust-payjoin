using System;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Payjoin.Http
{
    /// <summary>
    /// Fetch OHTTP keys from a payjoin directory through an OHTTP relay.
    /// </summary>
    /// <remarks>
    /// When multiple relays are configured, callers should pick one at random per request
    /// to avoid a fixed contact pattern at the network layer.
    ///
    /// Random selection only helps if the relay list itself is not identifying: prefer a shared
    /// relay list and discourage isolated infrastructure that other apps don't use, since a
    /// distinctive list fingerprints the client regardless of how a relay is picked from it.
    ///
    /// Sender and receiver have distinct request patterns:
    /// - Receiver: long-poll GETs, then a POST
    /// - Sender: a POST, then long-poll GETs
    ///
    /// OHTTP does not hide the client IP from the relay. A relay that sees the same
    /// client repeatedly can observe its access patterns to infer whether
    /// the IP is associated with a sender or receiver, potentially linking to identity or
    /// location. Based on when a session ends it may be easier to correctly guess
    /// whether a transaction is a PayJoin. The IP address linked information may
    /// additionally aid in cluster analysis, for example whether a cluster's temporal
    /// patterns are consistent with a location guess for the IP address.
    ///
    /// Health checks: some clients call <see cref="GetOhttpKeysAsync"/> periodically to
    /// verify that the directory and relay infrastructure is reachable. Given the threat
    /// model above, this is acceptable only when:
    /// - The call is not triggered on any deterministic, recurring event
    ///   (e.g. app startup, periodic timer). Prefer user-initiated actions
    ///   (e.g. opening a settings/status screen) or piggybacking on operations
    ///   the user already triggered (e.g. resuming an existing session).
    /// - The caller throttles invocations so they don't produce a recurring
    ///   timing pattern observable by the relay.
    ///
    /// A health check has a distinct traffic pattern from a real payjoin request
    /// and is not temporally tied to any onchain broadcast, but repeated calls
    /// still expose the client IP to the relay.
    /// </remarks>
    internal sealed class OhttpKeysClient : IDisposable
    {
        private readonly HttpClient _client;
        private readonly HttpClientHandler _handler;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of <see cref="OhttpKeysClient"/> configured to route
        /// requests through an OHTTP relay proxy, ensuring the client IP address is never
        /// revealed to the payjoin directory.
        /// </summary>
        /// <remarks>
        /// The instance should be kept long-lived to allow the underlying
        /// <see cref="HttpClientHandler"/> to reuse connections and avoid socket exhaustion.
        /// </remarks>
        /// <param name="ohttpRelayUrl">
        /// The HTTP CONNECT method proxy through which requests are routed.
        /// </param>
        /// <param name="certificate">The DER-encoded certificate to use for local HTTPS connections.</param>
        public OhttpKeysClient(System.Uri ohttpRelayUrl, byte[]? certificate = null)
        {
            ArgumentNullException.ThrowIfNull(ohttpRelayUrl);

            _handler = new HttpClientHandler
            {
                Proxy = new System.Net.WebProxy(ohttpRelayUrl),
                UseProxy = true,
                CheckCertificateRevocationList = true
            };

            if (certificate is { Length: > 0 })
            {
                _handler.ServerCertificateCustomValidationCallback = (_, serverCert, _, _) =>
                    serverCert is not null &&
                    certificate.SequenceEqual(serverCert.GetRawCertData());
            }

            _client = new HttpClient(_handler);
        }

        /// <summary>
        /// Fetches the OHTTP keys from the specified payjoin directory.
        /// </summary>
        /// <param name="directoryUrl">
        /// The payjoin directory from which to fetch the OHTTP keys. This directory stores
        /// and forwards payjoin client payloads.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        /// <returns>The decoded <see cref="OhttpKeys"/> from the payjoin directory.</returns>
        public async Task<OhttpKeys> GetOhttpKeysAsync(System.Uri directoryUrl, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(directoryUrl);

            var keysUrl = new System.Uri(directoryUrl, "/.well-known/ohttp-gateway");

            using var request = new HttpRequestMessage(HttpMethod.Get, keysUrl);
            request.Headers.Accept.ParseAdd("application/ohttp-keys");

            using var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var ohttpKeysBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            return OhttpKeys.Decode(ohttpKeysBytes);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                _client.Dispose();
                _handler.Dispose();
            }

            _disposed = true;
        }
    }
}
