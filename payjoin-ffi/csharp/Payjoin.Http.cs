using System;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Payjoin.Http
{
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
