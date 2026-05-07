library http;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'payjoin.dart' show OhttpKeys;

/// Fetches the OHTTP keys from a payjoin directory through an OHTTP relay
/// proxy so the directory never observes the client IP address.
///
/// [ohttpRelayUrl] is the HTTP(S) CONNECT proxy that tunnels the request.
/// [directoryUrl] is the payjoin directory whose `/.well-known/ohttp-gateway`
/// endpoint is queried. [certificate] is the DER-encoded certificate the
/// directory is expected to present, intended for local test setups that use a
/// self-signed directory certificate; leave unset in production so normal
/// system trust-root validation applies. [relayCertificate] serves the same
/// purpose for an HTTPS relay.
Future<OhttpKeys> fetchOhttpKeys({
  required String ohttpRelayUrl,
  required String directoryUrl,
  Uint8List? certificate,
  Uint8List? relayCertificate,
  Duration timeout = const Duration(seconds: 10),
}) async {
  final relayUri = Uri.parse(ohttpRelayUrl);
  _validateUrl(relayUri, 'ohttpRelayUrl', ohttpRelayUrl);
  final keysUrl = Uri.parse(directoryUrl).resolve('/.well-known/ohttp-gateway');
  _validateUrl(keysUrl, 'directoryUrl', directoryUrl);

  final client = HttpClient()..connectionTimeout = timeout;
  client.findProxy = (_) => 'PROXY ${_proxyHost(relayUri)}:${_port(relayUri)}';

  final directoryCertificateCallback = _httpCertificateCallback(certificate);
  if (directoryCertificateCallback != null) {
    client.badCertificateCallback = directoryCertificateCallback;
  }

  if (relayUri.scheme == 'https') {
    // Dart's proxy grammar only accepts DIRECT and PROXY. Advertising an HTTPS
    // relay as PROXY still lets HttpClient do CONNECT, while connectionFactory
    // opens the underlying TLS connection to the relay.
    client.connectionFactory = (_, proxyHost, proxyPort) {
      if (proxyHost == null || proxyPort == null) {
        throw StateError('fetchOhttpKeys expected a proxy connection');
      }
      return SecureSocket.startConnect(
        proxyHost,
        proxyPort,
        onBadCertificate: _secureSocketCertificateCallback(relayCertificate),
      );
    };
  }

  try {
    final request = await client
        .getUrl(keysUrl)
        .timeout(
          timeout,
          onTimeout: () => throw HttpException(
            'fetchOhttpKeys connection timed out',
            uri: keysUrl,
          ),
        );
    request.headers.set(HttpHeaders.acceptHeader, 'application/ohttp-keys');

    final response = await request.close().timeout(
      timeout,
      onTimeout: () =>
          throw HttpException('fetchOhttpKeys request timed out', uri: keysUrl),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw HttpException(
        'fetchOhttpKeys failed: HTTP ${response.statusCode}',
        uri: keysUrl,
      );
    }
    final bodyBytes = await _collectBytes(response).timeout(
      timeout,
      onTimeout: () => throw HttpException(
        'fetchOhttpKeys response timed out',
        uri: keysUrl,
      ),
    );
    return OhttpKeys.decode(bytes: bodyBytes);
  } finally {
    client.close(force: true);
  }
}

bool Function(X509Certificate, String, int)? _httpCertificateCallback(
  Uint8List? certificate,
) {
  if (certificate == null || certificate.isEmpty) return null;
  return (cert, _, _) => _bytesEqual(cert.der, certificate);
}

bool Function(X509Certificate)? _secureSocketCertificateCallback(
  Uint8List? certificate,
) {
  if (certificate == null || certificate.isEmpty) return null;
  return (cert) => _bytesEqual(cert.der, certificate);
}

void _validateUrl(Uri uri, String parameter, String source) {
  if (uri.scheme != 'http' && uri.scheme != 'https') {
    throw ArgumentError.value(
      source,
      parameter,
      'scheme must be http or https',
    );
  }
  if (uri.userInfo.isNotEmpty || !_isValidHost(uri, source)) {
    throw ArgumentError.value(source, parameter, 'invalid host');
  }
  final port = _port(uri);
  if (port < 1 || port > 65535) {
    throw ArgumentError.value(source, parameter, 'invalid port');
  }
}

final _domainHostPattern = RegExp(r'^[A-Za-z0-9.-]+$');

bool _isValidHost(Uri uri, String source) {
  final host = uri.host;
  if (host.isEmpty) return false;
  if (_domainHostPattern.hasMatch(host)) return true;
  if (!host.contains(':')) return false;

  final authorityStart = source.indexOf('://');
  if (authorityStart == -1) return false;
  return source.startsWith('[', authorityStart + 3);
}

int _port(Uri uri) {
  final port = uri.port;
  if (port != 0) return port;
  return uri.scheme == 'https' ? 443 : 80;
}

String _proxyHost(Uri uri) {
  return uri.host.contains(':') ? '[${uri.host}]' : uri.host;
}

const _maxBodyBytes = 1024;

Future<Uint8List> _collectBytes(Stream<List<int>> stream) async {
  final builder = BytesBuilder(copy: false);
  await for (final chunk in stream) {
    if (builder.length + chunk.length > _maxBodyBytes) {
      throw HttpException('response body exceeds $_maxBodyBytes bytes');
    }
    builder.add(chunk);
  }
  return builder.toBytes();
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
