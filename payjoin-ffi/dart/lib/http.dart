library http;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'payjoin.dart' show OhttpKeys;

/// Fetches the OHTTP keys from a payjoin directory through an OHTTP relay
/// proxy so the directory never observes the client IP address.
///
/// [ohttpRelayUrl] is the HTTP CONNECT proxy that tunnels the request.
/// [directoryUrl] is the payjoin directory whose `/.well-known/ohttp-gateway`
/// endpoint is queried. [certificate] is the DER-encoded
/// certificate the directory is expected to present, intended for
/// local test setups that use a self-signed directory certificate; leave
/// unset in production so normal system trust-root validation applies.
Future<OhttpKeys> fetchOhttpKeys({
  required String ohttpRelayUrl,
  required String directoryUrl,
  Uint8List? certificate,
}) async {
  final relayUri = Uri.parse(ohttpRelayUrl);
  final keysUrl = Uri.parse(directoryUrl).resolve('/.well-known/ohttp-gateway');

  final client = HttpClient();
  client.findProxy = (_) => 'PROXY ${relayUri.host}:${relayUri.port}';
  if (certificate != null && certificate.isNotEmpty) {
    client.badCertificateCallback = (cert, _, _) =>
        _bytesEqual(cert.der, certificate);
  }

  try {
    final request = await client.getUrl(keysUrl);
    request.headers.set(HttpHeaders.acceptHeader, 'application/ohttp-keys');
    final response = await request.close();
    final bodyBytes = await _collectBytes(response);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw HttpException(
        'fetchOhttpKeys failed: HTTP ${response.statusCode}',
        uri: keysUrl,
      );
    }
    return OhttpKeys.decode(bytes: bodyBytes);
  } finally {
    client.close(force: true);
  }
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Future<Uint8List> _collectBytes(Stream<List<int>> stream) async {
  final builder = BytesBuilder(copy: false);
  await for (final chunk in stream) {
    builder.add(chunk);
  }
  return builder.toBytes();
}
