library http;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'payjoin.dart' show OhttpKeys;

/// Fetches the OHTTP keys from a payjoin directory through an OHTTP relay
/// proxy so the directory never observes the client IP address.
///
/// [ohttpRelayUrl] is the HTTP(S) CONNECT proxy that tunnels the request.
/// HTTPS relays are supported via TLS-in-TLS. [directoryUrl] is the payjoin
/// directory whose `/.well-known/ohttp-gateway` endpoint is queried.
/// [certificate] is the DER-encoded certificate the directory is expected to
/// present, intended for local test setups that use a self-signed directory
/// certificate; leave unset in production so normal system trust-root
/// validation applies. [relayCertificate] serves the same purpose for the
/// relay connection.
Future<OhttpKeys> fetchOhttpKeys({
  required String ohttpRelayUrl,
  required String directoryUrl,
  Uint8List? certificate,
  Uint8List? relayCertificate,
}) async {
  final relayUri = Uri.parse(ohttpRelayUrl);
  final keysUrl = Uri.parse(directoryUrl).resolve('/.well-known/ohttp-gateway');
  final relayIsHttps = relayUri.scheme == 'https';
  final destIsHttps = keysUrl.scheme == 'https';
  final destAuthority = '${keysUrl.host}:${keysUrl.port}';

  RawSocket socket = relayIsHttps
      ? await RawSecureSocket.connect(
          relayUri.host,
          relayUri.port,
          onBadCertificate: _certChecker(relayCertificate),
        )
      : await RawSocket.connect(relayUri.host, relayUri.port);

  try {
    final tunnelSub = await _openConnectTunnel(socket, destAuthority);

    if (destIsHttps) {
      socket = await RawSecureSocket.secure(
        socket,
        subscription: tunnelSub,
        host: keysUrl.host,
        onBadCertificate: _certChecker(certificate),
      );
    }

    final response = await _sendGet(
      socket,
      keysUrl.path,
      keysUrl.host,
      destIsHttps ? null : tunnelSub,
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw HttpException(
        'fetchOhttpKeys failed: HTTP ${response.statusCode}',
        uri: keysUrl,
      );
    }
    return OhttpKeys.decode(bytes: response.body);
  } finally {
    socket.close();
  }
}

bool Function(X509Certificate)? _certChecker(Uint8List? der) {
  if (der == null || der.isEmpty) return null;
  return (cert) => _bytesEqual(cert.der, der);
}

Future<StreamSubscription<RawSocketEvent>> _openConnectTunnel(
  RawSocket socket,
  String authority,
) async {
  final req = Uint8List.fromList(
    utf8.encode('CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n'),
  );

  int writePos = 0;
  final buf = <int>[];
  final done = Completer<String>();
  late final StreamSubscription<RawSocketEvent> sub;

  sub = socket.listen(
    (event) {
      if (done.isCompleted) return;
      switch (event) {
        case RawSocketEvent.write:
          if (writePos < req.length) {
            writePos += socket.write(req, writePos);
            if (writePos >= req.length) socket.writeEventsEnabled = false;
          }
        case RawSocketEvent.read:
          final chunk = socket.read();
          if (chunk != null) buf.addAll(chunk);
          final i = _indexOfCrlfCrlf(buf);
          if (i != -1) {
            socket.readEventsEnabled = false;
            done.complete(utf8.decode(buf.sublist(0, i)));
          }
        case RawSocketEvent.readClosed:
        case RawSocketEvent.closed:
          done.completeError(HttpException('Connection closed during CONNECT'));
      }
    },
    onError: (Object e) {
      if (!done.isCompleted) done.completeError(e);
    },
  );

  socket.writeEventsEnabled = true;
  socket.readEventsEnabled = true;

  final headers = await done.future;
  final status = headers.split('\r\n').first;
  if (_parseStatusCode(status) != 200) {
    await sub.cancel();
    throw HttpException('CONNECT failed: $status');
  }
  return sub;
}

int _parseStatusCode(String statusLine) {
  final m = RegExp(r'^HTTP/1\.[01] (\d{3})').firstMatch(statusLine);
  if (m == null) {
    throw HttpException('Invalid HTTP status line: $statusLine');
  }
  return int.parse(m.group(1)!);
}

class _Response {
  final int statusCode;
  final Uint8List body;
  _Response(this.statusCode, this.body);
}

Future<_Response> _sendGet(
  RawSocket socket,
  String path,
  String host,
  StreamSubscription<RawSocketEvent>? existingSub,
) async {
  final req = Uint8List.fromList(
    utf8.encode(
      'GET $path HTTP/1.1\r\n'
      'Host: $host\r\n'
      'Accept: application/ohttp-keys\r\n'
      'Connection: close\r\n'
      '\r\n',
    ),
  );

  int writePos = 0;
  final buf = <int>[];
  final done = Completer<Uint8List>();

  void handler(RawSocketEvent event) {
    if (done.isCompleted) return;
    switch (event) {
      case RawSocketEvent.write:
        if (writePos < req.length) {
          writePos += socket.write(req, writePos);
          if (writePos >= req.length) socket.writeEventsEnabled = false;
        }
      case RawSocketEvent.read:
        final chunk = socket.read();
        if (chunk != null) buf.addAll(chunk);
      case RawSocketEvent.readClosed:
      case RawSocketEvent.closed:
        done.complete(Uint8List.fromList(buf));
    }
  }

  late final StreamSubscription<RawSocketEvent> sub;
  if (existingSub != null) {
    sub = existingSub;
    sub.onData(handler);
    sub.onError((Object e) {
      if (!done.isCompleted) done.completeError(e);
    });
  } else {
    sub = socket.listen(
      handler,
      onError: (Object e) {
        if (!done.isCompleted) done.completeError(e);
      },
    );
  }

  socket.writeEventsEnabled = true;
  socket.readEventsEnabled = true;

  final responseBytes = await done.future;
  await sub.cancel();

  final headerEnd = _indexOfCrlfCrlf(responseBytes);
  if (headerEnd == -1) {
    throw HttpException('Malformed HTTP response');
  }
  final statusLine = utf8
      .decode(responseBytes.sublist(0, headerEnd))
      .split('\r\n')
      .first;
  return _Response(
    _parseStatusCode(statusLine),
    Uint8List.sublistView(responseBytes, headerEnd + 4),
  );
}

int _indexOfCrlfCrlf(List<int> bytes) {
  for (var i = 0; i <= bytes.length - 4; i++) {
    if (bytes[i] == 0x0d &&
        bytes[i + 1] == 0x0a &&
        bytes[i + 2] == 0x0d &&
        bytes[i + 3] == 0x0a) {
      return i;
    }
  }
  return -1;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
