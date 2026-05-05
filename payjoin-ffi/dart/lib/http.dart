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
/// relay connection. [timeout] is applied per network phase (TCP connect,
/// TLS handshake(s), CONNECT exchange, GET); the worst-case wall-clock is
/// roughly 4× this value.
Future<OhttpKeys> fetchOhttpKeys({
  required String ohttpRelayUrl,
  required String directoryUrl,
  Uint8List? certificate,
  Uint8List? relayCertificate,
  Duration timeout = const Duration(seconds: 10),
}) async {
  final relayUri = Uri.parse(ohttpRelayUrl);
  final keysUrl = Uri.parse(directoryUrl).resolve('/.well-known/ohttp-gateway');
  final relayIsHttps = relayUri.scheme == 'https';
  final destIsHttps = keysUrl.scheme == 'https';
  final destAuthority = '${keysUrl.host}:${keysUrl.port}';

  RawSocket socket =
      await (relayIsHttps
              ? RawSecureSocket.connect(
                  relayUri.host,
                  relayUri.port,
                  onBadCertificate: _certChecker(relayCertificate),
                )
              : RawSocket.connect(relayUri.host, relayUri.port))
          .timeout(
            timeout,
            onTimeout: () => throw HttpException('relay connect timeout'),
          );

  try {
    final tunnel = await _openConnectTunnel(socket, destAuthority, timeout);

    if (destIsHttps) {
      if (tunnel.leftover.isNotEmpty) {
        await tunnel.subscription.cancel();
        throw HttpException(
          'Relay sent ${tunnel.leftover.length} unexpected bytes after '
          'CONNECT response, before TLS handshake',
        );
      }
      socket =
          await RawSecureSocket.secure(
            socket,
            subscription: tunnel.subscription,
            host: keysUrl.host,
            onBadCertificate: _certChecker(certificate),
          ).timeout(
            timeout,
            onTimeout: () =>
                throw HttpException('directory TLS handshake timeout'),
          );
    }

    final response = await _sendGet(
      socket,
      keysUrl.path,
      keysUrl.host,
      destIsHttps ? null : tunnel.subscription,
      destIsHttps ? Uint8List(0) : tunnel.leftover,
      timeout,
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

class _TunnelResult {
  final StreamSubscription<RawSocketEvent> subscription;
  final Uint8List leftover;
  _TunnelResult(this.subscription, this.leftover);
}

Future<_TunnelResult> _openConnectTunnel(
  RawSocket socket,
  String authority,
  Duration timeout,
) async {
  final req = Uint8List.fromList(
    utf8.encode('CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n'),
  );

  int writePos = 0;
  final buf = <int>[];
  // Completes with the index of the CRLFCRLF that ends the response headers.
  final done = Completer<int>();
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
          if (buf.length > _maxResponseBytes) {
            socket.readEventsEnabled = false;
            done.completeError(
              HttpException(
                'CONNECT response exceeded $_maxResponseBytes bytes',
              ),
            );
            return;
          }
          final i = _indexOfCrlfCrlf(buf);
          if (i != -1) {
            socket.readEventsEnabled = false;
            done.complete(i);
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

  final int headerEnd;
  try {
    headerEnd = await done.future.timeout(
      timeout,
      onTimeout: () => throw HttpException('CONNECT timeout'),
    );
  } catch (_) {
    await sub.cancel();
    rethrow;
  }

  final status = latin1.decode(buf.sublist(0, headerEnd)).split('\r\n').first;
  if (_parseStatusCode(status) != 200) {
    await sub.cancel();
    throw HttpException('CONNECT failed: $status');
  }

  final leftoverStart = headerEnd + 4;
  final leftover = leftoverStart < buf.length
      ? Uint8List.fromList(buf.sublist(leftoverStart))
      : Uint8List(0);
  return _TunnelResult(sub, leftover);
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
  Uint8List initialBuffer,
  Duration timeout,
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
  final buf = <int>[...initialBuffer];
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
        if (buf.length > _maxResponseBytes) {
          socket.readEventsEnabled = false;
          done.completeError(
            HttpException('GET response exceeded $_maxResponseBytes bytes'),
          );
          return;
        }
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

  final responseBytes = await done.future.timeout(
    timeout,
    onTimeout: () => throw HttpException('GET timeout'),
  );
  await sub.cancel();

  return _parseResponse(responseBytes);
}

const _maxBodyBytes = 1024;

// Hard cap on accumulated bytes during the CONNECT and GET reads. Prevents an
// untrusted relay or directory from forcing unbounded buffer growth before the
// later body-cap check can fire. Sized well above any plausible legitimate
// response (headers + a sub-1 KiB OhttpKeys body).
const _maxResponseBytes = 16 * 1024;

_Response _parseResponse(Uint8List responseBytes) {
  final headerEnd = _indexOfCrlfCrlf(responseBytes);
  if (headerEnd == -1) {
    throw HttpException('Malformed HTTP response');
  }

  final headerBlock = latin1.decode(responseBytes.sublist(0, headerEnd));
  final lines = headerBlock.split('\r\n');
  final statusCode = _parseStatusCode(lines.first);

  final headers = <String, String>{};
  for (var i = 1; i < lines.length; i++) {
    final c = lines[i].indexOf(':');
    if (c <= 0) continue;
    headers[lines[i].substring(0, c).toLowerCase()] = lines[i]
        .substring(c + 1)
        .trim();
  }

  final hasCL = headers.containsKey('content-length');
  final hasTE = headers.containsKey('transfer-encoding');
  if (hasCL && hasTE) {
    throw HttpException('Content-Length and Transfer-Encoding both set');
  }

  final bodyStart = headerEnd + 4;
  final raw = (bodyStart >= responseBytes.length)
      ? Uint8List(0)
      : Uint8List.sublistView(responseBytes, bodyStart);

  if (hasCL) {
    final cl = int.tryParse(headers['content-length']!);
    if (cl == null || cl < 0) {
      throw HttpException('Invalid Content-Length');
    }
    if (cl > _maxBodyBytes) {
      throw HttpException('Content-Length exceeds 1 KiB cap');
    }
    if (raw.length < cl) {
      throw HttpException('Short body: expected $cl, got ${raw.length}');
    }
    return _Response(statusCode, Uint8List.sublistView(raw, 0, cl));
  } else if (hasTE) {
    if (headers['transfer-encoding']!.toLowerCase() != 'chunked') {
      throw HttpException('Unsupported Transfer-Encoding');
    }
    return _Response(statusCode, _decodeSingleChunk(raw));
  } else {
    throw HttpException(
      'No framing header (Content-Length or Transfer-Encoding required)',
    );
  }
}

Uint8List _decodeSingleChunk(Uint8List raw) {
  // Accepts exactly: <hex-size>\r\n<body>\r\n0\r\n\r\n
  // Rejects: chunk-extensions, trailers, multi-chunk, body > 1 KiB.
  final crlf1 = _indexOfCrlf(raw, 0);
  if (crlf1 == -1) {
    throw HttpException('Malformed chunk size line');
  }
  final sizeLine = latin1.decode(raw.sublist(0, crlf1));
  if (sizeLine.contains(';')) {
    throw HttpException('Chunk extensions not supported');
  }
  final n = int.tryParse(sizeLine.trim(), radix: 16);
  if (n == null || n < 0) {
    throw HttpException('Invalid chunk size');
  }
  if (n > _maxBodyBytes) {
    throw HttpException('Chunk size exceeds 1 KiB cap');
  }
  final bodyStart = crlf1 + 2;
  // Body, then \r\n, then "0\r\n\r\n" — total 5 bytes after the body.
  if (raw.length < bodyStart + n + 2 + 5) {
    throw HttpException('Short chunked response');
  }
  if (raw[bodyStart + n] != 0x0d || raw[bodyStart + n + 1] != 0x0a) {
    throw HttpException('Missing chunk terminator');
  }
  final term = bodyStart + n + 2;
  if (raw[term] != 0x30 ||
      raw[term + 1] != 0x0d ||
      raw[term + 2] != 0x0a ||
      raw[term + 3] != 0x0d ||
      raw[term + 4] != 0x0a) {
    throw HttpException('Multi-chunk responses or trailers not supported');
  }
  return Uint8List.sublistView(raw, bodyStart, bodyStart + n);
}

int _indexOfCrlf(List<int> bytes, int from) {
  for (var i = from; i + 1 < bytes.length; i++) {
    if (bytes[i] == 0x0d && bytes[i + 1] == 0x0a) return i;
  }
  return -1;
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
