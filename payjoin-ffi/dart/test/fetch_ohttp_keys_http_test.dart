import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:payjoin/http.dart' as payjoin_http;
import 'package:payjoin/payjoin.dart' as payjoin;

const _localhostCertPem =
    '-----BEGIN CERTIFICATE-----\n'
    'MIIBmDCCAT+gAwIBAgIUZmuZcOJ7AKPKxmXUdl8mALQqLjkwCgYIKoZIzj0EAwIw\n'
    'FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQyMzAyNDYzNloXDTM2MDQyMDAy\n'
    'NDYzNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n'
    'AQcDQgAEMbQWJrdEdXIX4hHIcRcpMlRY8+YpH9X9e5DkreID6fVh9tRIoqFSURL1\n'
    'L8q2mLIxLl4W5L4HRJuPkKVCiUI9/qNvMG0wHQYDVR0OBBYEFKih01KF98UDEZg6\n'
    'FOo4nHUVpKGLMB8GA1UdIwQYMBaAFKih01KF98UDEZg6FOo4nHUVpKGLMA8GA1Ud\n'
    'EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49\n'
    'BAMCA0cAMEQCIGCqHp/SwHSxkOxECoU6qEq+/kapotRRTSe3SsWRjQ38AiBITEBf\n'
    'j3sL7LkmerQLhWwl7u7UMHb0rBeuFbSmRmxCGA==\n'
    '-----END CERTIFICATE-----';

const _localhostKeyPem =
    '-----BEGIN PRIVATE KEY-----\n'
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUZxLsCYEttJjv9WN\n'
    '6xUtRwFu40pdAk80R8tgCIlqbhahRANCAAQxtBYmt0R1chfiEchxFykyVFjz5ikf\n'
    '1f17kOSt4gPp9WH21EiioVJREvUvyraYsjEuXhbkvgdEm4+QpUKJQj3+\n'
    '-----END PRIVATE KEY-----';

final _ohttpKeysBytes = Uint8List.fromList(
  _hexToBytes(
    '01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad'
    '2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382'
    'af588d370957000400010003',
  ),
);

List<int> _hexToBytes(String hex) {
  final bytes = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return bytes;
}

Uint8List _localhostCertDer() => base64.decode(
  _localhostCertPem.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''),
);

SecurityContext _localhostSecurityContext() {
  return SecurityContext()
    ..useCertificateChainBytes(utf8.encode(_localhostCertPem))
    ..usePrivateKeyBytes(utf8.encode(_localhostKeyPem));
}

List<int> _contentLengthResponse() {
  return [
    ...ascii.encode(
      'HTTP/1.1 200 OK\r\n'
      'Content-Length: ${_ohttpKeysBytes.length}\r\n'
      '\r\n',
    ),
    ..._ohttpKeysBytes,
  ];
}

List<int> _chunkedResponseWithExtension() {
  return [
    ...ascii.encode(
      'HTTP/1.1 200 OK\r\n'
      'Transfer-Encoding: chunked\r\n'
      '\r\n'
      '${_ohttpKeysBytes.length.toRadixString(16)};proxy=caddy\r\n',
    ),
    ..._ohttpKeysBytes,
    ...ascii.encode('\r\n0\r\n\r\n'),
  ];
}

int _headerEnd(List<int> bytes) {
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

Future<SecureServerSocket> _startSecureDirectory(List<int> response) async {
  final server = await SecureServerSocket.bind(
    'localhost',
    0,
    _localhostSecurityContext(),
  );
  server.listen((client) {
    final buffer = <int>[];
    client.listen((chunk) {
      buffer.addAll(chunk);
      if (_headerEnd(buffer) == -1) return;
      client.add(response);
    }, onError: (_) => client.destroy());
  });
  return server;
}

Future<ServerSocket> _startHttpConnectProxy() async {
  final server = await ServerSocket.bind('localhost', 0);
  server.listen(_handleConnectProxyClient);
  return server;
}

Future<SecureServerSocket> _startHttpsConnectProxy() async {
  final server = await SecureServerSocket.bind(
    'localhost',
    0,
    _localhostSecurityContext(),
  );
  server.listen(_handleConnectProxyClient);
  return server;
}

void _handleConnectProxyClient(Socket client) {
  final buffer = <int>[];
  late StreamSubscription<List<int>> subscription;
  subscription = client.listen((chunk) {
    buffer.addAll(chunk);
    final headerEnd = _headerEnd(buffer);
    if (headerEnd == -1) return;
    final request = latin1.decode(buffer.sublist(0, headerEnd));
    final match = RegExp(
      r'^CONNECT ([^:]+):(\d+) HTTP/1\.1',
    ).firstMatch(request);
    if (match == null) {
      client.destroy();
      return;
    }

    subscription.pause();
    Socket.connect(match.group(1)!, int.parse(match.group(2)!))
        .then((target) {
          client.add(
            ascii.encode('HTTP/1.1 200 Connection Established\r\n\r\n'),
          );
          subscription
            ..onData(target.add)
            ..onError((_) => target.destroy())
            ..onDone(target.destroy);
          target.listen(
            client.add,
            onDone: client.destroy,
            onError: (_) => client.destroy(),
          );
          subscription.resume();
        })
        .catchError((_) {
          client.destroy();
        });
  }, onError: (_) => client.destroy());
}

void main() {
  group('fetchOhttpKeys HTTP handling', () {
    test('uses Content-Length without waiting for connection close', () async {
      final directory = await _startSecureDirectory(_contentLengthResponse());
      final relay = await _startHttpConnectProxy();
      try {
        final keys = await payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http://localhost:${relay.port}',
          directoryUrl: 'https://localhost:${directory.port}',
          certificate: _localhostCertDer(),
          timeout: const Duration(seconds: 2),
        );
        expect(keys, isA<payjoin.OhttpKeys>());
      } finally {
        await relay.close();
        await directory.close();
      }
    });

    test('accepts chunk extensions on chunked responses', () async {
      final directory = await _startSecureDirectory(
        _chunkedResponseWithExtension(),
      );
      final relay = await _startHttpConnectProxy();
      try {
        final keys = await payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http://localhost:${relay.port}',
          directoryUrl: 'https://localhost:${directory.port}',
          certificate: _localhostCertDer(),
          timeout: const Duration(seconds: 2),
        );
        expect(keys, isA<payjoin.OhttpKeys>());
      } finally {
        await relay.close();
        await directory.close();
      }
    });

    test('supports HTTPS CONNECT relay to HTTPS directory', () async {
      final directory = await _startSecureDirectory(_contentLengthResponse());
      final relay = await _startHttpsConnectProxy();
      try {
        final keys = await payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'https://localhost:${relay.port}',
          directoryUrl: 'https://localhost:${directory.port}',
          certificate: _localhostCertDer(),
          relayCertificate: _localhostCertDer(),
          timeout: const Duration(seconds: 3),
        );
        expect(keys, isA<payjoin.OhttpKeys>());
      } finally {
        await relay.close();
        await directory.close();
      }
    });

    test('rejects non-http relay schemes', () async {
      await expectLater(
        payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'socks5://127.0.0.1:9000',
          directoryUrl: 'https://example.com',
        ),
        throwsArgumentError,
      );
    });

    test('rejects underscore in domain hosts', () async {
      await expectLater(
        payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http://bad_host.example',
          directoryUrl: 'https://example.com',
        ),
        throwsArgumentError,
      );
    });

    test('rejects userinfo in URLs', () async {
      await expectLater(
        payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http://user@example.com',
          directoryUrl: 'https://example.com',
        ),
        throwsArgumentError,
      );
    });

    test('accepts bracketed IPv6 relay hosts', () async {
      final directory = await _startSecureDirectory(_contentLengthResponse());
      final relay = await ServerSocket.bind(InternetAddress.loopbackIPv6, 0);
      relay.listen(_handleConnectProxyClient);
      try {
        final keys = await payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http://[::1]:${relay.port}',
          directoryUrl: 'https://localhost:${directory.port}',
          certificate: _localhostCertDer(),
          timeout: const Duration(seconds: 2),
        );
        expect(keys, isA<payjoin.OhttpKeys>());
      } finally {
        await relay.close();
        await directory.close();
      }
    });
  });
}
