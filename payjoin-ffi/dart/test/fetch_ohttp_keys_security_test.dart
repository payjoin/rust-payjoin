import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:payjoin/http.dart' as payjoin_http;

/// Spawns a TCP server on localhost that hands each accepted client to
/// [onClient]. The test is responsible for whatever protocol behavior it
/// wants to script (responses, hangs, premature close, etc.).
Future<ServerSocket> _startScriptedRelay(
  void Function(Socket client) onClient,
) async {
  final server = await ServerSocket.bind('127.0.0.1', 0);
  server.listen(onClient);
  return server;
}

void main() {
  group('fetchOhttpKeys hardening', () {
    test('rejects oversized CONNECT response', () async {
      // Stream more than the 16 KiB buffer cap with no \r\n\r\n in sight.
      final relay = await _startScriptedRelay((client) {
        client.listen((_) {}, onError: (_) {});
        client.add(Uint8List(32 * 1024));
      });
      try {
        await expectLater(
          payjoin_http.fetchOhttpKeys(
            ohttpRelayUrl: 'http://127.0.0.1:${relay.port}',
            directoryUrl: 'http://example.invalid/',
            timeout: const Duration(seconds: 3),
          ),
          throwsA(
            predicate(
              (e) =>
                  e is HttpException &&
                  e.message.contains('CONNECT response exceeded'),
            ),
          ),
        );
      } finally {
        await relay.close();
      }
    });

    test('rejects post-CONNECT bytes when directory is HTTPS', () async {
      // Pack a CONNECT 200 and "extra" payload into the same write so the
      // client's read picks them up together. Without the leftover check,
      // the bytes would be silently dropped before the TLS handshake.
      final relay = await _startScriptedRelay((client) {
        client.listen((_) {}, onError: (_) {});
        client.add(
          utf8.encode('HTTP/1.1 200 Connection Established\r\n\r\nEXTRA'),
        );
      });
      try {
        await expectLater(
          payjoin_http.fetchOhttpKeys(
            ohttpRelayUrl: 'http://127.0.0.1:${relay.port}',
            directoryUrl: 'https://localhost:9999/',
            timeout: const Duration(seconds: 3),
          ),
          throwsA(
            predicate(
              (e) =>
                  e is HttpException &&
                  e.message.contains('unexpected bytes after CONNECT'),
            ),
          ),
        );
      } finally {
        await relay.close();
      }
    });

    test('rejects oversized GET response', () async {
      // Two-phase scripted relay: respond 200 to CONNECT, then on the next
      // chunk (the GET request) flood the client past the 16 KiB cap.
      final relay = await _startScriptedRelay((client) {
        var sawConnect = false;
        client.listen((_) {
          if (!sawConnect) {
            sawConnect = true;
            client.add(
              utf8.encode('HTTP/1.1 200 Connection Established\r\n\r\n'),
            );
          } else {
            client.add(Uint8List(32 * 1024));
          }
        }, onError: (_) {});
      });
      try {
        await expectLater(
          payjoin_http.fetchOhttpKeys(
            ohttpRelayUrl: 'http://127.0.0.1:${relay.port}',
            directoryUrl: 'http://example.invalid/',
            timeout: const Duration(seconds: 3),
          ),
          throwsA(
            predicate(
              (e) =>
                  e is HttpException &&
                  e.message.contains('GET response exceeded'),
            ),
          ),
        );
      } finally {
        await relay.close();
      }
    });

    test('rejects status line with trailing junk after status code', () async {
      // Without the tightened regex, "HTTP/1.1 2009" would be parsed as 200
      // and the CONNECT would succeed against this malformed response.
      final relay = await _startScriptedRelay((client) {
        client.listen((_) {}, onError: (_) {});
        client.add(utf8.encode('HTTP/1.1 2009\r\n\r\n'));
      });
      try {
        await expectLater(
          payjoin_http.fetchOhttpKeys(
            ohttpRelayUrl: 'http://127.0.0.1:${relay.port}',
            directoryUrl: 'http://example.invalid/',
            timeout: const Duration(seconds: 3),
          ),
          throwsA(
            predicate(
              (e) =>
                  e is HttpException &&
                  e.message.contains('Invalid HTTP status line'),
            ),
          ),
        );
      } finally {
        await relay.close();
      }
    });
  });

  group('fetchOhttpKeys URL validation', () {
    test('rejects non-http(s) relay scheme', () async {
      await expectLater(
        payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'file:///tmp/foo',
          directoryUrl: 'http://example.com/',
        ),
        throwsArgumentError,
      );
    });

    test('rejects non-http(s) directory scheme', () async {
      await expectLater(
        payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http://example.com/',
          directoryUrl: 'file:///tmp/foo',
        ),
        throwsArgumentError,
      );
    });

    test('rejects empty relay host', () async {
      await expectLater(
        payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http:///pj',
          directoryUrl: 'http://example.com/',
        ),
        throwsArgumentError,
      );
    });

    test('rejects host containing control or unusual characters', () async {
      // The exact Uri.parse behavior on encoded CR/LF varies, but anything
      // outside the allowlist (letters/digits/.-_:) must be rejected.
      await expectLater(
        payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: 'http://exam%0aple.com/',
          directoryUrl: 'http://example.com/',
        ),
        throwsArgumentError,
      );
    });
  });
}
