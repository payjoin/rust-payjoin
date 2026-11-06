import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:payjoin/payjoin.dart' as payjoin;

// The bundled library is built without the test utilities, so the unit tests
// that call them cannot run here.
class _ReceiverPersister implements payjoin.JsonReceiverSessionPersister {
  final List<String> events = [];

  @override
  void save(String event) => events.add(event);

  @override
  List<String> load() => events;

  @override
  void close() {}
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  test('parses a payjoin URI', () {
    final uri = payjoin.Uri.parse(
      uri: 'bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com',
    );
    expect(uri.address(), '12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX');
  });

  test('rejects userinfo in the payjoin URL', () {
    expect(
      () => payjoin.Uri.parse(
        uri: 'bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example@evil.com',
      ),
      throwsA(isA<payjoin.UriParseException>()),
    );
  });

  test('persists a new receiver session', () {
    final persister = _ReceiverPersister();
    payjoin.ReceiverBuilder(
      address: 'tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4',
      directory: 'https://example.com',
      ohttpKeys: payjoin.OhttpKeys.decode(
        bytes: Uint8List.fromList(
          hex.decode(
            '01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003',
          ),
        ),
      ),
    ).build().save(persister: persister);
    expect(
      payjoin.replayReceiverEventLog(persister: persister).state(),
      isA<payjoin.InitializedReceiveSession>(),
    );
  });
}
