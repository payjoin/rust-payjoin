import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:test/test.dart';
import "package:payjoin/payjoin.dart" as payjoin;

class InMemoryReceiverPersister
    implements payjoin.JsonReceiverSessionPersister {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemoryReceiverPersister(this.id);

  @override
  void save(String event) {
    events.add(event);
  }

  @override
  List<String> load() {
    return events;
  }

  @override
  void close() {
    closed = true;
  }
}

class InMemorySenderPersister implements payjoin.JsonSenderSessionPersister {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemorySenderPersister(this.id);

  @override
  void save(String event) {
    events.add(event);
  }

  @override
  List<String> load() {
    return events;
  }

  @override
  void close() {
    closed = true;
  }
}

class InMemoryReceiverPersisterAsync
    implements payjoin.JsonReceiverSessionPersisterAsync {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemoryReceiverPersisterAsync(this.id);

  @override
  Future<void> save(String event) async {
    events.add(event);
  }

  @override
  Future<List<String>> load() async {
    return events;
  }

  @override
  Future<void> close() async {
    closed = true;
  }
}

class InMemorySenderPersisterAsync
    implements payjoin.JsonSenderSessionPersisterAsync {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemorySenderPersisterAsync(this.id);

  @override
  Future<void> save(String event) async {
    events.add(event);
  }

  @override
  Future<List<String>> load() async {
    return events;
  }

  @override
  Future<void> close() async {
    closed = true;
  }
}

void main() {
  group('Test URIs', () {
    test('Test todo url encoded', () {
      var uri =
          "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
      final result = payjoin.Url.parse(input: uri);
      expect(
        result,
        isA<payjoin.Url>(),
        reason: "pj url should be url encoded",
      );
    });

    test('Test valid url', () {
      var uri =
          "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
      final result = payjoin.Url.parse(input: uri);
      expect(result, isA<payjoin.Url>(), reason: "pj is not a valid url");
    });

    test('Test missing amount', () {
      var uri =
          "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
      final result = payjoin.Url.parse(input: uri);
      expect(result, isA<payjoin.Url>(), reason: "missing amount should be ok");
    });

    test('Test valid uris', () {
      final https = payjoin.exampleUrl();
      final onion =
          "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";

      final base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
      final bech32Upper = "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
      final bech32Lower = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

      final addresses = [base58, bech32Upper, bech32Lower];
      final pjs = [https, onion];

      for (final address in addresses) {
        for (final pj in pjs) {
          final uri = "$address?amount=1&pj=$pj";
          try {
            payjoin.Url.parse(input: uri);
          } catch (e) {
            fail("Failed to create a valid Uri for $uri. Error: $e");
          }
        }
      }
    });
  });

  group("Test Persistence", () {
    test("Test receiver persistence", () {
      var persister = InMemoryReceiverPersister("1");
      payjoin.ReceiverBuilder(
        address: "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
        directory: "https://example.com",
        ohttpKeys: payjoin.OhttpKeys.decode(
          bytes: Uint8List.fromList(
            hex.decode(
              "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003",
            ),
          ),
        ),
      ).build().save(persister: persister);
      final result = payjoin.replayReceiverEventLog(persister: persister);
      expect(
        result.state(),
        isA<payjoin.InitializedReceiveSession>(),
        reason: "receiver should be in Initialized state",
      );
    });

    test("Test sender persistence", () {
      var receiver_persister = InMemoryReceiverPersister("1");
      var receiver = payjoin.ReceiverBuilder(
        address: "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
        directory: "https://example.com",
        ohttpKeys: payjoin.OhttpKeys.decode(
          bytes: Uint8List.fromList(
            hex.decode(
              "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003",
            ),
          ),
        ),
      ).build().save(persister: receiver_persister);
      var uri = receiver.pjUri();

      var sender_persister = InMemorySenderPersister("1");
      var psbt = payjoin.originalPsbt();
      payjoin.SenderBuilder(
        psbt: psbt,
        uri: uri,
      ).buildRecommended(minFeeRate: 1000).save(persister: sender_persister);
      final senderResult = payjoin.replaySenderEventLog(
        persister: sender_persister,
      );
      expect(
        senderResult.state(),
        isA<payjoin.WithReplyKeySendSession>(),
        reason: "sender should be in WithReplyKey state",
      );
    });
  });

  group("Test Async Persistence", () {
    test("Test receiver async persistence", () async {
      var persister = InMemoryReceiverPersisterAsync("1");
      await payjoin.ReceiverBuilder(
        address: "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
        directory: "https://example.com",
        ohttpKeys: payjoin.OhttpKeys.decode(
          bytes: Uint8List.fromList(
            hex.decode(
              "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003",
            ),
          ),
        ),
      ).build().saveAsync(persister: persister);
      final result = await payjoin.replayReceiverEventLogAsync(
        persister: persister,
      );
      expect(
        result.state(),
        isA<payjoin.InitializedReceiveSession>(),
        reason: "receiver should be in Initialized state",
      );
    });

    test("Test sender async persistence", () async {
      var receiver_persister = InMemoryReceiverPersisterAsync("1");
      var receiver = await payjoin.ReceiverBuilder(
        address: "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
        directory: "https://example.com",
        ohttpKeys: payjoin.OhttpKeys.decode(
          bytes: Uint8List.fromList(
            hex.decode(
              "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003",
            ),
          ),
        ),
      ).build().saveAsync(persister: receiver_persister);
      var uri = receiver.pjUri();

      var sender_persister = InMemorySenderPersisterAsync("1");
      var psbt = payjoin.originalPsbt();
      await payjoin.SenderBuilder(psbt: psbt, uri: uri)
          .buildRecommended(minFeeRate: 1000)
          .saveAsync(persister: sender_persister);
      final senderResult = await payjoin.replaySenderEventLogAsync(
        persister: sender_persister,
      );
      expect(
        senderResult.state(),
        isA<payjoin.WithReplyKeySendSession>(),
        reason: "sender should be in WithReplyKey state",
      );
    });

    test("Validation sender builder rejects bad psbt", () {
      final uri = payjoin.Uri.parse(
        uri:
            "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?pj=https://example.com/pj",
      ).checkPjSupported();
      expect(
        () => payjoin.SenderBuilder(psbt: "not-a-psbt", uri: uri),
        throwsA(isA<payjoin.SenderInputException>()),
      );
    });

    test("Validation sender builder exposes invalid original input index", () {
      final receiverPersister = InMemoryReceiverPersister("1");
      final receiver = payjoin.ReceiverBuilder(
        address: "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
        directory: "https://example.com",
        ohttpKeys: payjoin.OhttpKeys.decode(
          bytes: Uint8List.fromList(
            hex.decode(
              "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003",
            ),
          ),
        ),
      ).build().save(persister: receiverPersister);
      final uri = receiver.pjUri();

      try {
        payjoin.SenderBuilder(
          psbt: payjoin.invalidOriginalInputPsbt(),
          uri: uri,
        ).buildNonIncentivizing(minFeeRate: 1000);
        fail("expected sender build error");
      } on payjoin.BuildSenderInputException catch (e) {
        expect(e.v0.invalidOriginalInputIndex(), 0);
        expect(
          e.v0.invalidOriginalInputMessage(),
          "invalid previous transaction output",
        );
      }
    });
  });
}
