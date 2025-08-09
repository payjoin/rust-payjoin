import 'package:test/test.dart';
import "package:payjoin_dart/payjoin_ffi.dart" as payjoin;
import "package:payjoin_dart/bitcoin.dart" as bitcoin;

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

void main() {
  group('Test URIs', () {
    test('Test todo url encoded', () {
      var uri =
          "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
      final result = payjoin.Url.parse(uri);
      expect(result, isA<payjoin.Url>(),
          reason: "pj url should be url encoded");
    });

    test('Test valid url', () {
      var uri =
          "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
      final result = payjoin.Url.parse(uri);
      expect(result, isA<payjoin.Url>(), reason: "pj is not a valid url");
    });

    test('Test missing amount', () {
      var uri =
          "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
      final result = payjoin.Url.parse(uri);
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
            payjoin.Url.parse(uri);
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
      var address = bitcoin.Address(
          "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", bitcoin.Network.signet);
      payjoin.UninitializedReceiver()
          .createSession(
              address,
              "https://example.com",
              payjoin.OhttpKeys.fromString(
                  "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"),
              null,
              null)
          .save(persister);
      final result = payjoin.replayReceiverEventLog(persister);
      expect(result, isA<payjoin.ReplayResult>(),
          reason: "persistence should return a replay result");
    });

    test("Test sender persistence", () {
      var receiver_persister = InMemoryReceiverPersister("1");
      var address = bitcoin.Address(
          "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", bitcoin.Network.testnet);
      var receiver = payjoin.UninitializedReceiver()
          .createSession(
              address,
              "https://example.com",
              payjoin.OhttpKeys.fromString(
                  "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"),
              null,
              null)
          .save(receiver_persister);
      var uri = receiver.pjUri();

      var sender_persister = InMemorySenderPersister("1");
      var psbt =
          "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
      final result = payjoin.SenderBuilder(psbt, uri)
          .buildRecommended(1000)
          .save(sender_persister);
      expect(result, isA<payjoin.WithReplyKey>(),
          reason: "persistence should return a reply key");
    });
  });
}
