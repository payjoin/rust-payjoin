import 'package:test/test.dart';
import "../lib/payjoin_ffi.dart" as payjoin;

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
      // import test_utils to allow for const EXAMPLE_URL
      final https = "https://example.com";
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
}
