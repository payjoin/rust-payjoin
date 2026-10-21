import 'package:payjoin/payjoin.dart' as payjoin;

void main() {
  // Parsing goes through the native library, so this only runs once the
  // payjoin build hook has produced the asset.
  final uri = payjoin.Uri.parse(
    uri: 'bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1',
  );
  print(uri.address());
}
