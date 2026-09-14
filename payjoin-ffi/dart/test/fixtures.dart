import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:convert/convert.dart';

// Resolve from the package source so fixture loading is independent of the
// test runner's working directory. These tests run from the repository checkout.
final _fixtures = Isolate.resolvePackageUriSync(
  Uri.parse('package:payjoin/payjoin.dart'),
)!.resolve('../../../payjoin-test-utils/fixtures/');

final originalPsbt = File.fromUri(_fixtures.resolve('original-psbt.base64'))
    .readAsStringSync();
final _ohttpKeysHex = File.fromUri(_fixtures.resolve('ohttp-keys.hex'))
    .readAsStringSync()
    .trim();

Uint8List get ohttpKeys => Uint8List.fromList(hex.decode(_ohttpKeysHex));
