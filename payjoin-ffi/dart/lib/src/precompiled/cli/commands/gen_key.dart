import 'dart:io';

import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:payjoin/src/precompiled/util.dart';

Future<void> run(List<String> args) async {
  if (args.contains('--help') || args.contains('-h')) {
    return;
  }
  final kp = generateKey();
  final privateHex = hexEncode(kp.privateKey.bytes);
  final publicHex = hexEncode(kp.publicKey.bytes);
  stdout.writeln('PRIVATE_KEY=$privateHex');
  stdout.writeln('PUBLIC_KEY=$publicHex');
}
