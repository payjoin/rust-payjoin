import 'dart:io';

import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:payjoin/src/precompiled/util.dart';

Future<void> run(List<String> args) async {
  if (args.length != 2 || args.contains('--help') || args.contains('-h')) {
    stderr.writeln('Usage: sign <input_file> <output_sig_file>');
    if (args.contains('--help') || args.contains('-h')) return;
    exitCode = 2;
    return;
  }

  final privateKeyHex = Platform.environment['PRIVATE_KEY'];
  if (privateKeyHex == null) {
    stderr.writeln('Missing PRIVATE_KEY environment variable');
    exitCode = 2;
    return;
  }
  final privateKeyBytes = decodeHex(privateKeyHex);
  if (privateKeyBytes.length != 64) {
    stderr.writeln('PRIVATE_KEY must be 64 bytes (hex-encoded)');
    exitCode = 2;
    return;
  }

  final inputFile = File(args[0]);
  if (!inputFile.existsSync()) {
    stderr.writeln('Input file does not exist: ${inputFile.path}');
    exitCode = 1;
    return;
  }

  final outFile = File(args[1]);
  outFile.parent.createSync(recursive: true);

  final data = inputFile.readAsBytesSync();
  final signature = sign(PrivateKey(privateKeyBytes), data);
  outFile.writeAsBytesSync(signature);
}
