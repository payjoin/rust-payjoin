import 'dart:io';

import 'package:payjoin/src/precompiled/crate_hash.dart';

Future<void> run(List<String> args) async {
  String? manifestDir;
  var debug = false;
  var list = false;

  for (final arg in args) {
    if (arg == '--debug') {
      debug = true;
      continue;
    }
    if (arg == '--list') {
      list = true;
      continue;
    }
    if (arg.startsWith('--manifest-dir=')) {
      manifestDir = arg.substring('--manifest-dir='.length).trim();
      continue;
    }
    if (arg == '--help' || arg == '-h') {
      stdout.writeln('Usage: hash --manifest-dir=<dir> [--debug] [--list]');
      return;
    }
    if (arg.trim().isEmpty) continue;
    stderr.writeln('Unknown argument: $arg');
    exitCode = 2;
    return;
  }

  if (manifestDir == null || manifestDir.trim().isEmpty) {
    stderr.writeln('Missing --manifest-dir');
    exitCode = 2;
    return;
  }
  if (!Directory(manifestDir).existsSync()) {
    stderr.writeln('Manifest directory not found: $manifestDir');
    exitCode = 1;
    return;
  }

  if (debug || list) {
    final files = CrateHash.collectFiles(manifestDir);
    for (final file in files) {
      if (list) {
        stderr.writeln(file.path);
      } else {
        stderr.writeln('${file.path}');
      }
    }
  }
  stdout.write(CrateHash.compute(manifestDir));
}
