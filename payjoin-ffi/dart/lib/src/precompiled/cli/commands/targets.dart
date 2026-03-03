import 'dart:io';

import 'package:payjoin/src/precompiled/rust_toolchain.dart';

import '../support/os.dart';

Future<void> run(List<String> args) async {
  String? os;
  String? manifestDir;
  var printChannel = false;

  for (final arg in args) {
    if (arg.startsWith('--os=')) {
      os = arg.substring('--os='.length).trim();
      continue;
    }
    if (arg.startsWith('--manifest-dir=')) {
      manifestDir = arg.substring('--manifest-dir='.length).trim();
      continue;
    }
    if (arg == '--channel') {
      printChannel = true;
      continue;
    }
    if (arg == '--help' || arg == '-h') {
      stdout.writeln(
        'Usage: targets --manifest-dir=<dir> [--os=macos] [--channel]',
      );
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

  try {
    final toolchain = RustToolchain.load(manifestDir);
    if (printChannel) {
      stdout.write(toolchain.channel);
      return;
    }
    final targets = toolchain.targets;
    if (targets.isEmpty) {
      stderr.writeln('No targets found in rust-toolchain.toml');
      exitCode = 1;
      return;
    }
    final normalized = normalizeOs(os ?? Platform.operatingSystem);
    final filtered = normalized == null
        ? targets
        : toolchain.targetsForOs(normalized);
    if (filtered.isEmpty) {
      stderr.writeln('No targets match os=${normalized ?? 'all'}');
      exitCode = 1;
      return;
    }
    stdout.write(filtered.join(' '));
  } catch (e) {
    stderr.writeln('Error: $e');
    exitCode = 1;
  }
}
