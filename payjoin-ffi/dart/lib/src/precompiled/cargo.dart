import 'dart:io';

import 'package:path/path.dart' as path;

class CrateInfo {
  CrateInfo({required this.packageName});

  final String packageName;

  static CrateInfo load(String manifestDir) {
    final manifestFile = File(path.join(manifestDir, 'Cargo.toml'));
    final manifest = manifestFile.readAsStringSync();
    final lines = manifest.split('\n');
    var inPackage = false;
    for (final raw in lines) {
      final line = raw.trim();
      if (line.startsWith('[') && line.endsWith(']')) {
        inPackage = line == '[package]';
        continue;
      }
      if (!inPackage) continue;
      if (line.startsWith('name')) {
        final parts = line.split('=');
        if (parts.length >= 2) {
          final value = parts.sublist(1).join('=').trim();
          final m = RegExp(r'^"(.+)"$').firstMatch(value);
          if (m != null) {
            return CrateInfo(packageName: m.group(1)!);
          }
        }
      }
    }
    throw StateError('Failed to determine crate name from Cargo.toml');
  }
}
