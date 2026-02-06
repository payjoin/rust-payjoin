import 'dart:io';

import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:path/path.dart' as path;
import 'package:yaml/yaml.dart';

import 'util.dart';

enum PrecompiledBinaryMode { auto, always, never }

class PrecompiledBinariesConfig {
  PrecompiledBinariesConfig({
    required this.artifactHost,
    required this.mode,
    required this.publicKey,
    this.urlPrefix,
  });

  final String artifactHost;
  final PrecompiledBinaryMode mode;
  final String? urlPrefix;
  final PublicKey publicKey;

  Uri fileUrl({required String crateHash, required String fileName}) {
    final prefix = urlPrefix;
    if (prefix != null && prefix.isNotEmpty) {
      return Uri.parse('$prefix$crateHash/$fileName');
    }
    final tag = 'precompiled_$crateHash';
    return Uri.parse(
      'https://github.com/$artifactHost/releases/download/$tag/$fileName',
    );
  }

  static PrecompiledBinariesConfig parse(YamlNode node) {
    if (node is! YamlMap) {
      throw FormatException('precompiled_binaries must be a map');
    }

    String? urlPrefix;
    final urlPrefixNode = node.nodes['url_prefix'];
    if (urlPrefixNode != null) {
      if (urlPrefixNode is! YamlScalar || urlPrefixNode.value is! String) {
        throw FormatException(
          'precompiled_binaries.url_prefix must be a string',
        );
      }
      urlPrefix = urlPrefixNode.value as String;
    }

    PrecompiledBinaryMode mode = PrecompiledBinaryMode.auto;
    final modeNode = node.nodes['mode'];
    if (modeNode != null) {
      if (modeNode is! YamlScalar || modeNode.value is! String) {
        throw FormatException('precompiled_binaries.mode must be a string');
      }
      final m = (modeNode.value as String).trim();
      final parsed = _parsePrecompiledBinaryMode(m);
      if (parsed == null) {
        throw FormatException(
          'precompiled_binaries.mode must be one of: auto, always, never (aliases: download->always, build->never)',
        );
      }
      mode = parsed;
    }

    final artifactHostNode = node.nodes['artifact_host'];
    final releaseRepoNode = node.nodes['release_repo'];

    final publicKeyNode = node.nodes['public_key'];

    String? artifactHost;
    if (artifactHostNode != null) {
      if (artifactHostNode is! YamlScalar ||
          artifactHostNode.value is! String) {
        throw FormatException(
          'precompiled_binaries.artifact_host must be a string',
        );
      }
      artifactHost = (artifactHostNode.value as String).trim();
    }
    if (artifactHost == null && releaseRepoNode != null) {
      if (releaseRepoNode is! YamlScalar || releaseRepoNode.value is! String) {
        throw FormatException(
          'precompiled_binaries.release_repo must be a string',
        );
      }
      artifactHost = (releaseRepoNode.value as String).trim();
    }

    if ((urlPrefix == null || urlPrefix.isEmpty) &&
        (artifactHost == null || artifactHost.isEmpty)) {
      throw FormatException(
        'precompiled_binaries must specify either url_prefix or artifact_host',
      );
    }

    artifactHost ??= '';
    final normalizedArtifactHost = artifactHost.isEmpty
        ? ''
        : _normalizeOwnerRepo(artifactHost);
    if (artifactHost.isNotEmpty && normalizedArtifactHost == null) {
      throw FormatException(
        'precompiled_binaries.artifact_host must be in owner/repo format (or github.com/owner/repo)',
      );
    }

    if (publicKeyNode is! YamlScalar || publicKeyNode.value is! String) {
      throw FormatException('precompiled_binaries.public_key must be a string');
    }
    final keyBytes = decodeHex(publicKeyNode.value as String);
    if (keyBytes.length != 32) {
      throw FormatException('public_key must be 32 bytes');
    }
    return PrecompiledBinariesConfig(
      artifactHost: normalizedArtifactHost ?? '',
      mode: mode,
      publicKey: PublicKey(keyBytes),
      urlPrefix: urlPrefix,
    );
  }
}

String? _normalizeOwnerRepo(String raw) {
  var v = raw.trim();
  v = v.replaceFirst(RegExp(r'^https?://'), '');
  v = v.replaceFirst(RegExp(r'^github\.com/'), '');
  v = v.replaceAll(RegExp(r'/+$'), '');
  final parts = v.split('/');
  if (parts.length != 2) {
    return null;
  }
  if (parts[0].isEmpty || parts[1].isEmpty) {
    return null;
  }
  return '${parts[0]}/${parts[1]}';
}

class PubspecOptions {
  PubspecOptions({required this.precompiledBinaries});

  final PrecompiledBinariesConfig? precompiledBinaries;

  static YamlNode? _findPrecompiledBinariesNode(
    YamlMap root, {
    required String configKey,
  }) {
    final key = configKey.trim();
    if (key.isEmpty) {
      return null;
    }
    final packageNode = root.nodes[key];
    if (packageNode is! YamlMap) {
      return null;
    }
    return packageNode.nodes['precompiled_binaries'];
  }

  static PrecompiledBinaryMode? loadModeOverride({
    required String packageRoot,
    required String packageName,
  }) {
    final file = File(path.join(packageRoot, 'pubspec.yaml'));
    if (!file.existsSync()) {
      return null;
    }
    final root = loadYamlNode(file.readAsStringSync(), sourceUrl: file.uri);
    if (root is! YamlMap) {
      throw FormatException('pubspec.yaml must be a map');
    }

    final node = _findPrecompiledBinariesNode(root, configKey: packageName);
    if (node == null) {
      return null;
    }
    if (node is! YamlMap) {
      throw FormatException('precompiled_binaries must be a map');
    }

    final modeNode = node.nodes['mode'];
    if (modeNode == null) {
      return null;
    }
    if (modeNode is! YamlScalar || modeNode.value is! String) {
      throw FormatException('precompiled_binaries.mode must be a string');
    }

    final m = (modeNode.value as String).trim();
    final parsed = _parsePrecompiledBinaryMode(m);
    if (parsed == null) {
      throw FormatException(
        'precompiled_binaries.mode must be one of: auto, always, never (aliases: download->always, build->never)',
      );
    }
    return parsed;
  }

  static PubspecOptions load({
    required String packageRoot,
    required String pluginConfigKey,
  }) {
    final file = File(path.join(packageRoot, 'pubspec.yaml'));
    if (!file.existsSync()) {
      return PubspecOptions(precompiledBinaries: null);
    }
    final root = loadYamlNode(file.readAsStringSync(), sourceUrl: file.uri);
    if (root is! YamlMap) {
      throw FormatException('pubspec.yaml must be a map');
    }
    final node = _findPrecompiledBinariesNode(root, configKey: pluginConfigKey);

    if (node == null) {
      return PubspecOptions(precompiledBinaries: null);
    }

    return PubspecOptions(
      precompiledBinaries: PrecompiledBinariesConfig.parse(node),
    );
  }
}

class UserOptions {
  UserOptions({required this.usePrecompiledBinaries});

  final bool usePrecompiledBinaries;

  static bool _rustupExists() {
    final envPath = Platform.environment['PATH'];
    final envPathSeparator = Platform.isWindows ? ';' : ':';
    final home = Platform.isWindows
        ? Platform.environment['USERPROFILE']
        : Platform.environment['HOME'];
    final paths = [
      if (home != null) path.join(home, '.cargo', 'bin'),
      if (envPath != null) ...envPath.split(envPathSeparator),
    ];
    for (final p in paths) {
      final rustup = Platform.isWindows ? 'rustup.exe' : 'rustup';
      if (File(path.join(p, rustup)).existsSync()) {
        return true;
      }
    }
    return false;
  }

  static bool defaultUsePrecompiledBinaries() => !_rustupExists();

  static UserOptions load({required bool hasConfig}) {
    if (!hasConfig) {
      return UserOptions(usePrecompiledBinaries: false);
    }
    return UserOptions(usePrecompiledBinaries: defaultUsePrecompiledBinaries());
  }
}

PrecompiledBinaryMode? _parsePrecompiledBinaryMode(String raw) {
  final v = raw.trim().toLowerCase();
  return switch (v) {
    'auto' => PrecompiledBinaryMode.auto,
    'always' || 'download' => PrecompiledBinaryMode.always,
    'never' || 'build' || 'off' || 'disabled' => PrecompiledBinaryMode.never,
    _ => null,
  };
}
