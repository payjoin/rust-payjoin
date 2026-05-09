import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:path/path.dart' as path;

import 'cargo.dart';
import 'crate_hash.dart';
import 'options.dart';
import 'target.dart';
import 'util.dart';

final _log = Logger('payjoin.artifacts_provider');

String? _invokerRootFromOutputDirectory(Uri outputDirectory) {
  final parts = path.split(path.fromUri(outputDirectory));
  final dartToolIndex = parts.lastIndexOf('.dart_tool');
  if (dartToolIndex <= 0) {
    return null;
  }
  return path.joinAll(parts.take(dartToolIndex));
}

class DownloadedArtifact {
  DownloadedArtifact({required this.filePath, required this.dependencies});

  final String filePath;
  final List<Uri> dependencies;
}

class PrecompiledBinaryRequiredException implements Exception {
  PrecompiledBinaryRequiredException(this.message);

  final String message;

  @override
  String toString() => 'PrecompiledBinaryRequiredException: $message';
}

class PrecompiledArtifactProvider {
  PrecompiledArtifactProvider({
    required this.input,
    required this.buildModeName,
    required this.crateDir,
  });

  final BuildInput input;
  final String buildModeName;
  final Directory crateDir;

  Future<DownloadedArtifact?> tryGetPrecompiledArtifact() async {
    final pubspecOptions = PubspecOptions.load(
      packageRoot: path.fromUri(input.packageRoot),
      pluginConfigKey: 'payjoin',
    );
    final baseConfig = pubspecOptions.precompiledBinaries;
    if (baseConfig == null) {
      return null;
    }

    final invokerRoot = _invokerRootFromOutputDirectory(input.outputDirectory);
    final invokerMode = invokerRoot == null
        ? null
        : PubspecOptions.loadModeOverride(
            packageRoot: invokerRoot,
            packageName: input.packageName,
          );

    final precompiled = invokerMode == null
        ? baseConfig
        : PrecompiledBinariesConfig(
            artifactHost: baseConfig.artifactHost,
            mode: invokerMode,
            publicKey: baseConfig.publicKey,
            urlPrefix: baseConfig.urlPrefix,
          );

    if (invokerMode != null) {
      _log.info(
        'Using invoker override precompiled_binaries.mode=${invokerMode.name} from $invokerRoot',
      );
    }

    if (precompiled.mode == PrecompiledBinaryMode.never) {
      _log.info('Precompiled binaries disabled by mode=never');
      return null;
    }

    if (precompiled.mode == PrecompiledBinaryMode.auto) {
      final userOptions = UserOptions.load(hasConfig: true);
      if (!userOptions.usePrecompiledBinaries) {
        _log.info(
          'Precompiled binaries disabled (auto mode + local build preferred)',
        );
        return null;
      }
    }

    if (!input.config.buildCodeAssets) {
      return null;
    }

    final codeConfig = input.config.code;
    final crateInfo = CrateInfo.load(crateDir.path);
    final targetTriple = codeConfig.targetTriple;
    final linkMode = codeConfig.linkMode;

    final outDir = path.join(path.fromUri(input.outputDirectory), 'target');
    final libFileName = codeConfig.targetOS
        .libraryFileName(crateInfo.packageName, linkMode)
        .replaceAll('-', '_');
    final finalLibPath = path.join(
      outDir,
      targetTriple,
      buildModeName,
      libFileName,
    );

    Directory(path.dirname(finalLibPath)).createSync(recursive: true);

    final crateHash = CrateHash.compute(crateDir.path, tempStorage: outDir);

    final remoteFileName = '${targetTriple}_$libFileName';
    final remoteSignatureName = '$remoteFileName.sig';

    final binaryUrl = precompiled.fileUrl(
      crateHash: crateHash,
      fileName: remoteFileName,
    );
    final signatureUrl = precompiled.fileUrl(
      crateHash: crateHash,
      fileName: remoteSignatureName,
    );

    final bool requirePrecompiled =
        precompiled.mode == PrecompiledBinaryMode.always;

    DownloadedArtifact? handleFailure(String message) {
      if (requirePrecompiled) {
        throw PrecompiledBinaryRequiredException(message);
      }
      return null;
    }

    _log.info('Downloading signature from $signatureUrl');
    final signatureRes = await httpGetWithRetry(signatureUrl);
    if (signatureRes.statusCode == 404) {
      _log.info('No precompiled binaries for crate hash $crateHash');
      return handleFailure('No precompiled binaries for crate hash $crateHash');
    }
    if (signatureRes.statusCode != 200) {
      _log.warning(
        'Failed to download signature: status ${signatureRes.statusCode}',
      );
      return handleFailure(
        'Failed to download signature: status ${signatureRes.statusCode}',
      );
    }

    _log.info('Downloading binary from $binaryUrl');
    final binaryRes = await httpGetWithRetry(binaryUrl);
    if (binaryRes.statusCode != 200) {
      _log.warning('Failed to download binary: status ${binaryRes.statusCode}');
      return handleFailure(
        'Failed to download binary: status ${binaryRes.statusCode}',
      );
    }

    final ok = verify(
      precompiled.publicKey,
      binaryRes.bodyBytes,
      signatureRes.bodyBytes,
    );
    if (!ok) {
      _log.warning('Signature verification failed; ignoring binary');
      return handleFailure('Signature verification failed; ignoring binary');
    }

    await writeBytesAtomically(File(finalLibPath), binaryRes.bodyBytes);
    _log.info('Verified and wrote precompiled binary to $finalLibPath');

    final deps = CrateHash.collectFiles(
      crateDir.path,
    ).map((f) => f.absolute.uri).toList(growable: false);

    return DownloadedArtifact(filePath: finalLibPath, dependencies: deps);
  }
}
