import 'dart:convert';
import 'dart:io';

import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:path/path.dart' as p;
import 'package:payjoin/src/precompiled/crate_hash.dart';
import 'package:payjoin/src/precompiled/rust_toolchain.dart';
import 'package:payjoin/src/precompiled/util.dart';

import '../support/os.dart';
import '../support/process.dart';

Future<void> run(List<String> args) async {
  String? manifestDir;
  String? cratePackage;
  String? repository;
  String? os;
  String? androidSdkLocation;
  String? androidNdkVersion;
  String? androidMinSdkVersion;
  var verbose = false;

  for (final arg in args) {
    if (arg == '--help' || arg == '-h') {
      stdout.writeln('''
Usage: precompile-binaries [options]

Options:
  --manifest-dir=<dir>      Rust crate directory (required)
  --crate-package=<name>    Cargo package name (required)
  --repository=<owner/repo> GitHub repository for releases (required)
  --os=<os>                 macos | linux | windows | android | ios | all (default: current)
  --android-sdk-location=<path>  Android SDK root (required when --os=android)
  --android-ndk-version=<ver>    NDK version folder name (required when --os=android)
  --android-min-sdk-version=<n>  Android minSdkVersion (required when --os=android)
  -v, --verbose             Verbose output
''');
      return;
    }
    if (arg == '-v' || arg == '--verbose') {
      verbose = true;
      continue;
    }
    if (arg.startsWith('--manifest-dir=')) {
      manifestDir = arg.substring('--manifest-dir='.length).trim();
      continue;
    }
    if (arg.startsWith('--crate-package=')) {
      cratePackage = arg.substring('--crate-package='.length).trim();
      continue;
    }
    if (arg.startsWith('--repository=')) {
      repository = arg.substring('--repository='.length).trim();
      continue;
    }
    if (arg.startsWith('--os=')) {
      os = arg.substring('--os='.length).trim();
      continue;
    }
    if (arg.startsWith('--android-sdk-location=')) {
      androidSdkLocation = arg
          .substring('--android-sdk-location='.length)
          .trim();
      continue;
    }
    if (arg.startsWith('--android-ndk-version=')) {
      androidNdkVersion = arg.substring('--android-ndk-version='.length).trim();
      continue;
    }
    if (arg.startsWith('--android-min-sdk-version=')) {
      androidMinSdkVersion = arg
          .substring('--android-min-sdk-version='.length)
          .trim();
      continue;
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
  final manifestDirNormalized = manifestDir.trim();
  final manifestPath = Directory(manifestDirNormalized).absolute.path;
  if (cratePackage == null || cratePackage.trim().isEmpty) {
    stderr.writeln('Missing --crate-package');
    exitCode = 2;
    return;
  }
  if (repository == null || repository.trim().isEmpty) {
    stderr.writeln('Missing --repository');
    exitCode = 2;
    return;
  }
  os ??= Platform.operatingSystem;

  final normalizedOs = normalizeOs(os);
  if (normalizedOs == null && os.trim().toLowerCase() != 'all') {
    stderr.writeln('Unsupported --os=$os');
    exitCode = 2;
    return;
  }

  if (verbose) {
    stderr.writeln(
      'Precompiling binaries for manifest: $manifestDirNormalized',
    );
    stderr.writeln('Crate package: $cratePackage');
    stderr.writeln('Repository: $repository');
    stderr.writeln('OS filter: ${normalizedOs ?? 'all'}');
  }

  final toolchain = RustToolchain.load(manifestPath);
  final crateHash = CrateHash.compute(manifestPath);
  final tag = 'precompiled_$crateHash';

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
  final privateKey = PrivateKey(privateKeyBytes);

  final ghToken =
      Platform.environment['GH_TOKEN'] ??
      Platform.environment['GITHUB_TOKEN'] ??
      Platform.environment['GITHUB_TOKEN'.toUpperCase()];
  if (ghToken == null || ghToken.trim().isEmpty) {
    stderr.writeln('Missing GH_TOKEN/GITHUB_TOKEN for GitHub release upload');
    exitCode = 2;
    return;
  }

  final targets = normalizedOs == null
      ? toolchain.targets
      : toolchain.targetsForOs(normalizedOs);
  if (targets.isEmpty) {
    stderr.writeln(
      'No toolchain targets found for os=${normalizedOs ?? 'all'}',
    );
    exitCode = 1;
    return;
  }

  String? abiForTarget(String t) => switch (t) {
    'armv7-linux-androideabi' => 'armeabi-v7a',
    'aarch64-linux-android' => 'arm64-v8a',
    'x86_64-linux-android' => 'x86_64',
    _ => null,
  };

  final buildableTargets = normalizedOs == 'android'
      ? targets.where((t) => abiForTarget(t) != null).toList(growable: false)
      : List<String>.from(targets);

  final releaseHasAssets = buildableTargets.isNotEmpty
      ? await _releaseHasAllAssets(
          tag: tag,
          targets: buildableTargets,
          repository: repository,
        )
      : false;

  final buildDir = Directory('precompiled_build');
  final uploadDir = Directory('precompiled_upload');
  final buildDirAbs = Directory(
    p.join(Directory.current.absolute.path, buildDir.path),
  );
  final uploadDirAbs = Directory(
    p.join(Directory.current.absolute.path, uploadDir.path),
  );

  await _ensureReleaseExists(
    tag: tag,
    crateHash: crateHash,
    repository: repository,
  );
  if (releaseHasAssets) {
    if (verbose) {
      stderr.writeln(
        'Release $tag already contains assets for ${buildableTargets.join(', ')}; skipping build.',
      );
    }
    return;
  }

  if (buildDirAbs.existsSync()) buildDirAbs.deleteSync(recursive: true);
  if (uploadDirAbs.existsSync()) uploadDirAbs.deleteSync(recursive: true);
  buildDirAbs.createSync(recursive: true);
  uploadDirAbs.createSync(recursive: true);

  final crateFileBase = cratePackage.replaceAll('-', '_');

  if (normalizedOs == 'android') {
    if (androidSdkLocation == null || androidSdkLocation.trim().isEmpty) {
      stderr.writeln(
        'Missing --android-sdk-location (required for --os=android)',
      );
      exitCode = 2;
      return;
    }
    if (androidNdkVersion == null || androidNdkVersion.trim().isEmpty) {
      stderr.writeln(
        'Missing --android-ndk-version (required for --os=android)',
      );
      exitCode = 2;
      return;
    }
    if (androidMinSdkVersion == null || androidMinSdkVersion.trim().isEmpty) {
      stderr.writeln(
        'Missing --android-min-sdk-version (required for --os=android)',
      );
      exitCode = 2;
      return;
    }

    final ndkHome = '$androidSdkLocation/ndk/$androidNdkVersion';
    final env = <String, String>{
      ...Platform.environment,
      'ANDROID_SDK_ROOT': androidSdkLocation,
      'ANDROID_NDK_HOME': ndkHome,
      'ANDROID_NDK_ROOT': ndkHome,
    };

    final buildOut = Directory(p.join(buildDirAbs.path, 'android'));
    buildOut.createSync(recursive: true);

    String? abiForTarget(String t) => switch (t) {
      'armv7-linux-androideabi' => 'armeabi-v7a',
      'aarch64-linux-android' => 'arm64-v8a',
      'x86_64-linux-android' => 'x86_64',
      _ => null,
    };

    for (final target in buildableTargets) {
      final abi = abiForTarget(target)!;
      if (verbose)
        stderr.writeln('Building Android target: $target (abi=$abi)');

      await runOrThrow(
        'rustup',
        ['target', 'add', target, '--toolchain', toolchain.channel],
        verbose: verbose,
        environment: env,
      );

      await runOrThrow(
        'rustup',
        [
          'run',
          toolchain.channel,
          'cargo',
          'ndk',
          '--platform',
          androidMinSdkVersion,
          '-t',
          abi,
          '-o',
          buildOut.absolute.path,
          'build',
          '--package',
          cratePackage,
          '--release',
          '--locked',
        ],
        verbose: verbose,
        environment: env,
        workingDirectory: manifestPath,
      );

      final soPath = p.join(buildOut.path, abi, 'lib$crateFileBase.so');
      final soFile = File(soPath);
      if (!soFile.existsSync()) {
        stderr.writeln('Expected Android artifact not found: $soPath');
        exitCode = 1;
        return;
      }

      final outPath = p.join(
        uploadDirAbs.path,
        '${target}_lib$crateFileBase.so',
      );
      final outFile = File(outPath)..writeAsBytesSync(soFile.readAsBytesSync());
      final sig = sign(privateKey, outFile.readAsBytesSync());
      File('$outPath.sig').writeAsBytesSync(sig);
      if (verbose) stderr.writeln('Prepared: $outPath (+ .sig)');
    }
  } else {
    for (final target in buildableTargets) {
      if (verbose) stderr.writeln('Building target: $target');
      await runOrThrow('rustup', [
        'target',
        'add',
        target,
        '--toolchain',
        toolchain.channel,
      ], verbose: verbose);
      await runOrThrow(
        'rustup',
        [
          'run',
          toolchain.channel,
          'cargo',
          'build',
          '--manifest-path',
          '$manifestPath/Cargo.toml',
          '--package',
          cratePackage,
          '--release',
          '--locked',
          '--target',
          target,
          '--target-dir',
          buildDirAbs.path,
        ],
        verbose: verbose,
        workingDirectory: manifestPath,
      );

      final artDir = Directory(p.join(buildDirAbs.path, target, 'release'));
      if (!artDir.existsSync()) {
        stderr.writeln('Missing artifact directory: ${artDir.path}');
        exitCode = 1;
        return;
      }

      final artifacts = <File>[];
      for (final ent in artDir.listSync(followLinks: false)) {
        if (ent is! File) continue;
        final name = ent.uri.pathSegments.last;
        final ok =
            name.startsWith('lib$crateFileBase.') ||
            name.startsWith('$crateFileBase.') ||
            name == 'lib$crateFileBase.a';
        if (ok) artifacts.add(ent);
      }

      if (artifacts.isEmpty) {
        stderr.writeln(
          'No artifacts found in ${artDir.path} for $cratePackage',
        );
        exitCode = 1;
        return;
      }

      for (final file in artifacts) {
        final base = file.uri.pathSegments.last;
        final outPath = p.join(uploadDirAbs.path, '${target}_$base');
        final outFile = File(outPath);
        outFile.writeAsBytesSync(file.readAsBytesSync());
        final sig = sign(privateKey, outFile.readAsBytesSync());
        File('$outPath.sig').writeAsBytesSync(sig);
        if (verbose) stderr.writeln('Prepared: $outPath (+ .sig)');
      }
    }
  }

  await runOrThrow('gh', [
    'release',
    'upload',
    '--repo',
    repository,
    tag,
    '${uploadDirAbs.path}/*',
    '--clobber',
  ], verbose: verbose);
}

Future<void> _ensureReleaseExists({
  required String tag,
  required String crateHash,
  required String repository,
}) async {
  final view = await Process.run('gh', ['release', 'view', tag]);
  if (view.exitCode == 0) return;
  final create = await Process.run('gh', [
    'release',
    'create',
    tag,
    '--repo',
    repository,
    '--title',
    'Precompiled binaries $crateHash',
    '--notes',
    'Precompiled binaries for crate hash $crateHash.',
  ]);
  stdout.write(create.stdout);
  stderr.write(create.stderr);
  if (create.exitCode != 0) {
    exitCode = create.exitCode;
    throw StateError('Failed to create release $tag');
  }
}

Future<bool> _releaseHasAllAssets({
  required String tag,
  required List<String> targets,
  required String repository,
}) async {
  final view = await Process.run('gh', [
    'release',
    'view',
    tag,
    '--repo',
    repository,
    '--json',
    'assets',
    '--jq',
    '.assets[].name',
  ]);
  if (view.exitCode != 0) {
    return false;
  }
  final output = view.stdout.toString();
  final assets = LineSplitter.split(
    output,
  ).map((name) => name.trim()).where((name) => name.isNotEmpty).toSet();
  if (assets.isEmpty) {
    return false;
  }

  for (final target in targets) {
    final prefix = '${target}_';
    final binaryNames = assets
        .where((name) => name.startsWith(prefix) && !name.endsWith('.sig'))
        .toList();
    if (binaryNames.isEmpty) {
      return false;
    }
    final hasPair = binaryNames.any((name) => assets.contains('$name.sig'));
    if (!hasPair) {
      return false;
    }
  }

  return true;
}
