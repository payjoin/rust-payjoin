import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

const _assetName = 'uniffi:payjoin_ffi';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final mode = input.userDefines['build'] ?? 'prebuilt';
    if (mode == 'prebuilt') {
      if (input.config.buildCodeAssets) {
        _prebuilt(input, output);
      }
      return;
    }
    if (mode != 'source' && mode != 'workspace') {
      throw BuildError(
        message:
            'payjoin: unknown build mode "$mode". Set '
            'hooks.user_defines.payjoin.build to prebuilt or source.',
      );
    }

    final environment = Platform.environment;
    final separator = Platform.pathSeparator;
    String? nonEmpty(String? value) =>
        value == null || value.isEmpty ? null : value;
    // Directory URIs render with a trailing separator, and rustc substitutes
    // the prefix literally: without this, <packageRoot>/native/src/lib.rs
    // would remap to /payjoin/packagenative/src/lib.rs.
    String strip(String path) => path.length > 1 && path.endsWith(separator)
        ? path.substring(0, path.length - separator.length)
        : path;
    final home = nonEmpty(environment['HOME'] ?? environment['USERPROFILE']);
    final cargoHome =
        nonEmpty(environment['CARGO_HOME']) ??
        (home == null ? null : '${strip(home)}$separator.cargo');
    final rustupHome =
        nonEmpty(environment['RUSTUP_HOME']) ??
        (home == null ? null : '${strip(home)}$separator.rustup');
    final code = input.config.buildCodeAssets ? input.config.code : null;
    // Encoded rather than RUSTFLAGS, which Cargo splits on whitespace: the
    // output directory lives under the consumer's project, whose path may
    // contain spaces. hooks_runner never passes RUSTFLAGS to a build hook,
    // so only the encoded variable is inherited.
    final rustFlags = [
      ...?environment['CARGO_ENCODED_RUSTFLAGS']
          ?.split('\x1f')
          .where((flag) => flag.isNotEmpty),
      for (final (from, to) in [
        (input.packageRoot.toFilePath(), '/payjoin/package'),
        (input.outputDirectory.toFilePath(), '/payjoin/output'),
        if (cargoHome != null) (cargoHome, '/cargo'),
        if (rustupHome != null) (rustupHome, '/rustup'),
      ])
        '--remap-path-prefix=${strip(from)}=$to',
      // native_toolchain_rust accepts NDK r27, which aligns 64-bit libraries
      // to 4 KB, and Google Play requires 16 KB. Later NDKs already align to
      // 16 KB, and the flag leaves their output unchanged.
      if (code?.targetOS == OS.android &&
          code?.targetArchitecture != Architecture.arm)
        '-Clink-arg=-Wl,-z,max-page-size=16384',
    ].join('\x1f');

    // The repository's own pubspec selects the workspace build, which
    // builds payjoin-ffi from the checkout through this path overlay.
    // `.pubignore` withholds `.cargo/` from the archive.
    final localCargoConfig = File.fromUri(
      input.packageRoot.resolve('.cargo/config.local.toml'),
    );
    final isWorkspaceBuild = mode == 'workspace';

    await RustBuilder(
      assetName: _assetName,
      features: isWorkspaceBuild ? const ['_test-utils'] : const [],
      extraCargoBuildArgs: [
        // Cargo does not discover this file name on its own, and it
        // resolves a relative --config path against its own working
        // directory, so pass the absolute one.
        if (isWorkspaceBuild) ...['--config', localCargoConfig.path],
        // A published package ships the native/Cargo.lock its release was
        // staged with, so consumers build that graph instead of resolving
        // their own. The workspace overlay redirects `payjoin-ffi` to local
        // paths, which changes the graph, so development builds run unlocked.
        if (!isWorkspaceBuild) '--locked',
      ],
      extraCargoEnvironmentVariables: {
        // Cargo takes rustflags from the first source that sets any, and
        // this variable comes before every Cargo config file. It therefore
        // replaces `build.rustflags`, `target.<triple>.rustflags` and
        // `target.<cfg>.rustflags` from the consumer's config, rather than
        // adding to them.
        'CARGO_ENCODED_RUSTFLAGS': rustFlags,
      },
    ).run(input: input, output: output);
  });
}

/// Registers the library the release built for this target, which
/// prepare-publish.sh copied into the package under prebuilt/.
void _prebuilt(BuildInput input, BuildOutputBuilder output) {
  final code = input.config.code;
  final target = switch ((code.targetOS, code.targetArchitecture)) {
    (OS.android, Architecture.arm64) => 'aarch64-linux-android',
    (OS.android, Architecture.arm) => 'armv7-linux-androideabi',
    (OS.android, Architecture.x64) => 'x86_64-linux-android',
    (OS.iOS, Architecture.arm64) =>
      code.iOS.targetSdk == IOSSdk.iPhoneSimulator
          ? 'aarch64-apple-ios-sim'
          : 'aarch64-apple-ios',
    (OS.macOS, Architecture.arm64) => 'aarch64-apple-darwin',
    (OS.macOS, Architecture.x64) => 'x86_64-apple-darwin',
    (OS.linux, Architecture.arm64) => 'aarch64-unknown-linux-gnu',
    (OS.linux, Architecture.x64) => 'x86_64-unknown-linux-gnu',
    (OS.windows, Architecture.arm64) => 'aarch64-pc-windows-msvc',
    (OS.windows, Architecture.x64) => 'x86_64-pc-windows-msvc',
    (final os, final arch) => '$os on $arch',
  };
  final file = File.fromUri(
    input.packageRoot.resolve(
      'prebuilt/$target/${code.targetOS.dylibFileName('payjoin_ffi')}',
    ),
  );
  if (!file.existsSync()) {
    _fail('this copy of the package has no library for $target');
  }
  output.dependencies.add(file.uri);

  output.assets.code.add(
    CodeAsset(
      package: input.packageName,
      name: _assetName,
      linkMode: DynamicLoadingBundled(),
      file: file.uri,
    ),
  );
}

Never _fail(String reason) => throw BuildError(
  message:
      'payjoin: cannot use the prebuilt native library: $reason.\n'
      'To compile it from source with your own Rust toolchain instead, add '
      'this to the pubspec.yaml of your app:\n'
      '\n'
      'hooks:\n'
      '  user_defines:\n'
      '    payjoin:\n'
      '      build: source\n',
);
