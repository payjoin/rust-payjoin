import 'dart:io';

import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

import 'build_flags.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final environment = Platform.environment;

    // The path overlay doubles as the development marker. `.pubignore`
    // withholds `.cargo/` from the archive, so the file only exists in a
    // repository checkout. It cannot be an environment variable: hooks_runner
    // spawns build hooks with an allowlisted environment, and a project
    // specific name never survives that filter.
    final localCargoConfig = File.fromUri(
      input.packageRoot.resolve('.cargo/config.local.toml'),
    );
    final isWorkspaceBuild = localCargoConfig.existsSync();

    await RustBuilder(
      assetName: 'uniffi:payjoin_ffi',
      features: isWorkspaceBuild ? const ['_test-utils'] : const [],
      extraCargoBuildArgs: [
        // Cargo no longer discovers the renamed file on its own, and it
        // resolves a relative --config path against its own working
        // directory, so pass the absolute one.
        if (isWorkspaceBuild) ...['--config', localCargoConfig.path],
      ],
      extraCargoEnvironmentVariables: {
        'CARGO_ENCODED_RUSTFLAGS': composeEncodedRustFlags(
          packageRoot: input.packageRoot.toFilePath(),
          outputDirectory: input.outputDirectory.toFilePath(),
          cargoHome: environment['CARGO_HOME'],
          rustupHome: environment['RUSTUP_HOME'],
          home: environment['HOME'] ?? environment['USERPROFILE'],
          rustFlags: environment['RUSTFLAGS'],
          encodedRustFlags: environment['CARGO_ENCODED_RUSTFLAGS'],
          pathSeparator: Platform.pathSeparator,
        ),
      },
    ).run(input: input, output: output);
  });
}
