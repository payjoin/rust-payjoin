import 'dart:io';

import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

import 'build_flags.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final environment = Platform.environment;
    final rustFlags = composeRustFlags(
      packageRoot: input.packageRoot.toFilePath(),
      outputDirectory: input.outputDirectory.toFilePath(),
      cargoHome: environment['CARGO_HOME'],
      rustupHome: environment['RUSTUP_HOME'],
      home: environment['HOME'] ?? environment['USERPROFILE'],
      rustFlags: environment['RUSTFLAGS'],
      encodedRustFlags: environment['CARGO_ENCODED_RUSTFLAGS'],
      pathSeparator: Platform.pathSeparator,
    );
    final inheritedEncodedRustFlags = environment['CARGO_ENCODED_RUSTFLAGS'];
    final hasEncodedRustFlags =
        inheritedEncodedRustFlags != null &&
        inheritedEncodedRustFlags.isNotEmpty;
    final rustFlagEnvironment = hasEncodedRustFlags
        ? {'CARGO_ENCODED_RUSTFLAGS': rustFlags}
        : {'RUSTFLAGS': rustFlags};
    final enableTestUtils =
        testUtilsEnabled(environment['PAYJOIN_FFI_ENABLE_TEST_UTILS']);
    final localCargoConfig = File.fromUri(
      input.packageRoot.resolve('.cargo/config.local.toml'),
    );

    await RustBuilder(
      assetName: 'uniffi:payjoin_ffi',
      features: enableTestUtils ? const ['_test-utils'] : const [],
      extraCargoBuildArgs: [
        if (enableTestUtils && localCargoConfig.existsSync()) ...[
          '--config',
          '../.cargo/config.local.toml',
        ],
        '--locked',
      ],
      extraCargoEnvironmentVariables: rustFlagEnvironment,
    ).run(input: input, output: output);
  });
}
