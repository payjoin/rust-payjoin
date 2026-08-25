import 'dart:io';

import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
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
    ].join('\x1f');

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
        // Cargo does not discover this file name on its own, and it
        // resolves a relative --config path against its own working
        // directory, so pass the absolute one.
        if (isWorkspaceBuild) ...['--config', localCargoConfig.path],
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
