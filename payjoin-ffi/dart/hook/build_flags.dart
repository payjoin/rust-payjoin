/// Cargo's separator for `CARGO_ENCODED_RUSTFLAGS` entries.
const rustFlagSeparator = '\x1f';

/// Builds the `CARGO_ENCODED_RUSTFLAGS` value the hook hands to Cargo.
///
/// The result is always encoded rather than plain `RUSTFLAGS`: Cargo splits
/// `RUSTFLAGS` on whitespace, and the remapped prefixes are absolute paths
/// under the consumer's project, which may contain spaces.
String composeEncodedRustFlags({
  required String packageRoot,
  required String outputDirectory,
  String? cargoHome,
  String? rustupHome,
  String? home,
  String? rustFlags,
  String? encodedRustFlags,
  String pathSeparator = '/',
}) {
  final resolvedCargoHome =
      _nonEmpty(cargoHome) ??
      (_nonEmpty(home) == null ? null : '${home!}$pathSeparator.cargo');
  final resolvedRustupHome =
      _nonEmpty(rustupHome) ??
      (_nonEmpty(home) == null ? null : '${home!}$pathSeparator.rustup');
  String remap(String from, String to) =>
      '--remap-path-prefix=${_stripTrailingSeparator(from, pathSeparator)}=$to';

  final remaps = <String>[
    remap(packageRoot, '/payjoin/package'),
    remap(outputDirectory, '/payjoin/output'),
    if (resolvedCargoHome != null) remap(resolvedCargoHome, '/cargo'),
    if (resolvedRustupHome != null) remap(resolvedRustupHome, '/rustup'),
  ];

  return [
    ..._inheritedFlags(rustFlags, encodedRustFlags),
    ...remaps,
  ].join(rustFlagSeparator);
}

/// Splits whatever flags the hook inherited into individual arguments.
///
/// Encoded flags are already one argument per entry. Plain `RUSTFLAGS` is
/// split on whitespace, which is how Cargo would have split it anyway.
List<String> _inheritedFlags(String? rustFlags, String? encodedRustFlags) {
  final inheritedEncoded = _nonEmpty(encodedRustFlags);
  if (inheritedEncoded != null) {
    return inheritedEncoded
        .split(rustFlagSeparator)
        .where((flag) => flag.isNotEmpty)
        .toList();
  }

  final inheritedPlain = _nonEmpty(rustFlags);
  if (inheritedPlain != null) {
    return inheritedPlain
        .split(RegExp(r'\s+'))
        .where((flag) => flag.isNotEmpty)
        .toList();
  }

  return const [];
}

/// Drops a trailing separator so the remapped prefix keeps one.
///
/// Directory `Uri`s render with a trailing separator, and rustc substitutes
/// the prefix literally: without this, `<packageRoot>/native/src/lib.rs`
/// would remap to `/payjoin/packagenative/src/lib.rs`.
String _stripTrailingSeparator(String path, String pathSeparator) {
  if (path.length > 1 && path.endsWith(pathSeparator)) {
    return path.substring(0, path.length - pathSeparator.length);
  }
  return path;
}

String? _nonEmpty(String? value) {
  return value == null || value.isEmpty ? null : value;
}
