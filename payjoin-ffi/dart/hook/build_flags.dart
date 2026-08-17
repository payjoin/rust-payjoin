const rustFlagSeparator = '\x1f';

bool testUtilsEnabled(String? value) => value == '1';

String composeRustFlags({
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
  final remaps = <String>[
    '--remap-path-prefix=$packageRoot=/payjoin/package',
    '--remap-path-prefix=$outputDirectory=/payjoin/output',
    if (resolvedCargoHome != null)
      '--remap-path-prefix=$resolvedCargoHome=/cargo',
    if (resolvedRustupHome != null)
      '--remap-path-prefix=$resolvedRustupHome=/rustup',
  ];

  final inheritedEncoded = _nonEmpty(encodedRustFlags);
  if (inheritedEncoded != null) {
    return [inheritedEncoded, ...remaps].join(rustFlagSeparator);
  }

  final inheritedPlain = _nonEmpty(rustFlags);
  return [if (inheritedPlain != null) inheritedPlain, ...remaps].join(' ');
}

String? _nonEmpty(String? value) {
  return value == null || value.isEmpty ? null : value;
}
