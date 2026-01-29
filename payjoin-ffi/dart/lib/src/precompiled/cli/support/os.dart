String? normalizeOs(String raw) {
  final v = raw.trim().toLowerCase();
  return switch (v) {
    'linux' || 'ubuntu-latest' => 'linux',
    'macos' || 'darwin' || 'macos-latest' => 'macos',
    'windows' || 'windows-latest' => 'windows',
    'android' => 'android',
    'ios' => 'ios',
    'all' => null,
    _ => v.isEmpty ? null : v,
  };
}
