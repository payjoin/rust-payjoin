import 'package:test/test.dart';

import '../../hook/build_flags.dart';

void main() {
  test('disables test utils by default and enables them only for 1', () {
    expect(testUtilsEnabled(null), isFalse);
    expect(testUtilsEnabled('0'), isFalse);
    expect(testUtilsEnabled('true'), isFalse);
    expect(testUtilsEnabled('1'), isTrue);
  });

  test('remaps package, output, Cargo, and fallback rustup paths', () {
    final flags = composeRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      cargoHome: '/cargo-home',
      home: '/home/user',
    );

    expect(flags, contains('--remap-path-prefix=/package=/payjoin/package'));
    expect(flags, contains('--remap-path-prefix=/output=/payjoin/output'));
    expect(flags, contains('--remap-path-prefix=/cargo-home=/cargo'));
    expect(flags, contains('--remap-path-prefix=/home/user/.rustup=/rustup'));
  });

  test('uses a non-empty explicit RUSTUP_HOME', () {
    final flags = composeRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      home: '/home/user',
      rustupHome: '/custom/rustup',
    );

    expect(flags, contains('--remap-path-prefix=/custom/rustup=/rustup'));
    expect(flags, isNot(contains('/home/user/.rustup')));
  });

  test('preserves encoded flags and appends remaps with unit separators', () {
    final flags = composeRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      encodedRustFlags: '--cfg\x1ffeature="parent"',
    );

    expect(flags, startsWith('--cfg\x1ffeature="parent"\x1f'));
    expect(flags, contains('--remap-path-prefix=/output=/payjoin/output'));
  });

  test('preserves plain RUSTFLAGS when encoded flags are absent', () {
    final flags = composeRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      rustFlags: '--cfg feature="parent"',
    );

    expect(flags, startsWith('--cfg feature="parent" '));
    expect(flags, contains('--remap-path-prefix=/output=/payjoin/output'));
  });
}
