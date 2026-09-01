import 'package:test/test.dart';

import '../../hook/build_flags.dart';

void main() {
  test('remaps package, output, Cargo, and fallback rustup paths', () {
    final flags = composeEncodedRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      cargoHome: '/cargo-home',
      home: '/home/user',
    );

    expect(
      flags.split(rustFlagSeparator),
      containsAll([
        '--remap-path-prefix=/package=/payjoin/package',
        '--remap-path-prefix=/output=/payjoin/output',
        '--remap-path-prefix=/cargo-home=/cargo',
        '--remap-path-prefix=/home/user/.rustup=/rustup',
      ]),
    );
  });

  test('drops the trailing separator of directory paths', () {
    final flags = composeEncodedRustFlags(
      packageRoot: '/package/',
      outputDirectory: '/output/',
      cargoHome: '/cargo-home/',
      rustupHome: '/rustup-home/',
    );

    expect(
      flags.split(rustFlagSeparator),
      containsAll([
        '--remap-path-prefix=/package=/payjoin/package',
        '--remap-path-prefix=/output=/payjoin/output',
        '--remap-path-prefix=/cargo-home=/cargo',
        '--remap-path-prefix=/rustup-home=/rustup',
      ]),
    );
  });

  test('uses a non-empty explicit RUSTUP_HOME', () {
    final flags = composeEncodedRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      home: '/home/user',
      rustupHome: '/custom/rustup',
    );

    expect(flags, contains('--remap-path-prefix=/custom/rustup=/rustup'));
    expect(flags, isNot(contains('/home/user/.rustup')));
  });

  test('keeps paths containing spaces in a single argument', () {
    final flags = composeEncodedRustFlags(
      packageRoot: '/Users/jane/My App/package',
      outputDirectory: '/Users/jane/My App/output',
    );

    expect(
      flags.split(rustFlagSeparator),
      containsAll([
        '--remap-path-prefix=/Users/jane/My App/package=/payjoin/package',
        '--remap-path-prefix=/Users/jane/My App/output=/payjoin/output',
      ]),
    );
  });

  test('preserves inherited encoded flags', () {
    final flags = composeEncodedRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      encodedRustFlags: '--cfg\x1ffeature="parent"',
    );

    expect(flags, startsWith('--cfg\x1ffeature="parent"\x1f'));
    expect(
      flags.split(rustFlagSeparator),
      contains('--remap-path-prefix=/output=/payjoin/output'),
    );
  });

  test('re-encodes inherited plain RUSTFLAGS argument by argument', () {
    final flags = composeEncodedRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      rustFlags: '--cfg feature="parent"',
    );

    expect(flags, startsWith('--cfg\x1ffeature="parent"\x1f'));
  });

  test('prefers encoded flags over plain RUSTFLAGS', () {
    final flags = composeEncodedRustFlags(
      packageRoot: '/package',
      outputDirectory: '/output',
      rustFlags: '--cfg plain',
      encodedRustFlags: '--cfg\x1fencoded',
    );

    expect(flags, startsWith('--cfg\x1fencoded\x1f'));
    expect(flags, isNot(contains('plain')));
  });

  test('remaps Windows paths with a backslash separator', () {
    final flags = composeEncodedRustFlags(
      packageRoot: r'C:\src\package\',
      outputDirectory: r'C:\src\output\',
      home: r'C:\Users\jane',
      pathSeparator: r'\',
    );

    expect(
      flags.split(rustFlagSeparator),
      containsAll([
        r'--remap-path-prefix=C:\src\package=/payjoin/package',
        r'--remap-path-prefix=C:\src\output=/payjoin/output',
        r'--remap-path-prefix=C:\Users\jane\.cargo=/cargo',
        r'--remap-path-prefix=C:\Users\jane\.rustup=/rustup',
      ]),
    );
  });
}
