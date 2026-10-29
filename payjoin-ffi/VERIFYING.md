# Verifying the native libraries

Every bindings release attaches each native library it ships to its
[GitHub release](https://github.com/payjoin/rust-payjoin/releases) as
`payjoin_ffi-<version>-<target>.<ext>`, listed in `SHA256SUMS` and
attested by the release workflow. The Python wheels, the NuGet package and
the Dart package carry those same files, byte for byte.

CI builds each library twice, on separate runners from different paths,
and the release only goes ahead when both builds match. You can rebuild
any of them yourself, the Apple ones included, on Linux.

## Check a download

From a directory holding `SHA256SUMS` and the files you downloaded:

```shell
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify payjoin_ffi-<version>-<target>.<ext> -R payjoin/rust-payjoin
```

A maintainer may also upload `SHA256SUMS.asc`, a signature over
`SHA256SUMS` made with a key in
[`contrib/release/keys/`](../contrib/release/keys/).

## Check the Dart package

The Dart package ships each library as `prebuilt/<target>/<file>`, and
`dart pub get` unpacks it into the pub cache. Compare one with the line
for `payjoin_ffi-<version>-<target>.<ext>` in `SHA256SUMS`:

```shell
sha256sum ~/.pub-cache/hosted/pub.dev/payjoin-<version>/prebuilt/<target>/*
```

Use `$PUB_CACHE` in place of `~/.pub-cache` if you set it. The release
also attests the staged package, `payjoin-dart.tar.gz`, which it
attaches.

## Rebuild a library

You need an x86_64 Linux machine with [nix](https://nixos.org/download/)
and flakes enabled. The build does not depend on where the checkout or
your home directory is. Build from a clean target directory, as in a
fresh clone: Cargo does not rebuild dependencies when the deployment
target changes, so a reused one can mix objects built for another target
and give a false mismatch.

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin
git checkout payjoin-ffi-<version>
nix develop .#native -c contrib/native/build.sh <target> /tmp/out
sha256sum /tmp/out/<target>/*
```

Compare the hash with the line for `payjoin_ffi-<version>-<target>.<ext>`
in `SHA256SUMS`. The Android targets need the NDK, which only the
`.#native-android` devshell provides, so use it in place of `.#native`
for them.

| Target                                                                     | File                   |
| -------------------------------------------------------------------------- | ---------------------- |
| `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`                    | `libpayjoin_ffi.so`    |
| `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` | `libpayjoin_ffi.so`    |
| `aarch64-apple-darwin`, `x86_64-apple-darwin`                              | `libpayjoin_ffi.dylib` |
| `aarch64-apple-ios`, `aarch64-apple-ios-sim`                               | `libpayjoin_ffi.dylib` |
| `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`                        | `payjoin_ffi.dll`      |

`universal2-apple-darwin` is not built on its own. Build both macOS
targets, then combine them:

```shell
nix develop .#native -c llvm-lipo -create \
  /tmp/out/aarch64-apple-darwin/libpayjoin_ffi.dylib \
  /tmp/out/x86_64-apple-darwin/libpayjoin_ffi.dylib \
  -output /tmp/out/libpayjoin_ffi.dylib
sha256sum /tmp/out/libpayjoin_ffi.dylib
```

The [native build contract](../contrib/native/README.md) lists the
toolchain, flags and pinned inputs behind these builds.
