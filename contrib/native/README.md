# Native build contract

The payjoin-ffi native libraries are built on Linux, by one script, in one
devshell. The language bindings move onto these libraries one at a time.

```sh
nix develop .#native -c contrib/native/build.sh <triple> <out-dir>
```

The Android targets need the NDK, which only `.#native-android` provides.

The library lands in `<out-dir>/<triple>/`.

| Invariant | Rule                                                                                                                                                                                                                                               |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Toolchain | Rust 1.85.1. CI keeps testing the 1.85.0 MSRV.                                                                                                                                                                                                     |
| Lockfile  | `Cargo-recent.lock`, built `--locked`                                                                                                                                                                                                              |
| Features  | None. Bindings are generated separately, so the library is the same for every language.                                                                                                                                                            |
| Paths     | The repository is remapped to `/payjoin`, the target dir to `/payjoin/target`, the cargo home to `/cargo`, the rustup home to `/rustup`, the NDK to `/ndk` and the Windows SDK to `/xwin`, for rustc and the C compiler                            |
| Profile   | Cargo's release defaults                                                                                                                                                                                                                           |
| Linux     | `cargo zigbuild` against glibc 2.17                                                                                                                                                                                                                |
| macOS     | zig through `apple-cc.sh` against the stub SDK, deployment target 10.15 on x86_64 and 11.0 on arm64, Flutter's floor and the first macOS on Apple silicon. `universal2-apple-darwin` is the two slices combined with `llvm-lipo`.                  |
| iOS       | zig through `apple-cc.sh` against the stub SDK, minimum iOS 13.0. Device and arm64 simulator only.                                                                                                                                                 |
| Windows   | `xwin` fetches MSVC's CRT 14.44.17.14 and Windows SDK 10.0.26100 from the Visual Studio 17.14.37824.6 manifest pinned in `vs-channel.json`. LLVM 21's clang-cl, llvm-lib and lld-link build against them, linked with `/Brepro` and without a PDB. |
| Android   | NDK 29.0.14206865 at API 21, 16 KB aligned on 64-bit by the NDK's default                                                                                                                                                                          |

The Apple dylibs are linked with an `@rpath/libpayjoin_ffi.dylib` install
name, `-headerpad_max_install_names` for Flutter's `install_name_tool`, and
`-S`, which keeps object paths and mtimes out of the stabs.
`apple-stubs.sh` generates the stub SDK from the macOS `libSystem.tbd` and
Darwin headers that zig ships, so no Apple SDK file is used or committed.

`x86_64-apple-ios`, the Intel simulator, is not built. Rust 1.85.1's std
for it targets iOS 10.0, so its objects carry `LC_VERSION_MIN_IPHONEOS`,
which zig 0.16 reads as a device platform and rejects for a simulator
link.
