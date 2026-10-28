#!/usr/bin/env bash
# Generate a stub Apple SDK in $1 from the macOS libSystem.tbd and Darwin
# headers that zig ships, so the iOS and macOS targets link on Linux
# without Apple's SDK. Every target list is widened to all four targets;
# the macOS verification job checks the imports against Xcode's real stubs.
set -euo pipefail

sdk=$1
zig_lib=$(zig env | sed -n 's/^ *\.lib_dir = "\(.*\)",$/\1/p')
apple_targets="[ arm64-ios, arm64-ios-simulator, arm64-macos, x86_64-macos ]"

rm -rf "$sdk"
mkdir -p "$sdk/usr/include" "$sdk/usr/lib"
# The nix store copy is read-only, and the next run must remove it.
cp -R --no-preserve=mode "$zig_lib/libc/include/any-darwin-any/." "$sdk/usr/include/"
sed -zE "s/targets:( *)\[[^]]*\]/targets:\1$apple_targets/g" \
    "$zig_lib/libc/darwin/libSystem.tbd" >"$sdk/usr/lib/libSystem.tbd"
# std links libiconv on Apple targets, and zig ships no stub for it.
cat >"$sdk/usr/lib/libiconv.tbd" <<TBD
--- !tapi-tbd
tbd-version:     4
targets:         $apple_targets
install-name:    '/usr/lib/libiconv.2.dylib'
current-version: 7
compatibility-version: 7
exports:
  - targets:         $apple_targets
    symbols:         [ _iconv, _iconv_close, _iconv_open, _libiconv,
                       _libiconv_close, _libiconv_open ]
...
TBD
