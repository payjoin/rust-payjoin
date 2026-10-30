#!/usr/bin/env bash
set -euo pipefail

# Build the production wheel for one platform into dist/ around a native
# library built under the native build contract (contrib/native/build.sh):
# release profile, no test utils. Select the platform with
# PAYJOIN_WHEEL_PLATFORM (linux-x64, the default, or macos-universal2) and
# pass the library, libpayjoin_ffi.so or the universal2
# libpayjoin_ffi.dylib, as the only argument.

if [[ "$(uname -s)" != Linux ]]; then
    echo "error: release wheels build on a Linux host only" >&2
    exit 1
fi
if [[ $# -ne 1 ]]; then
    echo "usage: $0 <native library>" >&2
    exit 1
fi
LIBRARY=$(realpath "$1")

PLATFORM=${PAYJOIN_WHEEL_PLATFORM:-linux-x64}
case "$PLATFORM" in
    linux-x64 | macos-universal2) ;;
    *)
        echo "error: unsupported PAYJOIN_WHEEL_PLATFORM: $PLATFORM" >&2
        exit 1
        ;;
esac

# Build against the maintained lockfile instead of resolving the dependency
# graph fresh on every run. use_lockfile copies Cargo-recent.lock into place
# and restores the previous state when this script exits.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/python"

# uniffi reads its metadata from the static symbol table, which the
# zig-linked Linux library does not have, so the bindings come from a
# development build of the same featureless library.
echo "==> Generating production FFI bindings..."
(cd .. && cargo build --lib &&
    cargo run --bin uniffi-bindgen generate \
        --library ../target/debug/libpayjoin_ffi.so \
        --language python --out-dir python/src/payjoin/)

# A development build may have staged the other platform's library.
rm -f src/payjoin/libpayjoin_ffi.so src/payjoin/libpayjoin_ffi.dylib
cp "$LIBRARY" src/payjoin/

echo "==> Building the wheel..."
# Drop setuptools' build/ staging dir too: it survives across runs and
# would leak the other platform's library into this wheel.
rm -rf build dist
uv build --wheel

# The generated bindings load the bundled library through ctypes, so the
# wheel does not depend on a CPython ABI; setup.py tags it with the
# building interpreter's version only because has_ext_modules marks the
# wheel platform-specific.
echo "==> Retagging the wheel..."
wheel tags --python-tag py3 --abi-tag none --remove dist/*.whl

if [[ $PLATFORM == linux-x64 ]]; then
    # PyPI rejects the raw linux_x86_64 platform tag. auditwheel verifies
    # the library's external dependencies and applies the manylinux tag the
    # binary actually satisfies; nothing is grafted into the wheel since
    # the library links only glibc.
    auditwheel repair --wheel-dir dist dist/*-linux_x86_64.whl
    rm dist/*-linux_x86_64.whl
else
    # setup.py tagged the wheel with the build machine's (Linux) platform.
    # The native build contract's macOS deployment target is 10.15 for the
    # x86_64 slice and 11.0, the first macOS on Apple silicon, for arm64.
    wheel tags --platform-tag macosx_10_15_universal2 --remove dist/*.whl
fi

# The release lists the library on its own, so the wheel must carry it
# unchanged.
unzip -p dist/*.whl "payjoin/$(basename "$LIBRARY")" | cmp - "$LIBRARY"

echo "==> Built wheel:"
ls -l dist
