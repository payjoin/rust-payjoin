#!/usr/bin/env bash
set -euo pipefail

# Build the production wheel for one platform into dist/: release profile,
# no test utils. Select the platform with PAYJOIN_WHEEL_PLATFORM
# (linux-x64, the default, or macos-universal2).
#
# Both wheels build on a Linux host: a dylib linked inside the nix dev shell
# on a mac records nix store install names that exist on no user machine,
# while cargo-zigbuild links against zig's bundled Apple SDK stubs and records
# the system ones.

if [[ "$(uname -s)" != Linux ]]; then
    echo "error: release wheels build on a Linux host only" >&2
    exit 1
fi

PLATFORM=${PAYJOIN_WHEEL_PLATFORM:-linux-x64}

# Build against the maintained lockfile instead of resolving the dependency
# graph fresh on every run. use_lockfile copies Cargo-recent.lock into place
# and restores the previous state when this script exits.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/python"

echo "==> Generating production FFI bindings..."
PAYJOIN_FFI_FEATURES="" PAYJOIN_FFI_PROFILE=release bash ./scripts/generate_bindings.sh

# generate_bindings.sh stages the host's library; make sure the wheel
# ships exactly one platform's binary.
case "$PLATFORM" in
    linux-x64)
        rm -f src/payjoin/libpayjoin_ffi.dylib
        ;;
    macos-universal2)
        echo "==> Cross-compiling the universal2 macOS library..."
        (cd "$REPO_ROOT/payjoin-ffi" &&
            cargo zigbuild --profile release --target universal2-apple-darwin)
        rm -f src/payjoin/libpayjoin_ffi.so
        cp "$REPO_ROOT/target/universal2-apple-darwin/release/libpayjoin_ffi.dylib" \
            src/payjoin/
        ;;
    *)
        echo "error: unsupported PAYJOIN_WHEEL_PLATFORM: $PLATFORM" >&2
        exit 1
        ;;
esac

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
    # The macOS floor is zig's: its bundled SDK stubs currently support
    # macOS >= 13, and that is the minos both slices record. Keep this tag
    # in sync with the LC_BUILD_VERSION of the built dylib if zig moves.
    wheel tags --platform-tag macosx_13_0_universal2 --remove dist/*.whl
fi

echo "==> Built wheel:"
ls -l dist
