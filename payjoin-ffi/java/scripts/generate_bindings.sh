#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)
echo "Running on $OS"

if [[ $OS == "Darwin" ]]; then
    LIBNAME=libpayjoin_ffi.dylib
elif [[ $OS == "Linux" ]]; then
    LIBNAME=libpayjoin_ffi.so
elif [[ $OS == MINGW* || $OS == MSYS* || $OS == CYGWIN* ]]; then
    LIBNAME=payjoin_ffi.dll
else
    echo "Unsupported os: $OS"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required (to hash the local patch and to parse cargo's build output)" >&2
    exit 1
fi
if ! command -v git >/dev/null 2>&1; then
    echo "git is required to fetch and verify the pinned uniffi-bindgen-java commit" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

# Generator source and patch - see README.md "Generator provenance" for the full story. Short
# version: uniffi-bindgen-java's newest tagged release (0.4.2) reads payjoin-ffi's current
# UniFFI 0.31 metadata, but its error-type templates emit Java that doesn't compile for this
# crate. The fix already exists on upstream's unreleased main (versioned 0.5.0), but that line
# requires UniFFI 0.32, which payjoin-ffi is not on. So: build canonical upstream 0.4.2, with the
# two-file fix backported as a local patch, and use that until payjoin-ffi moves to UniFFI 0.32
# and can consume a real upstream 0.5.x release directly.
#
# Pinned by commit SHA (not the `0.4.2` tag name) so a future upstream re-tag can't silently
# change what this builds. `git tag -l 0.4.2 -n1` / `git rev-parse 0.4.2^{commit}` on the
# canonical repo is how this SHA was resolved from the tag.
GENERATOR_GIT_URL=${JAVA_BINDGEN_GIT_URL:-https://github.com/IronCoreLabs/uniffi-bindgen-java}
GENERATOR_REV=${JAVA_BINDGEN_REV:-559bd72e680e0be7feda6ac3a93819376db030d9}
GENERATOR_PATCH="$SCRIPT_DIR/../patches/0001-error-autocloseable-and-destroy-fields.patch"

# Building this generator needs a Rust toolchain new enough for its own MSRV (1.87.0 per its
# README/Cargo.toml), which is newer than this workspace's own MSRV (1.85.0). Inside
# `nix develop .#java`, `cargo` is already that new (see flake.nix's javaDevShell comment) -
# no toolchain switching needed here. Outside nix, whatever `cargo` is on PATH is used as-is; if
# it's older than 1.87.0, install/select a newer one before running this script (e.g. `rustup
# install 1.87.0` and `rustup override set 1.87.0` in this directory, or `cargo +1.87.0 ...` by
# hand) - this script does not attempt to switch toolchains for you.
#
# The cache key includes a hash of the patch file, not just the pinned rev, so editing the patch
# produces a fresh build instead of reusing a binary built from the old one. Hashed with python3
# (already required below, and everywhere else this script runs) rather than shasum, so this
# script doesn't add a second undeclared platform command to the requirements in README.md.
PATCH_HASH="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()[:12])' "$GENERATOR_PATCH")"
GENERATOR_ROOT="${CARGO_HOME:-$HOME/.cargo}/uniffi-bindgen-java-${GENERATOR_REV}-${PATCH_HASH}"
GENERATOR_BIN="$GENERATOR_ROOT/bin/uniffi-bindgen-java"

if [[ ! -x "$GENERATOR_BIN" ]]; then
    echo "Building patched uniffi-bindgen-java ($GENERATOR_REV, patch $PATCH_HASH)..."
    # A scratch checkout, not a persistent mutable one: cloned fresh, patched, built, and
    # discarded every time the cache misses, so there is never a partially-patched or
    # stale-relative-to-the-patch-file checkout lying around to reason about.
    GENERATOR_SRC="$(mktemp -d)"
    trap 'rm -rf "$GENERATOR_SRC"' EXIT
    git init --quiet "$GENERATOR_SRC"
    git -C "$GENERATOR_SRC" fetch --quiet --depth 1 "$GENERATOR_GIT_URL" "$GENERATOR_REV"
    git -C "$GENERATOR_SRC" checkout --quiet FETCH_HEAD
    ACTUAL_REV="$(git -C "$GENERATOR_SRC" rev-parse HEAD)"
    if [[ "$ACTUAL_REV" != "$GENERATOR_REV" ]]; then
        echo "error: fetched $ACTUAL_REV, expected $GENERATOR_REV" >&2
        exit 1
    fi
    # --unidiff-zero: the patch is generated with zero context lines (-U0) - safe here since it's
    # applied against this exact pinned commit every time, and it keeps upstream's own trailing
    # whitespace in surrounding template lines out of the patch file (git apply's default context
    # matching needs at least one line of context per hunk without this flag).
    git -C "$GENERATOR_SRC" apply --unidiff-zero "$GENERATOR_PATCH"
    cargo install --path "$GENERATOR_SRC" --locked --root "$GENERATOR_ROOT" uniffi-bindgen-java
    rm -rf "$GENERATOR_SRC"
    trap - EXIT
else
    echo "Using cached uniffi-bindgen-java at $GENERATOR_BIN"
fi

echo "Generating payjoin Java..."
PAYJOIN_FFI_FEATURES=${PAYJOIN_FFI_FEATURES-_test-utils}
PAYJOIN_FFI_PROFILE=${PAYJOIN_FFI_PROFILE:-dev}
# Empty FEATURE_ARGS + `set -u` is unbound on macOS bash 3.2. Pass --features only when set.
run_cargo() {
    local cmd=$1
    shift
    if [[ -n $PAYJOIN_FFI_FEATURES ]]; then
        cargo "$cmd" --features "$PAYJOIN_FFI_FEATURES" "$@"
    else
        cargo "$cmd" "$@"
    fi
}

# The reported compiler-artifact path already reflects CARGO_TARGET_DIR, Cargo's [build]
# target-dir, CARGO_BUILD_TARGET, and the active profile - so it's read from Cargo's own JSON
# output instead of reconstructed from any of those independently, which would drift under any
# one of them. json-render-diagnostics keeps human-readable compiler errors on stderr (a plain
# `--message-format=json` would swallow a real Rust compile error's message and location here,
# leaving only the missing-artifact failure below to explain why).
NATIVE_LIB="$(
    run_cargo build --message-format=json-render-diagnostics --profile "$PAYJOIN_FFI_PROFILE" -p payjoin-ffi |
        python3 -c '
import json, os, sys

libname = sys.argv[1]
found = None
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    if msg.get("reason") != "compiler-artifact":
        continue
    for filename in msg.get("filenames") or []:
        if os.path.basename(filename) == libname:
            found = filename
if not found:
    sys.stderr.write("cargo build did not report %s\n" % libname)
    sys.exit(1)
print(found)
' "$LIBNAME"
)"

OUT_DIR="java/src/main/java"
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR/org"

# Run from payjoin-ffi/ (not java/) so the generator's cargo-metadata lookup finds
# payjoin-ffi/uniffi.toml's [bindings.java] section the same way the Kotlin/Python scripts do.
"$GENERATOR_BIN" generate --out-dir "$OUT_DIR" "$NATIVE_LIB"

mkdir -p java/lib
cp "$NATIVE_LIB" "java/lib/$LIBNAME"

echo "All done!"
