#!/usr/bin/env bash
set -euo pipefail

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64)
            echo "x64"
            ;;
        arm64 | aarch64)
            echo "arm64"
            ;;
        *)
            echo "Unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
}

detect_rid() {
    local arch
    arch=$(detect_arch)

    case "$(uname -s)" in
        Linux)
            echo "linux-$arch"
            ;;
        Darwin)
            echo "osx-$arch"
            ;;
        MINGW* | MSYS* | CYGWIN*)
            echo "win-$arch"
            ;;
        *)
            echo "Unsupported os: $(uname -s)" >&2
            exit 1
            ;;
    esac
}

native_library_name() {
    case "$1" in
        linux-*)
            echo "libpayjoin_ffi.so"
            ;;
        osx-*)
            echo "libpayjoin_ffi.dylib"
            ;;
        win-*)
            echo "payjoin_ffi.dll"
            ;;
        *)
            echo "Unsupported RID: $1" >&2
            exit 1
            ;;
    esac
}

# Rust target triple for cross-compiling a RID from a Linux host. Linux targets pin a
# glibc floor through zig so the produced .so loads on older distributions instead of
# inheriting the build host's glibc version.
rid_to_cross_target() {
    case "$1" in
        linux-x64)
            echo "x86_64-unknown-linux-gnu.$PAYJOIN_FFI_GLIBC_FLOOR"
            ;;
        linux-arm64)
            echo "aarch64-unknown-linux-gnu.$PAYJOIN_FFI_GLIBC_FLOOR"
            ;;
        osx-x64)
            echo "x86_64-apple-darwin"
            ;;
        osx-arm64)
            echo "aarch64-apple-darwin"
            ;;
        win-x64)
            echo "x86_64-pc-windows-msvc"
            ;;
        win-arm64)
            echo "aarch64-pc-windows-msvc"
            ;;
        *)
            echo "Unsupported RID for cross build: $1" >&2
            exit 1
            ;;
    esac
}

# cargo-zigbuild links Linux (with a chosen glibc floor) and macOS targets (zig ships
# redistributable libSystem stubs); cargo-xwin links MSVC-ABI Windows targets against
# the Microsoft CRT/SDK it fetches.
rid_to_cross_tool() {
    case "$1" in
        linux-* | osx-*)
            echo "zigbuild"
            ;;
        win-*)
            echo "xwin"
            ;;
    esac
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CSHARP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$CSHARP_DIR"

RID=${PAYJOIN_FFI_RID:-$(detect_rid)}
LIBNAME=$(native_library_name "$RID")

export PAYJOIN_FFI_FEATURES="${PAYJOIN_FFI_FEATURES-}"
export PAYJOIN_FFI_PROFILE="${PAYJOIN_FFI_PROFILE:-release}"
PAYJOIN_FFI_GLIBC_FLOOR=${PAYJOIN_FFI_GLIBC_FLOOR:-2.17}

if [[ ${PAYJOIN_FFI_CROSS:-0} == 1 ]]; then
    # Cross-compile the native library for $RID from a Linux host. Bindings are never
    # generated here; the pack step generates the production bindings it packages.
    TARGET=$(rid_to_cross_target "$RID")
    TOOL=$(rid_to_cross_tool "$RID")
    if ! command -v "cargo-$TOOL" >/dev/null; then
        echo "cargo-$TOOL is required for cross builds: pip install cargo-zigbuild cargo-xwin" >&2
        exit 1
    fi

    CROSS_CARGO=(cargo "$TOOL")
    if [[ $TOOL == xwin ]]; then
        CROSS_CARGO+=(build)
    fi

    GENERATOR_FEATURES="csharp${PAYJOIN_FFI_FEATURES:+,$PAYJOIN_FFI_FEATURES}"
    (cd .. && "${CROSS_CARGO[@]}" --target "$TARGET" --features "$GENERATOR_FEATURES" --profile "$PAYJOIN_FFI_PROFILE" -p payjoin-ffi)

    # Cargo writes to the triple without any zig glibc suffix.
    TARGET_DIR=${TARGET%."$PAYJOIN_FFI_GLIBC_FLOOR"}
    if [[ $PAYJOIN_FFI_PROFILE == "dev" ]]; then
        PROFILE_DIR=debug
    else
        PROFILE_DIR=$PAYJOIN_FFI_PROFILE
    fi
    BUILT_LIB="../../target/$TARGET_DIR/$PROFILE_DIR/$LIBNAME"
else
    bash ./scripts/generate_bindings.sh --native-only
    BUILT_LIB="lib/$LIBNAME"
fi

ARTIFACT_DIR="artifacts/runtimes/$RID/native"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"
cp "$BUILT_LIB" "$ARTIFACT_DIR/$LIBNAME"

echo "Wrote $ARTIFACT_DIR/$LIBNAME"
