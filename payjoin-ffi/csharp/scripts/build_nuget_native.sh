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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CSHARP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$CSHARP_DIR"

RID=${PAYJOIN_FFI_RID:-$(detect_rid)}
LIBNAME=$(native_library_name "$RID")

export PAYJOIN_FFI_FEATURES="${PAYJOIN_FFI_FEATURES-}"
export PAYJOIN_FFI_PROFILE="${PAYJOIN_FFI_PROFILE:-release}"

bash ./scripts/generate_bindings.sh

ARTIFACT_DIR="artifacts/runtimes/$RID/native"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"
cp "lib/$LIBNAME" "$ARTIFACT_DIR/$LIBNAME"

echo "Wrote $ARTIFACT_DIR/$LIBNAME"
