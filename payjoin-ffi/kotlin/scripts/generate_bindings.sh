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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

echo "Generating payjoin Kotlin..."
PAYJOIN_FFI_FEATURES=${PAYJOIN_FFI_FEATURES-_test-utils}
PAYJOIN_FFI_PROFILE=${PAYJOIN_FFI_PROFILE:-dev}
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to parse cargo --message-format=json" >&2
    exit 1
fi
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

# compiler-artifact filenames include target-dir, CARGO_BUILD_TARGET, and profile.
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

OUT_DIR="kotlin/src/main/kotlin"
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR/org"

# ktlint is optional; --no-format keeps generate working without it.
run_cargo run --profile dev -p payjoin-ffi --bin uniffi-bindgen -- generate \
    --library "$NATIVE_LIB" \
    --language kotlin \
    --out-dir "$OUT_DIR" \
    --no-format

mkdir -p kotlin/lib
cp "$NATIVE_LIB" "kotlin/lib/$LIBNAME"

echo "All done!"
