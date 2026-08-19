#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PACKAGE_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
PARENT_DIR=${PAYJOIN_SMOKE_PARENT:?Set PAYJOIN_SMOKE_PARENT to a dedicated directory}
BINDING_SOURCE=${PAYJOIN_BINDING_SOURCE:?Set PAYJOIN_BINDING_SOURCE to a published payjoin.dart}
CARGO_HOME_SOURCE=${PAYJOIN_SMOKE_CARGO_HOME:?Set PAYJOIN_SMOKE_CARGO_HOME to a dedicated Cargo cache}
DART_BIN=${DART_BIN:-dart}
RUSTC_BIN=${RUSTC_BIN:-rustc}
KEEP=${PAYJOIN_SMOKE_KEEP:-0}

if [[ ! -d "$PARENT_DIR" || ! -w "$PARENT_DIR" ]]; then
    printf 'Smoke parent must be an existing writable directory: %s\n' "$PARENT_DIR" >&2
    exit 2
fi
if [[ ! -f "$BINDING_SOURCE" ]]; then
    printf 'Published binding source does not exist: %s\n' "$BINDING_SOURCE" >&2
    exit 2
fi
if [[ ! -d "$CARGO_HOME_SOURCE" ]]; then
    printf 'Cargo cache does not exist: %s\n' "$CARGO_HOME_SOURCE" >&2
    exit 2
fi

rustc_version=$("$RUSTC_BIN" --version)
rust_target=$("$RUSTC_BIN" -vV | awk '/^host:/{print $2}')
if [[ -z "$rust_target" ]]; then
    printf 'Could not determine the Rust host target triple\n' >&2
    exit 2
fi

work_dir=$(mktemp -d "$PARENT_DIR/payjoin-dart-consumer-smoke.XXXXXX")
if [[ "$KEEP" != 1 ]]; then
    trap 'rm -rf "$work_dir"' EXIT
fi

for copy in first second; do
    package_copy="$work_dir/package-$copy"
    consumer="$work_dir/consumer-$copy"
    mkdir -p "$package_copy" "$consumer/bin"
    cp -a "$PACKAGE_ROOT/." "$package_copy/"
    rm -rf "$package_copy/.cargo" "$package_copy/.dart_tool" \
        "$package_copy/build" "$package_copy/contrib" "$package_copy/scripts" \
        "$package_copy/test" "$package_copy/pubspec.lock"
    cp "$BINDING_SOURCE" "$package_copy/lib/payjoin.dart"

    test -f "$package_copy/native/Cargo.lock"
    test ! -d "$package_copy/.cargo"
    if grep -n 'path = ' "$package_copy/native/Cargo.lock"; then
        printf 'Consumer lockfile contains a path dependency\n' >&2
        exit 1
    fi
    grep -Fq 'https://github.com/payjoin/rust-payjoin.git?rev=' \
        "$package_copy/native/Cargo.lock"

    cat > "$consumer/pubspec.yaml" <<EOF
name: payjoin_consumer_smoke_$copy
environment:
  sdk: ^3.10.0
dependencies:
  payjoin:
    path: ../package-$copy
EOF
    cat > "$consumer/bin/main.dart" <<'EOF'
import 'package:payjoin/payjoin.dart';

void main() {
  print(OutPoint(txid: '00' * 32, vout: 0).vout);
}
EOF
done

for copy in first second; do
    consumer="$work_dir/consumer-$copy"
    (
        cd "$consumer"
        "$DART_BIN" pub get --offline
    ) > "$work_dir/$copy-pub-get.log" 2>&1
done

for copy in first second; do
    consumer="$work_dir/consumer-$copy"
    cargo_home="$work_dir/cargo-$copy"
    target_dir="$work_dir/target-$copy"
    mkdir -p "$cargo_home"
    cp -a "$CARGO_HOME_SOURCE/." "$cargo_home/"
    (
        cd "$consumer"
        CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target_dir" \
            CARGO_NET_OFFLINE=true RUSTC="$RUSTC_BIN" \
            "$DART_BIN" run bin/main.dart
    ) > "$work_dir/$copy-run.log" 2>&1
done

shopt -s nullglob
artifacts=()
for copy in first second; do
    matches=(
        "$work_dir/consumer-$copy/.dart_tool/hooks_runner/shared"/*/build/*/target/"$rust_target"/release/*.so
    )
    if [[ ${#matches[@]} -ne 1 ]]; then
        printf 'Expected exactly one native .so for consumer %s, found %s\n' \
            "$copy" "${#matches[@]}" >&2
        exit 1
    fi
    artifacts+=("${matches[0]}")
done
shopt -u nullglob

target=$($DART_BIN --version | awk '{print "dart-" $3}')
clang_version=$(clang --version | awk 'NR == 1 {print}')
linker_version=$(ld.lld --version | awk 'NR == 1 {print}')
bash "$SCRIPT_DIR/check_reproducible.sh" "$target" "$rustc_version" \
    "$clang_version" "$linker_version" "${artifacts[0]}" "${artifacts[1]}"
printf 'Consumer smoke artifacts: %s\n' "$work_dir"
