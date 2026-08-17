#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
    printf 'Usage: %s TARGET RUSTC CLANG LINKER FIRST_ARTIFACT SECOND_ARTIFACT\n' "$0" >&2
    exit 2
fi

target=$1
rustc_version=$2
clang_version=$3
linker_version=$4
first_artifact=$5
second_artifact=$6

if [[ ! -f "$first_artifact" || ! -f "$second_artifact" ]]; then
    printf 'Reproducibility check failed: both artifacts must be regular files\n' >&2
    exit 2
fi

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    else
        printf 'Cannot compute SHA-256: sha256sum or shasum is required\n' >&2
        exit 2
    fi
}

printf 'Target: %s\n' "$target"
printf 'rustc: %s\n' "$rustc_version"
printf 'clang: %s\n' "$clang_version"
printf 'linker: %s\n' "$linker_version"
printf '%s: %s\n' "$first_artifact" "$(sha256 "$first_artifact")"
printf '%s: %s\n' "$second_artifact" "$(sha256 "$second_artifact")"

if ! cmp -s "$first_artifact" "$second_artifact"; then
    printf 'Reproducibility check failed: artifacts differ byte-for-byte\n' >&2
    exit 1
fi

printf 'Reproducibility check passed: artifacts are byte-for-byte identical\n'
