#!/usr/bin/env bash
set -euo pipefail

# Assert the native build outputs exist before a tarball is packed.
#
# Runs as the "prepack" guard on every npm pack/publish, and as a step in
# contrib/pack.sh after the build. package.json ships these outputs via
# "files", but they are gitignored and produced only by
# scripts/generate_bindings.sh, which builds the iOS artifacts (xcframework,
# ios/, podspec) solely on macOS and silently skips them elsewhere. Without
# this check a pack that skipped generation, or ran on Linux, would ship a
# broken tarball with no error. Fail loudly instead. See CONTRIBUTING.md for
# the build steps.

cd "$(dirname "$0")/.."

required=(
    PayjoinRnFramework.xcframework
    android
    ios
    cpp
)

missing=()
for path in "${required[@]}"; do
    [[ -e $path ]] || missing+=("$path")
done

shopt -s nullglob
podspecs=(*.podspec)
[[ ${#podspecs[@]} -gt 0 ]] || missing+=("*.podspec")

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Error: native build artifacts are missing:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    echo "Build them by following CONTRIBUTING.md before packing or" >&2
    echo "publishing (iOS outputs require a macOS host)." >&2
    exit 1
fi
