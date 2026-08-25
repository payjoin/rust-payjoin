#!/usr/bin/env bash
set -euo pipefail

# Validate the native lockfile that ships to Dart consumers.
#
# A lockfile resolved through the .cargo/config.local.toml path overlay pins
# the local workspace instead of the published Git revision, and consumers
# cannot reproduce it. Such an entry has no `path` key to grep for: a path
# dependency shows up as a package without a `source` at all, exactly like
# the root wrapper crate. So assert that the wrapper is the only sourceless
# package, and that the pinned `payjoin-ffi` revision still matches the one
# the manifest asks for, which is what `--locked` enforces at build time.

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s MANIFEST LOCKFILE\n' "$0" >&2
    exit 2
fi

manifest=$1
lockfile=$2
root_package=payjoin-ffi-wrapper
repository=https://github.com/payjoin/rust-payjoin.git

for file in "$manifest" "$lockfile"; do
    if [[ ! -f $file ]]; then
        printf 'Production lockfile check failed: %s is missing\n' "$file" >&2
        exit 1
    fi
done

sourceless=$(awk -v root="$root_package" '
    function flush() {
        if (in_package && !sourced && name != root) print name
        in_package = 0
    }
    /^\[\[package\]\]$/ { flush(); in_package = 1; name = ""; sourced = 0; next }
    in_package && /^name = / { name = $3; gsub(/"/, "", name); next }
    in_package && /^source = / { sourced = 1; next }
    in_package && /^[[:space:]]*$/ { flush(); next }
    END { flush() }
' "$lockfile")

if [[ -n $sourceless ]]; then
    printf 'Production lockfile resolves packages from a local path:\n' >&2
    printf '%s\n' "$sourceless" >&2
    printf 'Regenerate it with .cargo/config.local.toml out of the way.\n' >&2
    exit 1
fi

revision=$(sed -n \
    "s|.*git = \"$repository\", rev = \"\([0-9a-f]\{40\}\)\".*|\1|p" \
    "$manifest")
if [[ -z $revision ]]; then
    printf 'Could not read the pinned payjoin-ffi revision from %s\n' \
        "$manifest" >&2
    exit 2
fi

expected="source = \"git+$repository?rev=$revision#$revision\""
if ! grep -Fq "$expected" "$lockfile"; then
    printf 'Production lockfile does not pin payjoin-ffi to %s\n' \
        "$revision" >&2
    printf 'Regenerate it after changing the manifest revision.\n' >&2
    exit 1
fi

printf 'Production lockfile check passed: %s pins %s\n' "$lockfile" "$revision"
