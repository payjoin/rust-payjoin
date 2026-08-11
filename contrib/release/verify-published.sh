#!/usr/bin/env bash
#
# After publishing, confirm crates.io reports a checksum matching the
# attested .crate and docs.rs built the docs. Runs after the upload, so a
# mismatch is a loud alert, not a gate. Poll counts and interval are
# overridable via the environment; the defaults suit CI.
set -euo pipefail

[ "$#" -eq 3 ] || {
    echo "usage: verify-published.sh <crate> <version> <crate-file>" >&2
    exit 1
}
crate="$1"
version="$2"
file="$3"
ua="rust-payjoin release verify-published"
interval="${POLL_INTERVAL:-10}"
die() {
    echo "verify-published: $*" >&2
    exit 1
}

# Poll a URL until its jq filter yields non-empty output; print it, or fail.
poll() {
    local attempts="$1" url="$2" filter="$3" out i
    for ((i = 0; i < attempts; i++)); do
        out="$(curl -sfL -H "User-Agent: $ua" "$url" 2>/dev/null | jq -r "$filter" 2>/dev/null || true)"
        [ -n "$out" ] && {
            printf '%s' "$out"
            return 0
        }
        sleep "$interval"
    done
    return 1
}

[ -f "$file" ] || die "no such file: $file"
local_sha="$(sha256sum "$file" | cut -d' ' -f1)"

echo "Waiting for $crate $version on crates.io (${CRATES_IO_ATTEMPTS:-30} checks, ${interval}s apart)"
published_sha="$(poll "${CRATES_IO_ATTEMPTS:-30}" \
    "https://crates.io/api/v1/crates/$crate/$version" '.version.checksum // empty')" ||
    die "$crate $version never appeared on crates.io"
[ "$published_sha" = "$local_sha" ] ||
    die "checksum mismatch: crates.io $published_sha vs local $local_sha"
echo "crates.io checksum matches the attested .crate ($local_sha)"

# docs.rs builds documentation only for crates with a library target;
# binary-only crates (e.g. payjoin-cli) never reach doc_status == true.
if cargo metadata --format-version 1 --no-deps 2>/dev/null |
    jq -e --arg c "$crate" \
        'any(.packages[] | select(.name == $c) | .targets[].kind[]; . | test("^(lib|rlib|dylib|cdylib|staticlib|proc-macro)$"))' \
        >/dev/null; then
    echo "Waiting for docs.rs to build $crate $version (${DOCS_RS_ATTEMPTS:-60} checks, ${interval}s apart)"
    poll "${DOCS_RS_ATTEMPTS:-60}" \
        "https://docs.rs/crate/$crate/$version/status.json" 'select(.doc_status == true) | "built"' >/dev/null ||
        die "docs.rs did not build $crate $version"
    echo "docs.rs built $crate $version"
else
    echo "Skipping docs.rs check for $crate (no library target)"
fi
