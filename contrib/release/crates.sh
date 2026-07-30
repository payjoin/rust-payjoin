#!/usr/bin/env bash
#
# Shared helpers for the release scripts, sourced like contrib/lockfile.sh.
# Versions come from `cargo metadata` parsed with jq, not from grepping
# manifests.

RELEASE_CRATES="payjoin payjoin-cli payjoin-mailroom"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# `cargo metadata` for the workspace. Command substitutions run in a subshell
# that cannot write the cache back, so a caller that queries repeatedly sets
# it once in its own shell: RELEASE_METADATA="$(cargo_metadata)".
cargo_metadata() {
    if [ -n "${RELEASE_METADATA:-}" ]; then
        printf '%s' "$RELEASE_METADATA"
    else
        cargo metadata --no-deps --format-version 1 --manifest-path "$REPO_ROOT/Cargo.toml"
    fi
}

# Print a crate's manifest version.
manifest_version() {
    cargo_metadata | jq -r --arg c "$1" '.packages[] | select(.name == $c) | .version'
}

# Print the release crate a `<crate>-<version>` tag belongs to, or fail.
crate_from_tag() {
    local crate="${1%-[0-9]*}"
    case " $RELEASE_CRATES " in
        *" $crate "*) printf '%s' "$crate" ;;
        *) return 1 ;;
    esac
}

# Print the version in a `<crate>-<version>` tag.
version_from_tag() {
    local crate
    crate="$(crate_from_tag "$1")" || return 1
    printf '%s' "${1#"$crate"-}"
}

# Succeed if the version has a semver pre-release suffix.
is_prerelease() {
    case "$1" in
        *-*) return 0 ;;
        *) return 1 ;;
    esac
}

# Print "<dep>\t<req>" for each sibling release-crate dependency of a crate.
sibling_deps() {
    local rel
    rel="$(printf '%s' "$RELEASE_CRATES" | jq -R 'split(" ")')"
    cargo_metadata | jq -r --arg self "$1" --argjson rel "$rel" '
        .packages[] | select(.name == $self) | .dependencies[]
        | select(.path == null and .name != $self and (.name | IN($rel[])))
        | "\(.name)\t\(.req)"
    '
}

# Succeed if <crate> <version> exists on crates.io.
crate_published() {
    curl -sfL -o /dev/null -H "User-Agent: rust-payjoin release tooling" \
        "https://crates.io/api/v1/crates/$1/$2"
}
