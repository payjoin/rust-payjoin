#!/usr/bin/env bash
#
# Prepare a release crate's bump commit. Sets the crate's version, rewrites
# every workspace member's version requirement on it, moves the changelog
# fragments in <crate>/changelog.d/ into a new section of its CHANGELOG.md
# and deletes them, fills in the version placeholders in the crate's
# source, regenerates both lock files, then runs check-invariants. Leaves
# the changes uncommitted for review.
#
# payjoin-ffi is bumped the same way, except that its changelog entry
# opens by naming the wrapped payjoin release, and its version is also
# set in the Python, JavaScript, Dart and C# package manifests, the uv and
# npm lock files, and the language changelogs, which open with a stock
# entry that points at payjoin-ffi/CHANGELOG.md, followed by the fragments
# in that language's changelog.d/. bindings-version.sh then confirms the
# packages agree.
#
# Run again at the version a bump already set, it folds the fragments
# that landed since into that version's sections and fills in any new
# placeholders, so a bump PR can take in the pull requests merged while it
# was open. check-invariants fails while fragments are left over, so a
# release is never tagged without them.
#
# usage: bump.sh [--no-lock] <crate> <version>
#   crate       a release crate, or payjoin-ffi for the language bindings
#   --no-lock   skip contrib/update-lock-files.sh (then check-invariants
#               reports the stale lock files, as it should)
#
# Needs jq, and without --no-lock a rustup nightly toolchain, which the
# lock file script calls as `cargo +nightly`.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/release/crates.sh
source "$DIR/crates.sh"
cd "$REPO_ROOT"

lock=1
if [ "${1:-}" = "--no-lock" ]; then
    lock=0
    shift
fi
[ "$#" -eq 2 ] || {
    sed -n '2,30p' "$0" >&2
    exit 1
}
crate="$1"
new="$2"
die() {
    echo "bump: $*" >&2
    exit 1
}

# Print the section that the changelog.d/ fragments beside <changelog>
# hold, failing on a malformed fragment.
fragments() { # <changelog>
    "$DIR/changelog-fragments.sh" "$(dirname "$1")/changelog.d"
}

# Write the <heading> section of <changelog> from the fragments beside it,
# then delete them. A section that already exists keeps its text: any
# opening prose stays on top and its items come before the fragments'.
# A new section goes above the newest one and opens with <line>, when
# given. Blank lines within items stay intact when the section is folded.
write_section() { # <changelog> <heading> [line]
    local changelog="$1" heading="$2" line="${3:-}" dir start end last tmp body
    dir="$(dirname "$changelog")/changelog.d"
    tmp="$(mktemp -d -p "$WORK")"
    start="$(grep -n -m1 -xF -e "$heading" "$changelog" | cut -d: -f1 || true)"
    if [ -n "$start" ]; then
        end="$(tail -n "+$((start + 1))" "$changelog" | grep -n -m1 '^## ' | cut -d: -f1 || true)"
        end="${end:+$((start + end))}"
        last='$'
        [ -z "$end" ] || last="$((end - 1))"
        sed -n "$((start + 1)),${last}p" "$changelog" >"$tmp/section"
        # Opening prose is everything before the first item or heading.
        awk '/^(- |### )/ { exit } { print }' "$tmp/section" |
            sed -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}' >"$tmp/prose"
        awk 'p || /^(- |### )/ { p = 1; print }' "$tmp/section" >"$tmp/items"
    else
        : >"$tmp/prose"
        [ -z "$line" ] || printf '%s\n' "$line" >"$tmp/items"
        touch "$tmp/items"
    fi
    # The section's own lines are reported against "items", counted from
    # its first item or heading.
    body="$("$DIR/changelog-fragments.sh" --first "$tmp/items" "$dir")" ||
        die "fix the fragment named above, or for an \"items\" line, the '$heading' section of $changelog"
    [ ! -s "$tmp/prose" ] || body="$(cat "$tmp/prose")"$'\n\n'"$body"
    {
        if [ -n "$start" ]; then
            head -n "$start" "$changelog"
            printf '\n%s\n' "$body"
            [ -z "$end" ] || { echo && tail -n "+$end" "$changelog"; }
        else
            start="$(grep -n -m1 '^## ' "$changelog" | cut -d: -f1 || true)"
            if [ -n "$start" ]; then
                head -n "$((start - 1))" "$changelog"
            else
                cat "$changelog"
                echo
            fi
            printf '%s\n\n%s\n' "$heading" "$body"
            [ -z "$start" ] || { echo && tail -n "+$start" "$changelog"; }
        fi
    } >"$tmp/changelog"
    mv "$tmp/changelog" "$changelog"
    rm -f "$dir"/*.md
    rmdir "$dir" 2>/dev/null || true
}

# Replace the version placeholder in the crate's source. A bare
# `since = "0.0.0-unreleased"` (a deprecation attribute) takes the new
# version. `since <crate> 0.0.0-unreleased` in prose takes that workspace
# crate's version: the bindings' doc comments name the payjoin release, since
# UniFFI does not carry Rust deprecation attributes into the bindings.
fill_unreleased() { # <new>
    local placeholder="${UNRELEASED//./\\.}" name version f
    while IFS= read -r f; do
        sed -i "s/since = \"$placeholder\"/since = \"$1\"/g" "$f"
        while IFS= read -r name; do
            if [ "$name" = "$crate" ]; then
                version="$1"
            else
                version="$(manifest_version "$name")"
            fi
            sed -i "s/since $name $placeholder/since $name $version/g" "$f"
        done < <(cargo_metadata | jq -r '.packages[].name')
        echo "  $f: $UNRELEASED filled in"
    done < <(git grep -l -F -e "$UNRELEASED" -- "$crate/src")
}

# Set the binding packages to the payjoin-ffi version. Each manifest is
# edited in place with sed and read back, as the Cargo.toml edit is, so a
# line that no longer looks the way this expects fails instead of being
# skipped. The lock files are edited the same way rather than regenerated,
# so the only change in them is the version.
bump_bindings() { # <old> <new>
    local old="$1" new="$2" old_py new_py f
    # Python spells a -rc.N pre-release as rcN (PEP 440), in uv.lock too.
    old_py="${old/-rc./rc}"
    new_py="${new/-rc./rc}"

    f=payjoin-ffi/python/pyproject.toml
    sed -i "0,/^version = \"$old_py\"/s//version = \"$new_py\"/" "$f"
    [ "$(sed -n 's/^version = "\(.*\)"$/\1/p' "$f" | head -1)" = "$new_py" ] ||
        die "could not set version in $f"
    echo "  $f: version -> $new_py"

    # The package's own entry: the version line that follows its name.
    f=payjoin-ffi/python/uv.lock
    sed -i "/^name = \"payjoin\"$/{n;s/^version = \"$old_py\"$/version = \"$new_py\"/}" "$f"
    [ "$(grep -A1 '^name = "payjoin"$' "$f" | sed -n 's/^version = "\(.*\)"$/\1/p')" = "$new_py" ] ||
        die "could not set version in $f"
    echo "  $f: version -> $new_py"

    # The root entry of package.json and, in the lock, of packages[""].
    for f in payjoin-ffi/javascript/package.json payjoin-ffi/javascript/package-lock.json; do
        sed -i "/^ *\"name\": \"payjoin\",$/{n;s/^\( *\"version\": \"\)$old\"/\1$new\"/}" "$f"
        [ "$(jq -r '[.version, .packages[""].version // .version] | unique | join(" ")' "$f")" = "$new" ] ||
            die "could not set version in $f"
        echo "  $f: version -> $new"
    done

    f=payjoin-ffi/dart/pubspec.yaml
    sed -i "s/^version: $old$/version: $new/" "$f"
    [ "$(sed -n 's/^version: *//p' "$f")" = "$new" ] || die "could not set version in $f"
    echo "  $f: version -> $new"

    f=payjoin-ffi/csharp/Payjoin.csproj
    sed -i "s#<Version>$old</Version>#<Version>$new</Version>#" "$f"
    [ "$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p' "$f" | head -1)" = "$new" ] ||
        die "could not set Version in $f"
    echo "  $f: Version -> $new"

}

# Each language changelog opens the new section with a stock entry that
# points at the shared changelog, above any language-specific fragments.
# The URL is absolute because pub.dev renders Dart's changelog and cannot
# resolve ../CHANGELOG.md.
binding_changelogs() { # <new>
    local line f
    line="- Wraps payjoin-ffi $1; see its [changelog](https://github.com/payjoin/rust-payjoin/blob/payjoin-ffi-$1/payjoin-ffi/CHANGELOG.md)."
    for f in "${LANGUAGE_CHANGELOGS[@]}"; do
        write_section "$f" "## [$1]" "$line"
        { grep -qxF -e "## [$1]" "$f" && grep -qxF -e "$line" "$f"; } ||
            die "could not write the $1 section of $f"
        echo "  $f: '## [$1]' section written"
    done
}

case " $RELEASE_CRATES payjoin-ffi " in
    *" $crate "*) ;;
    *) die "$crate is not a release crate ($RELEASE_CRATES) or payjoin-ffi" ;;
esac
if [ "$crate" = payjoin-ffi ]; then
    # The rule bindings-version.sh enforces: pre-releases are -rc.N only.
    [[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] ||
        die "$new must be MAJOR.MINOR.PATCH, optionally followed by -rc.N"
else
    [[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "$new is not a semver version"
fi
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "commit or discard your changes first"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Check every fragment this bump will move before changing anything. The
# bump deletes them, so an uncommitted one would be lost from the tree
# while its text ships in the release.
changelog="$crate/CHANGELOG.md"
LANGUAGE_CHANGELOGS=(payjoin-ffi/python/CHANGELOG.md payjoin-ffi/javascript/CHANGELOG.md payjoin-ffi/dart/CHANGELOG.md)
mapfile -t dirs < <(changelog_dirs "$crate")
untracked="$(git ls-files --others -- "${dirs[@]}")"
[ -z "$untracked" ] || die "commit or remove the untracked files first: $untracked"
notes="$(fragments "$changelog")" || die "fix the fragment named above first"
if [ "$crate" = payjoin-ffi ]; then
    for f in "${LANGUAGE_CHANGELOGS[@]}"; do
        notes+="$(fragments "$f")" || die "fix the fragment named above first"
    done
fi

# The crate's changelog keeps its heading style: the binding changelogs
# bracket versions, the crates do not.
if grep -q '^## \[' "$changelog"; then
    heading="## [$new]"
else
    heading="## $new"
fi

RELEASE_METADATA="$(cargo_metadata)"
old="$(manifest_version "$crate")"
if [ "$old" = "$new" ]; then
    grep -qxF -e "$heading" "$changelog" ||
        die "$crate is already $new, but $changelog has no '$heading' section to fold fragments into"
    [ -n "$notes" ] || die "$crate is already $new and no fragments are left to fold in"
    echo "Folding new fragments into $crate $new"
    write_section "$changelog" "$heading"
    echo "  $changelog: fragments from $crate/changelog.d/ folded into '$heading'"
    [ "$crate" != payjoin-ffi ] || binding_changelogs "$new"
    fill_unreleased "$new"
    "$DIR/check-invariants.sh" "$crate"
    echo
    echo "Review the '$heading' section of $changelog, then amend the bump commit with:"
    echo "  git commit --amend -a --no-edit"
    exit 0
fi
[ "$crate" = payjoin-ffi ] || [ -n "$notes" ] ||
    die "$crate/changelog.d/ has no fragments; a release needs at least one changelog line"
echo "Bumping $crate $old -> $new"

# The crate's own version: the first line-anchored `version =` in its manifest.
sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" "$crate/Cargo.toml"
[ "$(sed -n 's/^version = "\(.*\)"/\1/p' "$crate/Cargo.toml" | head -1)" = "$new" ] ||
    die "could not set version in $crate/Cargo.toml"

# Every workspace member that requires it by version. Members use the
# single-line table form `crate = { version = "x", ... }`.
while IFS= read -r manifest; do
    [ -f "$manifest" ] || continue
    if grep -q "^$crate = { version = \"$old\"" "$manifest"; then
        sed -i "s/^\($crate = { version = \"\)$old\"/\1$new\"/" "$manifest"
        echo "  $manifest: requirement on $crate -> $new"
    fi
done < <(cargo_metadata | jq -r '.packages[].manifest_path')

if [ "$crate" = payjoin-ffi ]; then
    bump_bindings "$old" "$new"
    binding_changelogs "$new"
fi

if [ "$crate" = payjoin-ffi ]; then
    # The entry names the wrapped payjoin release first; the manifests no
    # longer carry it, and the package docs point readers here for it.
    line="- Wraps payjoin $(manifest_version payjoin)"
    write_section "$changelog" "$heading" "$line"
    grep -qxF -e "$line" "$changelog" || die "could not add '$line' to $changelog"
    echo "  $changelog: '$heading' section added from $crate/changelog.d/, opening with '$line'"
else
    write_section "$changelog" "$heading"
    echo "  $changelog: '$heading' section added from $crate/changelog.d/"
fi

fill_unreleased "$new"

if [ "$lock" -eq 1 ]; then
    echo "Regenerating lock files (contrib/update-lock-files.sh)"
    ./contrib/update-lock-files.sh
fi

"$DIR/check-invariants.sh" "$crate"
if [ "$crate" = payjoin-ffi ]; then
    # Assigned first so a failing check stops the script under set -e.
    agreed="$("$DIR/bindings-version.sh")"
    echo "Binding packages agree at $agreed"
fi
echo
if [ "$crate" = payjoin-ffi ]; then
    echo "Review the '$heading' sections of $changelog and the language changelogs, then commit as:"
else
    echo "Review the '$heading' section of $changelog, then commit as:"
fi
echo "  git commit -am 'Bump $crate version to $new'"
