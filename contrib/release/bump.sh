#!/usr/bin/env bash
#
# Prepare a release crate's bump commit. Sets the crate's version, rewrites
# every workspace member's version requirement on it, renames the
# "## Unreleased" changelog section to the new version and opens a fresh
# empty one above it, regenerates both lock files, then runs
# check-invariants. Leaves the changes uncommitted for review.
#
# payjoin-ffi is bumped the same way, except that its changelog entry
# opens by naming the wrapped payjoin release, and its version is also
# set in the Python, JavaScript, Dart and C# package manifests, the uv and
# npm lock files, and the language changelogs, which open with a stock
# entry that points at payjoin-ffi/CHANGELOG.md. bindings-version.sh then
# confirms the packages agree.
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
    sed -n '2,22p' "$0" >&2
    exit 1
}
crate="$1"
new="$2"
die() {
    echo "bump: $*" >&2
    exit 1
}

# Rename a changelog's "## Unreleased" section to <heading>, open a fresh
# empty one above it, and make <line> the first entry of the renamed
# section, above any lines pull requests left there. The list stays tight,
# without a blank line after <line>, so prettier does not reflow it.
open_section() { # <file> <heading> <line>
    awk -v h="$2" -v l="$3" '
        !seen && $0 == "## Unreleased" { seen = 1; print; print ""; print h; print ""; print l; next }
        seen == 1 { seen = 2; if ($0 == "") { held = 1; next } }
        held { held = 0; if ($0 !~ /^- /) print "" }
        { print }
    ' "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}

# Set the binding packages to the payjoin-ffi version. Each manifest is
# edited in place with sed and read back, as the Cargo.toml edit is, so a
# line that no longer looks the way this expects fails instead of being
# skipped. The lock files are edited the same way rather than regenerated,
# so the only change in them is the version.
bump_bindings() { # <old> <new>
    local old="$1" new="$2" old_py new_py f line
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

    # Each language changelog opens the new section with a stock entry that
    # points at the shared changelog, above any language-specific lines a
    # pull request left under "## Unreleased". The URL is absolute because
    # pub.dev renders Dart's changelog and cannot resolve ../CHANGELOG.md.
    line="- Wraps payjoin-ffi $new; see its [changelog](https://github.com/payjoin/rust-payjoin/blob/payjoin-ffi-$new/payjoin-ffi/CHANGELOG.md)."
    for f in payjoin-ffi/python/CHANGELOG.md payjoin-ffi/javascript/CHANGELOG.md payjoin-ffi/dart/CHANGELOG.md; do
        if grep -qx '## Unreleased' "$f"; then
            open_section "$f" "## [$new]" "$line"
            echo "  $f: '## Unreleased' -> '## [$new]', fresh Unreleased section added"
        else
            { printf '## [%s]\n\n%s\n\n' "$new" "$line" && cat "$f"; } >"$f.tmp" && mv "$f.tmp" "$f"
            echo "  $f: '## [$new]' section added"
        fi
        { grep -qxF -e "## [$new]" "$f" && grep -qxF -e "$line" "$f"; } ||
            die "could not add the $new section to $f"
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

RELEASE_METADATA="$(cargo_metadata)"
old="$(manifest_version "$crate")"
[ "$old" != "$new" ] || die "$crate is already $new"
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

[ "$crate" != payjoin-ffi ] || bump_bindings "$old" "$new"

# The crate's changelog keeps its heading style: the binding changelogs
# bracket versions, the crates do not.
changelog="$crate/CHANGELOG.md"
grep -qx '## Unreleased' "$changelog" ||
    die "$changelog has no '## Unreleased' section; add the lines for this release under one first"
if grep -q '^## \[' "$changelog"; then
    heading="## [$new]"
else
    heading="## $new"
fi
if [ "$crate" = payjoin-ffi ]; then
    # The entry names the wrapped payjoin release first; the manifests no
    # longer carry it, and the package docs point readers here for it.
    line="- Wraps payjoin $(manifest_version payjoin)"
    open_section "$changelog" "$heading" "$line"
    grep -qxF -e "$line" "$changelog" || die "could not add '$line' to $changelog"
    echo "  $changelog: '## Unreleased' -> '$heading' opening with '$line', fresh Unreleased section added"
else
    sed -i "0,/^## Unreleased$/s//## Unreleased\n\n$heading/" "$changelog"
    echo "  $changelog: '## Unreleased' -> '$heading', fresh Unreleased section added"
fi

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
