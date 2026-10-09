#!/usr/bin/env bash
# Attach the collected binding assets to the shared release.
# GH_TOKEN and GH_REPO are supplied by the caller.
set -euo pipefail
[ "$#" -eq 3 ] || {
    echo "usage: attach-assets.sh <tag> <prerelease:true|false> <asset-dir>" >&2
    exit 1
}
tag="$1"
flags=()
case "$2" in
    true) flags+=(--prerelease) ;;
    false) ;;
    *)
        echo "Invalid prerelease value: $2; expected true or false" >&2
        exit 1
        ;;
esac
shopt -s nullglob
assets=("$3"/*)
[ "${#assets[@]}" -gt 0 ] || {
    echo "No release assets found in $3" >&2
    exit 1
}
if ! gh release view "$tag" >/dev/null 2>&1; then
    # Another caller may create the release after our initial lookup.
    # A failed create is safe only if that release now exists.
    gh release create "$tag" --verify-tag --title "Release $tag" \
        --notes "Language bindings for $tag" "${flags[@]}" ||
        gh release view "$tag" >/dev/null
fi
# Retries replace the collected assets without changing release metadata.
gh release upload "$tag" "${assets[@]}" --clobber
