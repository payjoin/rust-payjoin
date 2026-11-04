#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 1 ] || {
    echo "usage: publish.sh <prepared-package-dir>" >&2
    exit 1
}
revision="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse HEAD)"
cd "$1"
# Publish only what prepare-publish.sh staged for this checkout.
grep -Fq "rev = \"$revision\"" native/Cargo.toml || {
    echo "Staged native/Cargo.toml must pin the release checkout $revision" >&2
    exit 1
}
# A stage built against an unreleased core is only fit for pull request
# checks; consumers must build the core they can fetch from crates.io.
if [[ -e UNPUBLISHED_CORE ]]; then
    echo "Refusing to publish a stage built against an unpublished core:" >&2
    cat UNPUBLISHED_CORE >&2
    exit 1
fi

# Publish the package to pub.dev via automated publishing (OIDC).
# `dart pub publish` has no non-interactive authentication mode: without a
# registered token it falls back to the browser sign-in flow and hangs the
# job, so the runner-injected ACTIONS_ID_TOKEN_REQUEST_* variables (present
# only in jobs granted `id-token: write`) are exchanged here for a
# short-lived token that pub.dev verifies against the repository, tag
# pattern, and environment configured on the package's admin page. This is
# the same exchange the dart-lang/setup-dart action performs; we install
# Dart through nix, so it has to happen here instead.

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?must run in a GitHub Actions job with id-token: write}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?must run in a GitHub Actions job with id-token: write}"

PUB_TOKEN="$(
    curl --silent --show-error --fail --location \
        --header "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=https://pub.dev" |
        jq --raw-output .value
)"
export PUB_TOKEN
dart pub token add https://pub.dev --env-var PUB_TOKEN

dart pub publish --force
