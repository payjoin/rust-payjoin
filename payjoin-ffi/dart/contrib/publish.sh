#!/usr/bin/env bash
set -euo pipefail

# Publish the package to pub.dev via automated publishing (OIDC).
# `dart pub publish` has no non-interactive authentication mode: without a
# registered token it falls back to the browser sign-in flow and hangs the
# job, so the runner-injected ACTIONS_ID_TOKEN_REQUEST_* variables (present
# only in jobs granted `id-token: write`) are exchanged here for a
# short-lived token that pub.dev verifies against the repository, tag
# pattern, and environment configured on the package's admin page. This is
# the same exchange the dart-lang/setup-dart action performs; we install
# Dart through nix, so it has to happen here instead. Run
# prepare-publish.sh first to generate the bindings that get packed.

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

cd "$(dirname "$0")/.."
dart pub publish --force
