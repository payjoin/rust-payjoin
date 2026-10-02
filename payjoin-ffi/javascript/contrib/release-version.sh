#!/usr/bin/env bash
#
# Print the version the next payjoin-javascript release tag names: the
# `releaseTag` field of package.json. npm rejects build metadata in
# `version`, so the full version lives in `releaseTag`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
jq -er '.releaseTag' package.json
