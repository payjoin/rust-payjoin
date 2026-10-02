#!/usr/bin/env bash
#
# Print the version the next payjoin-python release tag names:
# <pyproject version>+payjoin-<payjoin version>. PyPI rejects local
# versions, so pyproject.toml holds only the bare version and the build
# metadata is added here; the publish workflow strips it again.
#
# usage: release-version.sh <payjoin version>
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -n "${1:-}" ] || exit 1
version="$(awk '/^\[/ { in_project = ($0 == "[project]") }
    in_project && /^version *=/ { gsub(/^version *= *"|"$/, ""); print; exit }' pyproject.toml)"
[ -n "$version" ] || exit 1
printf '%s+payjoin-%s\n' "$version" "$1"
