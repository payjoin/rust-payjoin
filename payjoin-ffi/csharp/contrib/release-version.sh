#!/usr/bin/env bash
#
# Print the version the next payjoin-csharp release tag names: the
# <Version> of Payjoin.csproj.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
version="$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p' Payjoin.csproj | head -1)"
[ -n "$version" ] || exit 1
printf '%s\n' "$version"
