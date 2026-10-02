#!/usr/bin/env bash
#
# Print the version the next payjoin-dart release tag names: the
# `version` of pubspec.yaml.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
version="$(sed -n 's/^version: *\(.*\)$/\1/p' pubspec.yaml | head -1)"
[ -n "$version" ] || exit 1
printf '%s\n' "$version"
