#!/usr/bin/env bash
# Run the consumer program against <package-dir> in the default prebuilt
# mode, so the hook must find the library for this host under prebuilt/.
set -euo pipefail
[ "$#" -eq 1 ] || {
    echo "usage: test-prebuilt.sh <package-dir>" >&2
    exit 1
}
package="$(realpath "$1")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -a "$(dirname "${BASH_SOURCE[0]}")/consumer" "$work/app"
ln -s "$package" "$work/payjoin"
cd "$work/app"
dart pub get
dart run bin/main.dart
