#!/usr/bin/env bash
# Compiler and linker for the Apple targets: zig for $APPLE_CC_TARGET
# against the stub SDK in $SDKROOT. The target flags rustc and cc-rs pass
# are dropped in favor of those.
set -euo pipefail

args=()
while (($#)); do
    case $1 in
        -target | -arch | -isysroot) shift ;;
        --target=* | -mmacosx-version-min=* | -mios-version-min=* | -mios-simulator-version-min=* | -miphoneos-version-min=*) ;;
        *) args+=("$1") ;;
    esac
    shift
done

# -headerpad_max_install_names leaves room for Flutter's install_name_tool,
# and -S keeps zig from writing object paths and mtimes into stabs.
exec zig cc -target "$APPLE_CC_TARGET" --sysroot "$SDKROOT" \
    -isystem "$SDKROOT/usr/include" -L/usr/lib \
    -Wl,-headerpad_max_install_names -Wl,-S "${args[@]}"
