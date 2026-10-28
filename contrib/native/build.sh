#!/usr/bin/env bash
# Build the payjoin-ffi native library for one target triple under the
# native build contract and copy it to $2/<triple>/.
set -euo pipefail

target=$1
out_dir=$(realpath -m "$2")
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
target_dir=$(realpath -m "${CARGO_TARGET_DIR:-$repo/target}")
target_env=${target//-/_}
CARGO_HOME=$(realpath -m "${CARGO_HOME:-$HOME/.cargo}")
export CARGO_HOME
# Two builds of the same zig version share a cache key, so keep the cache
# with the build rather than in $HOME.
export ZIG_GLOBAL_CACHE_DIR=$target_dir/zig-cache

cd "$repo"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

# rustc and the C compiler see the same prefixes, and the last match wins.
prefixes=(
    "$repo=/payjoin"
    "$target_dir=/payjoin/target"
    "$CARGO_HOME=/cargo"
    "${RUSTUP_HOME:-$HOME/.rustup}=/rustup"
)
rustflags=()
cflags=()
cargo=(cargo build)
cargo_target=$target
cflag=

case $target in
    *-unknown-linux-gnu)
        lib=libpayjoin_ffi.so
        cargo=(cargo zigbuild)
        cargo_target=$target.2.17
        ;;
    *-pc-windows-msvc)
        lib=payjoin_ffi.dll
        arch=${target%%-*}
        # MSVC's CRT and the Windows SDK from the Visual Studio manifest in
        # vs-channel.json, splatted once per set of pins.
        sdk=10.0.26100
        crt=14.44.17.14
        manifest=$(sha256sum contrib/native/vs-channel.json | cut -c1-16)
        xwin_dir=${XDG_CACHE_HOME:-$HOME/.cache}/payjoin-xwin/$manifest-$sdk-$crt
        if [[ ! -d $xwin_dir ]]; then
            # Concurrent first builds splat their own copies, and the first
            # one done is kept.
            mkdir -p "$(dirname "$xwin_dir")"
            tmp=$(mktemp -d "$xwin_dir.XXXXXX")
            xwin --accept-license --cache-dir "$tmp/download" \
                --manifest contrib/native/vs-channel.json \
                --sdk-version "$sdk" --crt-version "$crt" \
                --arch x86_64,aarch64 splat --output "$tmp/splat"
            mv -T "$tmp/splat" "$xwin_dir" 2>/dev/null || true
            rm -rf "$tmp"
        fi
        export "CARGO_TARGET_${target_env^^}_LINKER=lld-link" \
            "CC_$target_env=clang-cl" "AR_$target_env=llvm-lib"
        # lld-link otherwise stamps the build time, and the PDB rustc asks
        # for gives the DLL an id that depends on the build paths.
        rustflags+=(-Clink-arg=/Brepro -Clink-arg=/DEBUG:NONE)
        for dir in crt/lib sdk/lib/um sdk/lib/ucrt; do
            rustflags+=("-Lnative=$xwin_dir/$dir/$arch")
        done
        # clang-cl takes clang's own options behind /clang:.
        cflag=/clang:
        cflags+=("--target=$target")
        for dir in crt/include sdk/include/ucrt sdk/include/um sdk/include/shared; do
            cflags+=(/imsvc "$xwin_dir/$dir")
        done
        prefixes+=("$xwin_dir=/xwin")
        ;;
    *-linux-android*)
        lib=libpayjoin_ffi.so
        # API 21 is Rust's floor. NDK 29 aligns 64-bit libraries to 16 KB.
        ndk_bin=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
        clang=$ndk_bin/${target/armv7/armv7a}21-clang
        export "CARGO_TARGET_${target_env^^}_LINKER=$clang" "CC_$target_env=$clang" \
            "AR_$target_env=$ndk_bin/llvm-ar"
        prefixes+=("$(realpath "$ANDROID_NDK_HOME")=/ndk")
        ;;
    *-apple-darwin)
        # Flutter's floor, and the first macOS on Apple silicon.
        macos=10.15
        if [[ $target == aarch64-* ]]; then
            macos=11.0
        fi
        export APPLE_CC_TARGET=${target%%-*}-macos.$macos
        export MACOSX_DEPLOYMENT_TARGET=$macos
        ;;&
    aarch64-apple-ios | aarch64-apple-ios-sim)
        export APPLE_CC_TARGET=aarch64-ios.13.0
        if [[ $target == *-sim ]]; then
            APPLE_CC_TARGET+=-simulator
        fi
        export IPHONEOS_DEPLOYMENT_TARGET=13.0
        ;;&
    *-apple-darwin | aarch64-apple-ios | aarch64-apple-ios-sim)
        lib=libpayjoin_ffi.dylib
        export SDKROOT=$target_dir/apple-stubs
        bash contrib/native/apple-stubs.sh "$SDKROOT"
        export "CARGO_TARGET_${target_env^^}_LINKER=$repo/contrib/native/apple-cc.sh"
        export "CC_$target_env=$repo/contrib/native/apple-cc.sh"
        export "AR_$target_env=$(command -v zig) ar"
        rustflags+=("-Clink-arg=-Wl,-install_name,@rpath/$lib")
        ;;
    *)
        echo "unsupported target: $target" >&2
        exit 1
        ;;
esac

for prefix in "${prefixes[@]}"; do
    rustflags+=("--remap-path-prefix=$prefix")
    cflags+=("$cflag-ffile-prefix-map=$prefix")
done
# Quoted, because cc-rs would otherwise split a path with spaces.
export CC_SHELL_ESCAPED_FLAGS=1
export "CFLAGS_$target_env=$(printf '%q ' "${cflags[@]}")"
CARGO_ENCODED_RUSTFLAGS=$(
    IFS=$'\x1f'
    echo "${rustflags[*]}"
)
export CARGO_ENCODED_RUSTFLAGS

"${cargo[@]}" --locked --release --package payjoin-ffi --lib \
    --target "$cargo_target" --target-dir "$target_dir"
mkdir -p "$out_dir/$target"
cp "$target_dir/$target/release/$lib" "$out_dir/$target/"
