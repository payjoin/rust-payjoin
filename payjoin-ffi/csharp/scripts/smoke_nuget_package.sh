#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 <package-source> <package-version> [runtime-id]" >&2
    exit 1
fi

PACKAGE_SOURCE=$(cd "$1" && pwd)
PACKAGE_VERSION=$2
RID=${3:-}
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
export DOTNET_CLI_HOME="$WORKDIR/dotnet-home"

native_library_name() {
    case "$1" in
        linux-*)
            echo "libpayjoin_ffi.so"
            ;;
        osx-*)
            echo "libpayjoin_ffi.dylib"
            ;;
        win-*)
            echo "payjoin_ffi.dll"
            ;;
        *)
            echo "Unsupported RID: $1" >&2
            exit 1
            ;;
    esac
}

DOTNET_10_SDK_VERSION=$(dotnet --list-sdks | awk '/^10\./ { print $1; exit }')
if [[ -n $DOTNET_10_SDK_VERSION ]]; then
    cat >"$WORKDIR/global.json" <<EOF
{
  "sdk": {
    "version": "$DOTNET_10_SDK_VERSION",
    "rollForward": "latestFeature"
  }
}
EOF
fi

pushd "$WORKDIR" >/dev/null

dotnet new console --framework net10.0 --output "PayjoinSmoke" --no-restore
dotnet add "PayjoinSmoke/PayjoinSmoke.csproj" package Payjoin \
    --version "$PACKAGE_VERSION" \
    --source "$PACKAGE_SOURCE" \
    --no-restore

cat >"PayjoinSmoke/Program.cs" <<'EOF'
var uri = Payjoin.Url.Parse("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao");
Console.WriteLine(uri.AsString());
EOF

dotnet restore "PayjoinSmoke/PayjoinSmoke.csproj" \
    --source "$PACKAGE_SOURCE" \
    --ignore-failed-sources \
    -p:UseAppHost=false \
    -p:DisableTransitiveFrameworkReferenceDownloads=true
dotnet build "PayjoinSmoke/PayjoinSmoke.csproj" \
    --framework net10.0 \
    --no-restore \
    -p:UseAppHost=false \
    -p:DisableTransitiveFrameworkReferenceDownloads=true

if [[ -n $RID ]]; then
    LIBNAME=$(native_library_name "$RID")
    if [[ -z $(find "PayjoinSmoke/bin/Debug/net10.0" -name "$LIBNAME" -print -quit) ]]; then
        echo "Expected native asset $LIBNAME was not copied for $RID" >&2
        exit 1
    fi
fi

dotnet "PayjoinSmoke/bin/Debug/net10.0/PayjoinSmoke.dll"

popd >/dev/null
