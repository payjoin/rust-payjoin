# Payjoin C# Bindings

C# bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/), generated from
`payjoin-ffi` with UniFFI.

The NuGet package is still prepared as a preview while the C# API stabilizes. The
first release-ready package layout targets .NET 10 and ships a managed
`Payjoin.dll` plus RID-specific native `payjoin_ffi` libraries.

## Install

```shell
dotnet add package Payjoin --prerelease
```

## Requirements

- .NET 10.0 or higher
- A supported RID native asset in the package

The first preview release matrix is:

| OS                  | RID           | Native library         |
| ------------------- | ------------- | ---------------------- |
| Linux arm64         | `linux-arm64` | `libpayjoin_ffi.so`    |
| Linux x64           | `linux-x64`   | `libpayjoin_ffi.so`    |
| macOS Apple Silicon | `osx-arm64`   | `libpayjoin_ffi.dylib` |
| macOS x64           | `osx-x64`     | `libpayjoin_ffi.dylib` |
| Windows arm64       | `win-arm64`   | `payjoin_ffi.dll`      |
| Windows x64         | `win-x64`     | `payjoin_ffi.dll`      |

The package follows the .NET native asset layout:

- `ref/net10.0/Payjoin.dll`
- `runtimes/any/lib/net10.0/Payjoin.dll`
- `runtimes/{rid}/native/{native-library}`

## Minimal Usage

```csharp
var uri = Payjoin.Url.Parse(
    "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao");

Console.WriteLine(uri.AsString());
```

## Development

With nix, the C# development shell provides the Rust toolchain and .NET 10 SDK:

```shell
nix develop .#csharp -c bash payjoin-ffi/csharp/contrib/test.sh
```

Without nix, a Rust toolchain (MSRV: 1.85.0 for this repository) and the .NET 10
SDK are required:

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/csharp

bash ./scripts/generate_bindings.sh
dotnet build Payjoin.Tests.csproj
dotnet test Payjoin.Tests.csproj
```

### Windows

```powershell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/csharp

powershell -ExecutionPolicy Bypass -File .\scripts\generate_bindings.ps1
dotnet build Payjoin.Tests.csproj
dotnet test Payjoin.Tests.csproj
```

Generation uses the Cargo-managed C# generator pinned in `payjoin-ffi/Cargo.toml`.
By default, development generation enables `_test-utils` to keep parity with the
test suite. For production bindings, set `PAYJOIN_FFI_FEATURES` to an empty value
(bash) or pass `-ProductionBindings` (PowerShell — Windows cannot represent an
empty environment variable, so the switch is the only reliable signal there).

## Packaging

Build the release native asset for the current host RID (production features are
the default when `PAYJOIN_FFI_FEATURES` is not set; this step does not regenerate
the C# bindings):

```shell
bash ./scripts/build_nuget_native.sh
```

Any supported RID can also be cross-compiled from a Linux host, which is how CI
builds every native asset (`pip install -r scripts/cross-requirements.txt` for
the version- and hash-pinned toolchain CI uses, and `rustup target add` the
matching triple first):

```shell
PAYJOIN_FFI_CROSS=1 PAYJOIN_FFI_RID=osx-arm64 bash ./scripts/build_nuget_native.sh
```

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_nuget_native.ps1
```

To pack, gather every supported RID under `artifacts/runtimes/{rid}/native/`,
generate production bindings, and run:

```shell
PAYJOIN_FFI_FEATURES= PAYJOIN_FFI_PROFILE=release bash ./scripts/generate_bindings.sh
dotnet pack Payjoin.csproj --configuration Release --output artifacts/packages
```

On Windows:

```powershell
$env:PAYJOIN_FFI_PROFILE = "release"
powershell -ExecutionPolicy Bypass -File .\scripts\generate_bindings.ps1 -ProductionBindings
dotnet pack Payjoin.csproj --configuration Release --output artifacts/packages
```

Validate the package in a clean sample app (`auto` derives the version from the
packed artifact; an explicit version is also accepted):

```shell
bash ./scripts/smoke_nuget_package.sh artifacts/packages auto linux-x64
```

CI performs the package build from release native assets and runs the smoke test
on each supported RID before publishing should be considered. The maintainer
release and publish workflow is documented in
[`RELEASING.md`](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/csharp/RELEASING.md).
