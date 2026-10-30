# Contributing to the Payjoin C# Bindings

C# bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/), generated from
`payjoin-ffi` with UniFFI. This document covers building the bindings from
source, running the tests, and producing the NuGet package. For using the
published package, see [`README.md`](./README.md).

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

CI packs every RID's native asset from the native workflow, which builds them
on Linux under the [native build contract](../../contrib/native/README.md). To
build one the same way, run from the repository root with the target triple for the RID, then copy
`<out-dir>/<triple>/*` to `payjoin-ffi/csharp/artifacts/runtimes/{rid}/native/`:

```shell
nix develop .#native -c contrib/native/build.sh aarch64-apple-darwin <out-dir>
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
