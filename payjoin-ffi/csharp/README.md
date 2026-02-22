# Payjoin C# Bindings

Welcome to the C# language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Running Tests

Follow these steps to clone the repository and run the tests.

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/csharp

# Generate the bindings
bash ./scripts/generate_bindings.sh

# Build the project
dotnet build

# Run all tests
dotnet test
```

### Windows (PowerShell)

```powershell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/csharp

# Generate the bindings
powershell -ExecutionPolicy Bypass -File .\scripts\generate_bindings.ps1

# Build the project
dotnet build

# Run all tests
dotnet test
```

### Windows (Git Bash / MSYS)

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/csharp
bash ./scripts/generate_bindings.sh
dotnet build
dotnet test
```

## Requirements

- .NET 8.0 or higher
- Rust toolchain (MSRV: 1.85.0 for this repository)
- Cargo will fetch the C# generator from `chavic/uniffi-bindgen-cs` at commit `878a3d269eacce64beadcd336ade0b7c8da09824` (pinned in `payjoin-ffi/Cargo.toml`)

## Configuration

Generation uses the Cargo-managed C# generator from `payjoin-ffi/Cargo.toml`.

By default, generation builds `payjoin-ffi` with `_test-utils,_manual-tls` so C# integration tests can use local HTTPS services with generated self-signed certificates. Override via `PAYJOIN_FFI_FEATURES`.

### Unix shells

```shell
export PAYJOIN_FFI_FEATURES=_test-utils,_manual-tls     # default behavior
# export PAYJOIN_FFI_FEATURES=""            # build without extra features
bash ./scripts/generate_bindings.sh
```

### PowerShell

```powershell
$env:PAYJOIN_FFI_FEATURES = "_test-utils,_manual-tls"   # default behavior
# $env:PAYJOIN_FFI_FEATURES = ""            # build without extra features
powershell -ExecutionPolicy Bypass -File .\scripts\generate_bindings.ps1
dotnet build
```

## NuGet Packaging (Draft)

`Payjoin.nuspec` is included for packaging the generated C# source plus native library artifacts.

Before packing, make sure generation has produced:

- `src/payjoin.cs`
- `lib/*` (native library for the current platform)

Note: this packs the native library currently present in `lib/`. For a cross-platform package, build and include native artifacts from each target platform in CI before publishing.

Example:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\generate_bindings.ps1
nuget pack .\Payjoin.nuspec -Version 0.24.0
```

If `nuget` is not installed, install NuGet.CommandLine first (for example via `dotnet tool` or your package manager).
