param(
    # Force production bindings (no extra cargo features). Windows cannot represent an empty
    # environment variable distinctly from an unset one, so callers signal production through
    # this switch rather than by setting PAYJOIN_FFI_FEATURES to "".
    [switch] $ProductionBindings,

    # Build the native library without regenerating the C# bindings, for callers (the per-RID
    # packaging jobs) that consume only the native asset.
    [switch] $NativeOnly
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Tool,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Args
    )

    & $Tool @Args
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Tool $($Args -join ' ')"
    }
}

$osDescription = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
Write-Host "Running on $osDescription"

$isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
$isMacPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)
$isLinuxPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)

if ($isWindowsPlatform) {
    $libName = "payjoin_ffi.dll"
} elseif ($isMacPlatform) {
    $libName = "libpayjoin_ffi.dylib"
} elseif ($isLinuxPlatform) {
    $libName = "libpayjoin_ffi.so"
} else {
    throw "Unsupported OS: $osDescription"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$payjoinFfiDir = Resolve-Path (Join-Path $scriptDir "..\..")
Set-Location $payjoinFfiDir

# Build against the maintained lockfile instead of resolving the dependency
# graph fresh on every run; mirrors contrib/lockfile.sh for this Windows entry
# point. The previous lockfile state is restored before the script exits.
$repoRoot = Resolve-Path (Join-Path $payjoinFfiDir "..")
$lockFile = Join-Path $repoRoot "Cargo.lock"
$lockBackup = $null
if (Test-Path $lockFile) {
    $lockBackup = "$lockFile.bak"
    Move-Item $lockFile $lockBackup -Force
}
Copy-Item (Join-Path $repoRoot "Cargo-recent.lock") $lockFile -Force

try {

Write-Host "Generating payjoin C#..."
if ($ProductionBindings) {
    $payjoinFfiFeatures = ""
} elseif ($null -ne $env:PAYJOIN_FFI_FEATURES) {
    $payjoinFfiFeatures = $env:PAYJOIN_FFI_FEATURES
} else {
    # Keep parity with other language test scripts: include _test-utils by default.
    $payjoinFfiFeatures = "_test-utils"
}

if ($payjoinFfiFeatures) {
    $generatorFeatures = "csharp,$payjoinFfiFeatures"
} else {
    $generatorFeatures = "csharp"
}

if ($env:PAYJOIN_FFI_PROFILE) {
    $payjoinFfiProfile = $env:PAYJOIN_FFI_PROFILE
} else {
    $payjoinFfiProfile = "dev"
}

if ($payjoinFfiProfile -eq "dev") {
    $targetProfileDir = "debug"
} else {
    $targetProfileDir = $payjoinFfiProfile
}

Invoke-Native cargo build --features $generatorFeatures --profile $payjoinFfiProfile -j2

if (-not $NativeOnly) {
    Write-Host "Cleaning csharp/src/ directory..."
    New-Item -ItemType Directory -Force -Path "csharp/src" | Out-Null
    Get-ChildItem "csharp/src" -Filter "*.cs" -ErrorAction SilentlyContinue | Remove-Item -Force

    $previousUniffiLanguage = $env:UNIFFI_BINDGEN_LANGUAGE
    $env:UNIFFI_BINDGEN_LANGUAGE = "csharp"
    try {
        Invoke-Native cargo run --features $generatorFeatures --profile dev --bin uniffi-bindgen '--' --library "../target/$targetProfileDir/$libName" --out-dir "csharp/src/"
    }
    finally {
        if ($null -eq $previousUniffiLanguage) {
            Remove-Item Env:UNIFFI_BINDGEN_LANGUAGE -ErrorAction SilentlyContinue
        } else {
            $env:UNIFFI_BINDGEN_LANGUAGE = $previousUniffiLanguage
        }
    }
}

Write-Host "Copying native library..."
New-Item -ItemType Directory -Force -Path "csharp/lib" | Out-Null
Copy-Item "../target/$targetProfileDir/$libName" "csharp/lib/$libName" -Force

}
finally {
    Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
    if ($null -ne $lockBackup) {
        Move-Item $lockBackup $lockFile -Force
    }
}

Write-Host "All done!"
