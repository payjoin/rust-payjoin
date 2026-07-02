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

Write-Host "Generating payjoin C#..."
if ($null -ne $env:PAYJOIN_FFI_FEATURES) {
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

Write-Host "Copying native library..."
New-Item -ItemType Directory -Force -Path "csharp/lib" | Out-Null
Copy-Item "../target/$targetProfileDir/$libName" "csharp/lib/$libName" -Force

Write-Host "All done!"
