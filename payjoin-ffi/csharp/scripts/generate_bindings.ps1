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
    # Include test utilities and manual TLS by default so local test services
    # can fetch OHTTP keys over HTTPS with their generated self-signed cert.
    $payjoinFfiFeatures = "_test-utils,_manual-tls"
}

if ($payjoinFfiFeatures) {
    $generatorFeatures = "csharp,$payjoinFfiFeatures"
} else {
    $generatorFeatures = "csharp"
}

Invoke-Native cargo build --features $generatorFeatures --profile dev -j2

Write-Host "Cleaning csharp/src/ directory..."
New-Item -ItemType Directory -Force -Path "csharp/src" | Out-Null
Get-ChildItem "csharp/src" -Filter "*.cs" -ErrorAction SilentlyContinue | Remove-Item -Force

$previousUniffiLanguage = $env:UNIFFI_BINDGEN_LANGUAGE
$env:UNIFFI_BINDGEN_LANGUAGE = "csharp"
try {
    Invoke-Native cargo run --features $generatorFeatures --profile dev --bin uniffi-bindgen '--' --library "../target/debug/$libName" --out-dir "csharp/src/"
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
Copy-Item "../target/debug/$libName" "csharp/lib/$libName" -Force

Write-Host "All done!"
