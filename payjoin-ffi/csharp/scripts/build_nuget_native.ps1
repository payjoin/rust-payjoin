$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Get-PayjoinArchitecture {
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($architecture) {
        "X64" { "x64"; break }
        "Arm64" { "arm64"; break }
        default { throw "Unsupported architecture: $architecture" }
    }
}

function Get-PayjoinRid {
    $arch = Get-PayjoinArchitecture
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        return "win-$arch"
    }
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)) {
        return "osx-$arch"
    }
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)) {
        return "linux-$arch"
    }

    throw "Unsupported OS: $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"
}

function Get-NativeLibraryName {
    param([Parameter(Mandatory = $true)][string] $Rid)

    if ($Rid.StartsWith("win-")) {
        return "payjoin_ffi.dll"
    }
    if ($Rid.StartsWith("osx-")) {
        return "libpayjoin_ffi.dylib"
    }
    if ($Rid.StartsWith("linux-")) {
        return "libpayjoin_ffi.so"
    }

    throw "Unsupported RID: $Rid"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$csharpDir = Resolve-Path (Join-Path $scriptDir "..")
Set-Location $csharpDir

if ($env:PAYJOIN_FFI_RID) {
    $rid = $env:PAYJOIN_FFI_RID
} else {
    $rid = Get-PayjoinRid
}

$libName = Get-NativeLibraryName -Rid $rid

# On Windows, assigning "" to an environment variable removes it, so we cannot mark production
# bindings by clearing PAYJOIN_FFI_FEATURES the way the bash script does. When the caller has not
# requested specific features, ask generate_bindings.ps1 for production bindings explicitly; an
# explicitly-set PAYJOIN_FFI_FEATURES is still forwarded through the environment.
$useProductionBindings = $null -eq $env:PAYJOIN_FFI_FEATURES
if (-not $env:PAYJOIN_FFI_PROFILE) {
    $env:PAYJOIN_FFI_PROFILE = "release"
}

if ($useProductionBindings) {
    & (Join-Path $csharpDir "scripts/generate_bindings.ps1") -ProductionBindings -NativeOnly
} else {
    & (Join-Path $csharpDir "scripts/generate_bindings.ps1") -NativeOnly
}
if ($LASTEXITCODE -ne 0) {
    throw "generate_bindings.ps1 failed with exit code $LASTEXITCODE"
}

$artifactDir = Join-Path $csharpDir "artifacts/runtimes/$rid/native"
Remove-Item $artifactDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
Copy-Item (Join-Path $csharpDir "lib/$libName") (Join-Path $artifactDir $libName) -Force

Write-Host "Wrote $artifactDir/$libName"
