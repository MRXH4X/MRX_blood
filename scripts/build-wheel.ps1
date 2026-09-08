param(
    [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $true
}

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Tmp = Join-Path $Root ".tmp"
$PipCache = Join-Path $Root ".pip-cache"
$Python = Join-Path $Root ".venv\Scripts\python.exe"

New-Item -ItemType Directory -Force -Path $Tmp, $PipCache | Out-Null

$env:TEMP = $Tmp
$env:TMP = $Tmp
$env:PIP_CACHE_DIR = $PipCache

if (-not (Test-Path $Python)) {
    throw "Missing virtual environment Python: $Python. Create it first with: python -m venv .venv"
}

if ($InstallDeps) {
    & $Python -m pip install build "setuptools>=68" wheel
}

$Check = @"
import importlib.util
import sys
missing = [m for m in ("build", "setuptools", "wheel") if importlib.util.find_spec(m) is None]
if missing:
    print("Missing build dependencies in .venv: " + ", ".join(missing))
    print("Run: .\\scripts\\build-wheel.ps1 -InstallDeps")
    sys.exit(1)
"@

& $Python -c $Check
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $Python -m build --wheel --no-isolation
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$Wheel = Get-ChildItem -Path (Join-Path $Root "dist") -Filter "blood_bober-*.whl" |
    Sort-Object @{ Expression = {
        [version](($_.BaseName -replace '^blood_bober-', '' -replace '-py3-none-any$', ''))
    } } -Descending |
    Select-Object -First 1
if (Test-Path $Wheel) {
    icacls $Wheel /grant "${env:USERNAME}:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$BuildDir = Join-Path $Root "build"
if (Test-Path $BuildDir) {
    Remove-Item -LiteralPath $BuildDir -Recurse -Force
}

Write-Host "Wheel build complete:"
Write-Host "  $Wheel"
