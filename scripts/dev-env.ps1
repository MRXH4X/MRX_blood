$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Tmp = Join-Path $Root ".tmp"
$PipCache = Join-Path $Root ".pip-cache"

New-Item -ItemType Directory -Force -Path $Tmp, $PipCache | Out-Null

$env:TEMP = $Tmp
$env:TMP = $Tmp
$env:PIP_CACHE_DIR = $PipCache

Write-Host "Project temp configured:"
Write-Host "  TEMP=$env:TEMP"
Write-Host "  TMP=$env:TMP"
Write-Host "  PIP_CACHE_DIR=$env:PIP_CACHE_DIR"
Write-Host ""
Write-Host "Tip: dot-source this script to keep the variables in your current shell:"
Write-Host "  . .\scripts\dev-env.ps1"
