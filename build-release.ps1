#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Cross-compile pqgpg for GitHub Releases.
  Each zip contains the binary + README + LICENSE + SHA256SUMS (for that zip only).
#>

param(
    [string]$Version = "0.3.0",
    [string]$OutDir  = "dist",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$Targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe"; Name = "windows-amd64" },
    @{ GOOS = "windows"; GOARCH = "arm64"; Ext = ".exe"; Name = "windows-arm64" },
    @{ GOOS = "linux";   GOARCH = "amd64"; Ext = "";     Name = "linux-amd64" },
    @{ GOOS = "linux";   GOARCH = "arm64"; Ext = "";     Name = "linux-arm64" },
    @{ GOOS = "linux";   GOARCH = "386";   Ext = "";     Name = "linux-386" },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Ext = "";     Name = "darwin-amd64" },
    @{ GOOS = "darwin";  GOARCH = "arm64"; Ext = "";     Name = "darwin-arm64" },
    @{ GOOS = "freebsd"; GOARCH = "amd64"; Ext = "";     Name = "freebsd-amd64" }
)

$Root = $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }
Set-Location $Root

Write-Host "=== pqgpg release build ===" -ForegroundColor Cyan
Write-Host "Version : v$Version"
Write-Host "OutDir  : $OutDir"
Write-Host ""

try { Write-Host "Go      : $(go version)" } catch {
    Write-Error "Go is not installed or not on PATH."
}

if ($Clean -and (Test-Path $OutDir)) {
    Write-Host "Cleaning $OutDir ..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "Running go mod tidy ..." -ForegroundColor Cyan
& go mod tidy
if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }

$env:CGO_ENABLED = "0"
$Zips = @()

foreach ($t in $Targets) {
    $label   = $t.Name
    $binName = "pqgpg" + $t.Ext
    $zipName = "pqgpg-v$Version-$label.zip"
    $zipPath = Join-Path $OutDir $zipName

    Write-Host "Building $label ..." -NoNewline

    $env:GOOS   = $t.GOOS
    $env:GOARCH = $t.GOARCH

    $stage = Join-Path $OutDir ("_stage_" + $label)
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null

    $binPath = Join-Path $stage $binName
    $ldflags = "-s -w -X github.com/pqgpg/pqgpg/internal/cli.Version=$Version"
    & go build -trimpath -ldflags $ldflags -o $binPath ./cmd/pqgpg
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
        continue
    }

    if (Test-Path (Join-Path $Root "README.md")) {
        Copy-Item (Join-Path $Root "README.md") (Join-Path $stage "README.md")
    }
    if (Test-Path (Join-Path $Root "LICENSE")) {
        Copy-Item (Join-Path $Root "LICENSE") (Join-Path $stage "LICENSE")
    }

    # Per-zip checksum (binary only — standard release style)
    $hash = (Get-FileHash -Algorithm SHA256 -Path $binPath).Hash.ToLower()
    $sumsFile = Join-Path $stage "SHA256SUMS"
    Set-Content -Path $sumsFile -Value "$hash  $binName" -Encoding ascii

    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -Force
    Remove-Item -Recurse -Force $stage

    $sizeKB = [math]::Round((Get-Item $zipPath).Length / 1KB, 1)
    Write-Host " OK -> $zipName ($sizeKB KB)" -ForegroundColor Green
    $Zips += $zipPath
}

Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Build complete ===" -ForegroundColor Green
Write-Host "Artifacts in: $((Resolve-Path $OutDir).Path)"
Get-ChildItem $OutDir -Filter "*.zip" | Sort-Object Name | Format-Table Name, @{N="KB";E={[math]::Round($_.Length/1KB,1)}} -AutoSize

Write-Host "Each zip contains: pqgpg(+.exe), README.md, LICENSE, SHA256SUMS"
Write-Host ""
Write-Host "GitHub:"
Write-Host "  git tag v$Version && git push origin v$Version"
Write-Host "  gh release create v$Version dist/*.zip --title `"pqgpg v$Version`" --generate-notes"