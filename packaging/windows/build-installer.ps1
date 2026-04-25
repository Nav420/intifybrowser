<#
.SYNOPSIS
    Build the Intifybrowser Windows installer (MSI).

.DESCRIPTION
    Compiles both the CLI (ifb.exe) and GUI (ifb-gui.exe) binaries in release
    mode, then packages them into a single MSI via cargo-wix / WiX Toolset 3.

.PARAMETER Clean
    Remove all build artifacts before building.

.EXAMPLE
    .\build-installer.ps1
    .\build-installer.ps1 -Clean
#>
param([switch]$Clean)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$LauncherDir = "$PSScriptRoot\..\..\launcher"

# ── Prerequisites ──────────────────────────────────────────────────────────

function Require($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Required tool not found: $cmd`n$hint"
        exit 1
    }
}

Require cargo  "Install Rust from https://rustup.rs"
Require candle "Install WiX Toolset 3 from https://wixtoolset.org/releases/"

if (-not (Get-Command cargo-wix -ErrorAction SilentlyContinue)) {
    Write-Host "Installing cargo-wix…"
    cargo install cargo-wix
}

# ── Clean ──────────────────────────────────────────────────────────────────

if ($Clean) {
    Write-Host "Cleaning…"
    Push-Location $LauncherDir
    cargo clean
    Pop-Location
}

# ── Build ──────────────────────────────────────────────────────────────────

Write-Host "Building CLI + GUI (release)…"
Push-Location $LauncherDir
cargo build --release --locked --features gui
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Pop-Location

# ── Package ────────────────────────────────────────────────────────────────

Write-Host "Packaging MSI…"
Push-Location $LauncherDir
cargo wix --profile release --no-build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Pop-Location

# ── Report ─────────────────────────────────────────────────────────────────

$msi = Get-ChildItem "$LauncherDir\target\wix\*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($msi) {
    $sizeMB = [math]::Round($msi.Length / 1MB, 1)
    Write-Host ""
    Write-Host "Installer ready: $($msi.FullName) ($sizeMB MB)" -ForegroundColor Green
} else {
    Write-Warning "MSI not found — check WiX output above."
}
