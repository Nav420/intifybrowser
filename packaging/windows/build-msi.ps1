# intifybrowser MSI builder.
#
# Produces a Windows .msi installer for the ifb launcher.
#
# Prerequisites (one-time):
#   1. Rust toolchain        — https://rustup.rs/
#   2. WiX Toolset 3.x       — https://wixtoolset.org/releases/
#                              add the WiX bin dir to PATH (candle.exe, light.exe).
#   3. cargo-wix             — `cargo install cargo-wix`
#
# Usage:
#   .\packaging\windows\build-msi.ps1
#
# Output:
#   launcher\target\wix\intifybrowser-<version>-x86_64.msi
#
# The MSI:
#   - installs ifb.exe to %ProgramFiles%\intifybrowser\
#   - appends the install dir to the system PATH
#   - registers in Add/Remove Programs (uninstall via Settings → Apps)

[CmdletBinding()]
param(
    [switch]$Clean,
    [string]$Profile = 'release'
)

$ErrorActionPreference = 'Stop'

function Info($m) { Write-Host "[ifb-msi] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[ifb-msi] $m" -ForegroundColor Red; exit 1 }

# --- locate repo ------------------------------------------------------------

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Resolve-Path (Join-Path $ScriptDir '..\..')
$LauncherDir = Join-Path $RepoRoot 'launcher'

if (-not (Test-Path (Join-Path $LauncherDir 'Cargo.toml'))) {
    Fail "Cannot locate launcher/Cargo.toml at $LauncherDir"
}

# --- dependency checks ------------------------------------------------------

foreach ($t in @('cargo', 'rustc')) {
    if (-not (Get-Command $t -ErrorAction SilentlyContinue)) {
        Fail "Missing $t. Install Rust: https://rustup.rs/"
    }
}

if (-not (Get-Command 'cargo-wix' -ErrorAction SilentlyContinue) -and
    -not (cargo --list 2>$null | Select-String -Quiet '^\s+wix\s')) {
    Info "cargo-wix not found, installing"
    cargo install cargo-wix
    if ($LASTEXITCODE -ne 0) { Fail "cargo install cargo-wix failed" }
}

if (-not (Get-Command 'candle.exe' -ErrorAction SilentlyContinue)) {
    Fail "WiX Toolset (candle.exe) not on PATH. Install from https://wixtoolset.org/releases/"
}

# --- optional clean ---------------------------------------------------------

Push-Location $LauncherDir
try {
    if ($Clean) {
        Info "cargo clean"
        cargo clean
    }

    # --- build the MSI ------------------------------------------------------
    # cargo-wix runs `cargo build --release` itself (no-build = false), then
    # candle + light using packaging/windows/main.wxs.

    Info "cargo wix (profile = $Profile)"
    cargo wix --nocapture --profile $Profile
    if ($LASTEXITCODE -ne 0) { Fail "cargo wix failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

# --- locate output ----------------------------------------------------------

$Msi = Get-ChildItem -Path (Join-Path $LauncherDir 'target\wix') -Filter '*.msi' `
       | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($null -eq $Msi) { Fail "No .msi produced under target/wix/" }

Info "MSI ready: $($Msi.FullName)"
Info "Size: $([math]::Round($Msi.Length / 1KB, 1)) KiB"
Info ""
Info "To verify the installer:"
Info "  msiexec /i `"$($Msi.FullName)`" /l*v install.log"
