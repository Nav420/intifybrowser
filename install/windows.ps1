# intifybrowser launcher — Windows installer.
#
# Builds the launcher from source with cargo and installs ifb.exe into
# %ProgramFiles%\intifybrowser (machine-wide) or %LOCALAPPDATA%\Programs\
# intifybrowser (per-user fallback when not elevated). Also adds the
# install dir to PATH.
#
# Usage (elevated PowerShell for machine-wide install):
#   .\install\windows.ps1
#
# Usage (per-user, no admin):
#   .\install\windows.ps1 -PerUser
#
# NOTE: The Windows RAM-disk backend in mount.rs is currently stubbed.
#       The binary installs and runs, but `ifb run` will fail with
#       "RAM mount backend not implemented for this platform" until
#       an ImDisk / in-process RAM disk backend lands. You can still use
#       the `ifb init` and crypto subcommands to explore the vault format.

[CmdletBinding()]
param(
    [switch]$PerUser
)

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[ifb-install] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[ifb-install] $msg" -ForegroundColor Yellow }
function Fail($msg)       { Write-Host "[ifb-install] $msg" -ForegroundColor Red; exit 1 }

# --- dependencies -----------------------------------------------------------

foreach ($tool in @('cargo', 'rustc')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Fail "Missing dependency: $tool. Install Rust from https://rustup.rs/"
    }
}

# --- locate repo ------------------------------------------------------------

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Resolve-Path (Join-Path $ScriptDir '..')
$LauncherDir = Join-Path $RepoRoot 'launcher'

if (-not (Test-Path (Join-Path $LauncherDir 'Cargo.toml'))) {
    Fail "Cannot locate launcher/Cargo.toml (looked in $LauncherDir)"
}

# --- build ------------------------------------------------------------------

Write-Info "Building launcher (release)"
Push-Location $LauncherDir
try {
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { Fail "cargo build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$BinSrc = Join-Path $LauncherDir 'target\release\ifb.exe'
if (-not (Test-Path $BinSrc)) { Fail "Build did not produce $BinSrc" }

# --- install location -------------------------------------------------------

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($PerUser -or -not (Test-Admin)) {
    if (-not $PerUser) {
        Write-Warn "Not elevated; falling back to per-user install."
    }
    $InstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\intifybrowser'
    $PathScope   = 'User'
} else {
    $InstallRoot = Join-Path $env:ProgramFiles 'intifybrowser'
    $PathScope   = 'Machine'
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
$BinDst = Join-Path $InstallRoot 'ifb.exe'

Write-Info "Installing to $BinDst"
Copy-Item -Force $BinSrc $BinDst

# --- PATH -------------------------------------------------------------------

$currentPath = [Environment]::GetEnvironmentVariable('Path', $PathScope)
if ($currentPath -notlike "*$InstallRoot*") {
    $newPath = if ([string]::IsNullOrEmpty($currentPath)) { $InstallRoot }
               else { "$currentPath;$InstallRoot" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, $PathScope)
    Write-Info "Added $InstallRoot to $PathScope PATH (open a new shell for it to take effect)"
} else {
    Write-Info "$InstallRoot already on PATH ($PathScope)"
}

# --- post-install notes -----------------------------------------------------

Write-Info "Done."
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  ifb init --vault C:\Users\$env:USERNAME\my.ifb --size 2GiB --with-hidden"
Write-Host "  ifb run  --vault C:\Users\$env:USERNAME\my.ifb"
Write-Host ""
Write-Warn "The Windows RAM-disk backend is stubbed (see mount.rs)."
Write-Warn "  `ifb run` will bail until an ImDisk or in-process backend is added."
Write-Host ""
Write-Host "Uninstall: Remove-Item -Recurse -Force `"$InstallRoot`""
