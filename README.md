# Intifybrowser

A portable, self-encrypting Chromium browser. The entire browser environment
(binary, profile, cache, cookies, extensions, history) lives inside a single
AES-256-GCM encrypted vault file. A small Rust launcher unlocks the vault
into a RAM-backed mount at start, runs Chromium against it, and cryptographically
scrubs the mount when the browser exits.

The design is inspired by VeraCrypt (volume + hidden volume) and Tails
(RAM-only runtime). The browser itself is a stripped, privacy-hardened build
of Chromium; all hardening flags live in `chromium/args.gn`.

## Components

| Path | Purpose |
|------|---------|
| `launcher/` | Rust wrapper: KDF, unlock, mount, child supervision, scrub |
| `chromium/args.gn` | GN build flags for a telemetry-free, portable Chromium |
| `install/linux.sh` | Linux installer (builds via cargo, `setcap cap_ipc_lock`) |
| `install/windows.ps1` | Windows installer (builds via cargo, adds to PATH) |
| `docs/ARCHITECTURE.md` | System flow map, container layout, trust boundaries |
| `docs/SECURITY.md` | Threat model + leak-point risk assessment |

## Install

Both installers build from source with `cargo build --release`. You need a
Rust toolchain (https://rustup.rs/) on both platforms.

**Linux**

```sh
./install/linux.sh
# or install somewhere other than /usr/local:
PREFIX=$HOME/.local ./install/linux.sh
```

**Windows** (elevated PowerShell for machine-wide install, or `-PerUser`):

```powershell
.\install\windows.ps1
.\install\windows.ps1 -PerUser   # no admin; installs to %LOCALAPPDATA%
```

The Windows RAM-disk backend in `mount.rs` is currently stubbed — the binary
installs cleanly but `ifb run` will bail until an ImDisk / in-proc backend
lands. macOS is not yet packaged.

## High-level flow

```
         ┌────────────────────────────────────────────────────────┐
         │                    HOST OPERATING SYSTEM                │
         │                                                        │
         │   ┌──────────────┐      ┌────────────────────────┐     │
user ──▶ │   │   launcher   │─────▶│  password / keyfile UI │     │
         │   │  (Rust bin)  │      └────────────────────────┘     │
         │   │              │                                     │
         │   │  1. Argon2id │◀── reads vault header ──┐           │
         │   │  2. AES-GCM  │                         │           │
         │   │  3. mount RAM│                         ▼           │
         │   │  4. fork()   │                ┌──────────────────┐ │
         │   │  5. watchdog │                │  vault.ifb (disk)│ │
         │   │  6. scrub    │                │  header ∥ outer  │ │
         │   └──────┬───────┘                │  ciphertext ∥    │ │
         │          │                        │  hidden region   │ │
         │          │ spawn                  └──────────────────┘ │
         │          ▼                                             │
         │   ┌──────────────┐     --user-data-dir=/mnt/ifb-XXXX   │
         │   │   Chromium   │◀──── reads/writes ────┐             │
         │   │  (hardened)  │                       ▼             │
         │   └──────────────┘           ┌────────────────────┐    │
         │                              │  tmpfs / ramfs     │    │
         │                              │  (mlock'd, noexec  │    │
         │                              │   on host pagefile)│    │
         │                              └────────────────────┘    │
         └────────────────────────────────────────────────────────┘
```

See `docs/ARCHITECTURE.md` for the full sequence diagram and container layout.

## Status

Skeleton / design reference. The crypto and mount modules compile and unit-test
cleanly on Linux; the Windows/macOS mount backends are stubbed with the same
trait so the rest of the code is portable. The Chromium build flags are
self-contained and can be dropped into any `src/out/Release/args.gn`.

## License

TBD.
