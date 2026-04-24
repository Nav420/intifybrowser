# Security risk assessment

This is a *threat-model and risk register* — not a checklist of things
that are "done". Each entry lists an attacker capability, the leak
path, and the mitigation (design, build-time, runtime). Severity is
the residual risk *after* mitigation: H = exploitable in practice,
M = requires a capable local attacker or OS flaw, L = requires a
kernel compromise or physical access at the right moment.

## 1. Data at rest

| # | Threat | Path | Mitigation | Residual |
|---|---|---|---|---|
| 1.1 | Offline brute-force of vault password | Copy `vault.ifb`, run Argon2id on GPUs | Argon2id 256 MiB / 4-iter / 4-lane default; configurable up; keyfile mixed into KDF; no password-hash shortcut stored | **M** (user-chosen password strength dominates) |
| 1.2 | Header forgery / downgrade | Rewrite header to point at attacker-chosen KDF params | Header is AEAD-authenticated; version field is signed into AAD; launcher refuses unknown versions | **L** |
| 1.3 | Hidden volume existence disclosed by header entropy analysis | Compare a "no-hidden" vault to a "with-hidden" vault | Both slots always populated (real ciphertext or random-key ciphertext); both KDFs always run; padding to 64 KiB is random | **M** (statistical attacks on tiny samples may still work; recommend filling outer volume with decoy data) |
| 1.4 | Partial-write corruption on commit | Power loss mid-write leaves vault half-encrypted | Per-chunk AEAD means corruption is detected, not silently accepted; commit writes to a temp copy + rename on full-disk mode is a planned v2 change | **M** |
| 1.5 | Evil-maid replacement of the vault file | Attacker swaps the file while user is away; next unlock runs attacker's payload | Vault body is authenticated — a swapped file will fail AEAD open on unlock (the launcher exits). Attacker cannot forge a vault that opens with the victim's password. Does *not* defend against a tampered launcher binary — ship the launcher on read-only media or verify with an external signature | **M** (depends on launcher integrity) |

## 2. Data in memory

| # | Threat | Path | Mitigation | Residual |
|---|---|---|---|---|
| 2.1 | OS swaps secret pages to pagefile/swap | Plaintext profile or master key hits disk | `mlockall(MCL_CURRENT|MCL_FUTURE)` on Linux; `VirtualLock` per-region on Windows; secrets wrapped in `Zeroizing` | **M** (requires elevated privileges; best-effort without CAP_IPC_LOCK) |
| 2.2 | Core dump on crash | SEGV writes heap contents to `/var/crash` | `prctl(PR_SET_DUMPABLE, 0)`; `--disable-breakpad --disable-crash-reporter` passed to Chromium | **L** |
| 2.3 | Cold-boot attack on RAM | Physical attacker freezes RAM after power-off | Scrub pass before unmount reduces window; kernel zeroes tmpfs pages on unmount; not defeated for a well-equipped physical attacker | **H** (inherent to RAM-disk designs) |
| 2.4 | Another process reads `/proc/<pid>/mem` | Local user with `ptrace` capability dumps launcher memory | `PR_SET_DUMPABLE=0` also blocks ptrace for non-root; recommend `kernel.yama.ptrace_scope=2` | **M** |
| 2.5 | Memory not cleared on panic | `panic = "abort"` leaves heap live | `panic = "abort"` is deliberate: no unwinding means no partial-scrub window; the kernel reclaims pages on exit; `mlock` prevents them being swapped in the interim | **L** |

## 3. Chromium runtime leakage

| # | Threat | Path | Mitigation | Residual |
|---|---|---|---|---|
| 3.1 | Chromium writes state outside `--user-data-dir` | e.g. `~/.config/chromium` on some builds, DBus secrets service, NSS profile | Launcher sets `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `TMPDIR` to the mount; `--disk-cache-dir` forced; fires warning on any access outside; audit with `strace -f -e openat` during CI | **M** |
| 3.2 | DNS leak to system resolver | Chromium uses `getaddrinfo()` which hits `/etc/resolv.conf` | Force `--dns-over-https-server=...` or run behind a mandatory SOCKS/HTTP proxy supplied at launch; block outbound DNS via nftables/Windows Firewall rule installed by launcher (optional) | **H** if user doesn't configure DoH/proxy |
| 3.3 | WebRTC leaks LAN IPs via STUN/ICE | `RTCPeerConnection` reveals private addresses | `rtc_use_h264=false` at build; runtime `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`; recommend pairing with Tor/proxy | **M** |
| 3.4 | Component updater phones home | `chrome://components` self-updates | `--disable-component-update`; `enable_reporting=false`; pinned binary under `chromium/args.gn` | **L** |
| 3.5 | Sync / signed-in Google account | User logs into a Google account, sync uploads profile | `--disable-sync`; `enable_supervised_users=false`; launcher could further patch `sync_service_factory.cc` to hard-disable | **L** |
| 3.6 | Field-trial / variations server pings | Chromium fetches variations config | `disable_fieldtrial_testing_config=true`; runtime `--disable-field-trial-config --variations-server-url=` | **L** |
| 3.7 | Time-zone / locale fingerprint | Reveals host TZ when vault was built elsewhere | Set `TZ=UTC` and `LC_ALL=C.UTF-8` in launcher env; recommend user override | **M** |
| 3.8 | GPU/driver fingerprint via WebGL/WebGPU | Unique driver string | Consider `--use-angle=swiftshader` for a SW renderer at some performance cost | **M** |

## 4. Mount / filesystem

| # | Threat | Path | Mitigation | Residual |
|---|---|---|---|---|
| 4.1 | tmpfs contents swapped to disk | If host swap is enabled and the tmpfs is pressured | Linux tmpfs can be swapped — mitigate with `sysctl vm.swappiness=0` or encrypted swap; document this requirement | **M** |
| 4.2 | Another local user enumerates `/run/ifb-*` | Dir exists with a predictable prefix | 8-byte random suffix; directory mode 0700; inside a tmpfs only accessible by the calling user | **L** |
| 4.3 | Attacker bind-mounts over our mount dir | Races us between `mount()` and first write | Launcher stats the dir before and after mount, asserts it's `TMPFS_MAGIC`; watchdog re-checks every 1.5s | **M** |
| 4.4 | Attacker replaces Chromium binary inside tmpfs mid-run | Write to `/run/ifb-*/chromium/chrome` | tmpfs is owned by the launcher user; other local users cannot write; watchdog also reopens the binary path and compares inode | **L** |

## 5. Process & IPC

| # | Threat | Path | Mitigation | Residual |
|---|---|---|---|---|
| 5.1 | Chromium child survives launcher death | Orphaned, leaves mount live | Linux: `prctl(PR_SET_PDEATHSIG, SIGKILL)` set in child (add to `chromium::spawn`); Windows: job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | **M** — to be added; tracked as a follow-up |
| 5.2 | Shell history leaks vault path | User ran `ifb run --vault ~/secret.ifb` | Not our problem by default; document usage of `HISTCONTROL=ignorespace` or a GUI front-end | **M** |
| 5.3 | TTY prompt captured by a keylogger | Password read by `rpassword` | Out of scope — a compromised host defeats any userland tool | **H** if host is compromised |

## 6. Build & supply chain

| # | Threat | Path | Mitigation | Residual |
|---|---|---|---|---|
| 6.1 | Compromised crate dependency | Cargo pulls a malicious `argon2` | Pin exact versions with `Cargo.lock`; `cargo vet` / `cargo deny` in CI | **M** |
| 6.2 | Chromium source tampering | depot_tools fetches a poisoned tag | Pin Chromium to a specific release tag + verify `DEPS` sha-sums; reproducible builds via `is_official_build=true` + `strip_absolute_paths_from_debug_symbols=true` | **M** |
| 6.3 | Launcher binary tampering | Host swaps `ifb` binary | Ship signed binaries; have user verify signature out-of-band; consider distributing the launcher + vault bundled in a single ISO/USB-image | **M** |

## 7. Plausible deniability failure modes

| # | Threat | Path | Mitigation | Residual |
|---|---|---|---|---|
| 7.1 | Filesystem traces reveal hidden volume | OS records `last-accessed` on outer files the user never touched but which the launcher mapped | Outer volume should be realistically populated (decoy browser profile seeded at init) | **M** (operational, not technical) |
| 7.2 | User writes to outer volume after using hidden volume, corrupting hidden region | Classic VeraCrypt mistake | `container::Vault::unlock()` chooses hidden if both passwords match; outer writes from that session only ever target outer region; when a user unlocks outer, any writes are refused from overlapping hidden region by offset check | **L** (design) |
| 7.3 | Memory / disk artefacts correlate to "hidden mode" | Different code paths → different allocations | Both unlock paths run identical KDFs and identical allocation sizes; region offset is the only difference | **L** |

## 8. Things explicitly out of scope

- A root-level or kernel-level compromise of the host. None of this
  defends against an attacker who owns ring 0. Use measured boot,
  full-disk encryption, and a trusted OS (e.g. Qubes / Tails) if that
  is in your threat model.
- Side-channel attacks on AES-NI / Argon2id lanes. We rely on the
  upstream crates' constant-time guarantees.
- Network-level traffic analysis. Pair with Tor if anonymity matters.

## 9. Follow-ups before calling this production-ready

1. Add `PR_SET_PDEATHSIG` / Job Object in `chromium::spawn` (risk 5.1).
2. Add an nftables/Windows-Firewall helper that blocks all non-proxy
   traffic while Chromium is running (risk 3.2).
3. Ship reproducible Chromium builds + signed launcher (risk 6.3).
4. Replace the "decrypt to one big `image.bin`" skeleton path with a
   per-file AEAD layer so granular file writes don't require
   re-encrypting the entire region on commit.
5. Fuzz the header parser (risk 1.2 depends on it).
