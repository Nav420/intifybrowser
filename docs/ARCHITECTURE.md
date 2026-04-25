# Architecture

## 1. Trust boundaries

```
┌────────────────────── untrusted ──────────────────────┐
│  host disk  │  host pagefile/swap  │  host processes  │
└────────────────────────────────────────────────────────┘
                     ▲            ▲
                     │ ciphertext │ never (mlock + swapoff hint)
                     │            │
┌────────────────── trusted (in-process) ───────────────┐
│ launcher RAM: keys, Argon2 state, plaintext header    │
│ mount RAM:    plaintext profile + extracted Chromium  │
└───────────────────────────────────────────────────────┘
```

The only artefact written to host-visible storage is the ciphertext
vault file. Everything else lives in either launcher heap (locked with
`mlock`/`VirtualLock`) or a RAM-backed filesystem mounted with `noexec`
off and `nosuid`/`nodev` on.

## 2. Container (vault) file layout

All multi-byte integers little-endian. Sizes in bytes.

```
offset  size                 field
──────  ───────────────────  ─────────────────────────────────────────────
0       8                    magic  = "IFBVAULT"
8       2                    version = 1
10      2                    flags  (bit0 = has_hidden_volume)
12      16                   salt_outer   (Argon2id salt, outer password)
28      16                   salt_hidden  (Argon2id salt, hidden password)
44      12                   nonce_outer_hdr (AES-GCM)
56      12                   nonce_hidden_hdr
68      32                   enc_master_key_outer   (16 cipher + 16 tag)
                              ─ actually 48 bytes: 32-byte key + 16-byte tag
68      48                   enc_master_key_outer
116     48                   enc_master_key_hidden
164     32                   header_mac (BLAKE3 keyed, key=master_outer)
196     ...                  padding to 64 KiB (random bytes — indistinguishable
                              from hidden-volume metadata)
65536   OUTER_SIZE           outer ciphertext region
                             (AES-256-GCM over chunks of 64 KiB,
                              per-chunk nonce = nonce_base || chunk_index)
OUTER_SIZE+65536             hidden ciphertext region (optional).
                             Random-looking if absent. Starts at a fixed
                             offset computed from vault_size so the hidden
                             region's existence cannot be proven by header
                             inspection alone.
```

### Plausible deniability

- Both `enc_master_key_outer` and `enc_master_key_hidden` are always
  present. If there is no hidden volume, `enc_master_key_hidden` holds
  random bytes and `salt_hidden` is random; an adversary cannot
  distinguish an empty slot from a real one without the hidden password.
- The outer region is always filled with ciphertext to its nominal
  length, even if the user stored less data: unused outer chunks are
  encrypted random padding. This hides the boundary between outer data
  and the hidden region.
- Argon2id is run for both password slots on every unlock so timing does
  not reveal which slot matched.

## 3. Sequence — unlock, run, scrub

```
 user          launcher                 kernel / fs             chromium
  │                │                         │                       │
  │── run ────────▶│                         │                       │
  │                │ prompt pw + keyfile     │                       │
  │◀─ ask ─────────│                         │                       │
  │── secret ─────▶│                         │                       │
  │                │ mlock heap              │                       │
  │                │ Argon2id(pw, salt_o)    │                       │
  │                │ Argon2id(pw, salt_h)    │                       │
  │                │ try decrypt outer slot  │                       │
  │                │ try decrypt hidden slot │                       │
  │                │ pick whichever authenticates                     │
  │                │                         │                       │
  │                │ mount tmpfs size=N ────▶│                       │
  │                │   (noexec=false,        │                       │
  │                │    nosuid, nodev)       │                       │
  │                │ stream-decrypt vault ──▶│  /mnt/ifb-XXXX        │
  │                │                         │                       │
  │                │ fork + exec ──────────────────────────────────▶ │
  │                │   chromium                                      │
  │                │   --user-data-dir=/mnt/ifb-XXXX                 │
  │                │   --no-default-browser-check …                  │
  │                │                                                 │
  │                │ watchdog: stat(mount),  │                       │
  │                │   inotify on /mnt,      │                       │
  │                │   readlink /proc/<pid>/root                     │
  │                │                                                 │
  │                │  ◀─────── exit(code) ───────────────────────────│
  │                │                         │                       │
  │                │ re-encrypt + flush to vault.ifb                  │
  │                │ overwrite tmpfs with random x3                  │
  │                │ unmount tmpfs ─────────▶│                       │
  │                │ memzero + munlock heap  │                       │
  │                │ exit 0                  │                       │
```

## 4. Watchdog / tamper detection

While Chromium runs the launcher supervises in a separate thread:

1. `statfs(mount_dir)` — on Linux verifies the fs is still `TMPFS_MAGIC`.
2. `readlink("/proc/<chromium-pid>/root")` — must stay `/`.
3. `inotify` on the vault file — any external `open(O_WRONLY|O_TRUNC)`,
   `unlink`, or `rename` triggers shutdown.
4. Heartbeat pipe — the launcher writes a nonce over an anonymous pipe
   inherited by the child. The child's preloaded shim reads+echoes it
   every 2s. Missed heartbeats also trigger shutdown.

Any failure → SIGKILL Chromium → scrub path (section 3).

## 5. Memory hygiene

- `mlock`/`VirtualLock` over every heap region that ever holds a key,
  KDF output, or plaintext header.
- `mlockall(MCL_CURRENT|MCL_FUTURE)` on Linux when run with
  `CAP_IPC_LOCK` or as root; otherwise fall back to per-region locks.
- `madvise(MADV_DONTDUMP)` + `prctl(PR_SET_DUMPABLE, 0)` disables core
  dumps so a crash cannot spill keys to disk.
- Secret buffers are `Zeroizing<[u8; N]>` and overwritten on drop.
- On Windows: `SetProcessWorkingSetSize` is bumped before `VirtualLock`
  to avoid the undocumented "working set too small" failure mode.

## 6. Chromium isolation

Chromium is built with `is_official_build=true`,
`enable_reporting=false`, `google_api_key=""`, and the full flag set in
`chromium/args.gn`. At runtime the launcher adds:

```
--user-data-dir=<tmpfs>           pin all state into RAM
--disk-cache-dir=<tmpfs>/cache    same
--no-first-run
--no-default-browser-check
--disable-background-networking
--disable-sync
--disable-component-update
--disable-breakpad
--disable-features=MediaRouter,OptimizationHints,InterestFeedV2
--proxy-server=<optional tor/proxy>
--dns-over-https-server=<doh>
```

See `chromium/args.gn` for the build-time flags.
