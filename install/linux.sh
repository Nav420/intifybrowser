#!/usr/bin/env bash
#
# intifybrowser launcher — Linux installer.
#
# Builds the launcher from source with cargo and installs the `ifb` binary
# into /usr/local/bin. Optionally grants CAP_IPC_LOCK so mlockall succeeds
# without root, and tightens ptrace_scope per docs/SECURITY.md §2.4.
#
# Usage:  ./install/linux.sh
#         PREFIX=/opt/intifybrowser ./install/linux.sh
#         NO_CAPS=1 ./install/linux.sh           # skip setcap step
#         NO_SYSCTL=1 ./install/linux.sh         # skip ptrace_scope tweak
#
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAUNCHER_DIR="${REPO_ROOT}/launcher"

log() { printf '\033[1;34m[ifb-install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ifb-install]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[ifb-install]\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

need cargo
need rustc
need install

log "building launcher (release)"
( cd "${LAUNCHER_DIR}" && cargo build --release --locked )

BIN_SRC="${LAUNCHER_DIR}/target/release/ifb"
[[ -x "${BIN_SRC}" ]] || die "build did not produce ${BIN_SRC}"

log "installing to ${BIN_DIR}/ifb (requires sudo)"
sudo install -D -m 0755 "${BIN_SRC}" "${BIN_DIR}/ifb"

if [[ -z "${NO_CAPS:-}" ]] && command -v setcap >/dev/null 2>&1; then
    log "granting CAP_IPC_LOCK (mlockall without root)"
    sudo setcap cap_ipc_lock=+ep "${BIN_DIR}/ifb"
else
    warn "skipping setcap — mlockall will be best-effort only"
fi

if [[ -z "${NO_SYSCTL:-}" ]]; then
    current_scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo -1)"
    if [[ "${current_scope}" != "2" && "${current_scope}" != "3" ]]; then
        warn "ptrace_scope is ${current_scope}; see docs/SECURITY.md §2.4"
        warn "consider: echo 'kernel.yama.ptrace_scope = 2' | sudo tee /etc/sysctl.d/60-intifybrowser.conf"
    fi
fi

log "installed: $(${BIN_DIR}/ifb --help 2>&1 | head -1 || echo 'ifb')"
log "done"
cat <<EOF

Next steps:
  1. Create a vault:   ifb init --vault ~/my.ifb --size 2GiB --with-hidden
  2. Place a Chromium bundle inside the vault (see docs/ARCHITECTURE.md).
  3. Run:              ifb run --vault ~/my.ifb -- --proxy-server=socks5://127.0.0.1:9050

Uninstall: sudo rm ${BIN_DIR}/ifb
EOF
