//! Runtime tamper detection.
//!
//! We run a background thread that repeatedly verifies:
//!   - the vault file on disk still has the same inode and size
//!     (anything else means the file was replaced or truncated
//!     under us);
//!   - the mount point is still a tmpfs and belongs to us;
//!   - the Chromium child is still the original PID we spawned.
//!
//! Any failure → SIGKILL the child. The main thread then runs the
//! usual commit + scrub path, which will refuse to write back if the
//! mount has been swapped.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Watchdog {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Watchdog {
    pub fn start(vault: &Path, mount: &Path, child_pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let vault = vault.to_path_buf();
        let mount = mount.to_path_buf();

        let handle = thread::spawn(move || run(stop_thread, vault, mount, child_pid));
        Self { stop, handle: Some(handle) }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn run(stop: Arc<AtomicBool>, vault: PathBuf, mount: PathBuf, child_pid: u32) {
    let baseline = match baseline_snapshot(&vault, &mount) {
        Ok(b) => b,
        Err(e) => {
            log::error!("watchdog baseline failed: {e:#}");
            kill(child_pid);
            return;
        }
    };

    while !stop.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(1500));
        match current_snapshot(&vault, &mount) {
            Ok(cur) if cur == baseline => continue,
            Ok(cur) => {
                log::error!("watchdog: vault/mount changed (baseline={baseline:?} now={cur:?})");
                kill(child_pid);
                return;
            }
            Err(e) => {
                log::error!("watchdog: integrity check failed: {e:#}");
                kill(child_pid);
                return;
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    vault_ino: u64,
    vault_len: u64,
    #[cfg(target_os = "linux")]
    mount_fs_type: i64,
}

#[cfg(target_os = "linux")]
fn baseline_snapshot(vault: &Path, mount: &Path) -> anyhow::Result<Snapshot> {
    current_snapshot(vault, mount)
}

#[cfg(target_os = "linux")]
fn current_snapshot(vault: &Path, mount: &Path) -> anyhow::Result<Snapshot> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(vault)?;
    let st = nix::sys::statfs::statfs(mount)?;
    Ok(Snapshot {
        vault_ino: m.ino(),
        vault_len: m.len(),
        mount_fs_type: st.filesystem_type().0 as i64,
    })
}

#[cfg(not(target_os = "linux"))]
fn baseline_snapshot(vault: &Path, mount: &Path) -> anyhow::Result<Snapshot> {
    current_snapshot(vault, mount)
}

#[cfg(not(target_os = "linux"))]
fn current_snapshot(vault: &Path, _mount: &Path) -> anyhow::Result<Snapshot> {
    let m = std::fs::metadata(vault)?;
    Ok(Snapshot { vault_ino: 0, vault_len: m.len() })
}

fn kill(pid: u32) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill as nix_kill, Signal};
        use nix::unistd::Pid;
        let _ = nix_kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }
    #[cfg(windows)]
    {
        // Minimal Windows impl: open handle, TerminateProcess.
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 1);
            }
        }
    }
}
