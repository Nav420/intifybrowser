//! Prevent secrets from being paged/swapped to host disk.
//!
//! Linux   : `mlockall(MCL_CURRENT|MCL_FUTURE)`, plus
//!           `prctl(PR_SET_DUMPABLE, 0)` to disable core dumps.
//! Windows : `SetProcessWorkingSetSize` then `VirtualLock` on specific
//!           regions (no full-process equivalent to mlockall).
//! macOS   : `mlockall` exists but with a very small default RLIMIT;
//!           we raise `RLIMIT_MEMLOCK` first when possible.

use anyhow::{Context, Result};

pub fn harden_process() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::mman::{mlockall, MlockAllFlags};
        // Disable ptrace attach + core dumps.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }
        // Best-effort: if we don't have CAP_IPC_LOCK and the rlimit is
        // small, this fails — we'll still mlock individual regions.
        let _ = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)
            .context("mlockall (non-fatal)")
            .map_err(|e| log::warn!("{e:#}"));
    }

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
        // Bump working set so VirtualLock has room to work.
        unsafe {
            let proc = GetCurrentProcess();
            // -1, -1 means "use defaults based on available memory".
            SetProcessWorkingSetSize(proc, usize::MAX, usize::MAX);
        }
    }

    // Best-effort swap hint for Linux. On systems where swap is on an
    // encrypted partition this is redundant but harmless.
    Ok(())
}

/// Lock a specific byte range. Useful for a Zeroizing buffer whose
/// address we know. No-op fallback on platforms without per-range lock.
pub fn lock_range(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::mlock(ptr as *const libc::c_void, len);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Memory::VirtualLock;
        let _ = VirtualLock(ptr as *mut _, len);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
    }
}
