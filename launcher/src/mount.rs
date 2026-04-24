//! RAM-backed mount management.
//!
//! Linux   : tmpfs mounted at /run/ifb-<rand> with `size=<N>,nosuid,nodev`.
//!           Chromium requires execute permission on its binaries, so we
//!           deliberately do NOT set `noexec` (tmpfs defaults to exec).
//! macOS   : `hdiutil attach -nomount ram://<sectors>` + HFS+ newfs.
//! Windows : ImDisk driver or (preferred) an in-proc RAM disk; stubbed.
//!
//! The mount must NEVER end up in a directory that sits on an encrypted
//! home partition that is itself backed by swap-capable storage. We
//! always pick `/run` (tmpfs) or `/dev/shm` on Linux.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct RamMount {
    path: PathBuf,
    mounted: bool,
}

impl RamMount {
    #[cfg(target_os = "linux")]
    pub fn create(size_bytes: u64) -> Result<Self> {
        use nix::mount::{mount, MsFlags};
        use rand::RngCore;

        let mut rnd = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut rnd);
        let name = format!("ifb-{}", hex_short(&rnd));
        let path = Path::new("/run").join(&name);
        std::fs::create_dir_all(&path).context("mkdir mount point")?;
        // Chmod 700: only this user can traverse.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }

        let opts = format!("size={},mode=0700,nosuid,nodev", size_bytes);
        mount(
            Some("tmpfs"),
            &path,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(opts.as_str()),
        )
        .context("mount tmpfs")?;

        Ok(Self { path, mounted: true })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(_size_bytes: u64) -> Result<Self> {
        anyhow::bail!("RAM mount backend not implemented for this platform in skeleton")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(target_os = "linux")]
    pub fn unmount(mut self) -> Result<()> {
        use nix::mount::{umount2, MntFlags};
        if self.mounted {
            umount2(&self.path, MntFlags::MNT_DETACH).context("umount tmpfs")?;
            self.mounted = false;
        }
        let _ = std::fs::remove_dir(&self.path);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn unmount(self) -> Result<()> {
        Ok(())
    }
}

impl Drop for RamMount {
    fn drop(&mut self) {
        if self.mounted {
            #[cfg(target_os = "linux")]
            {
                use nix::mount::{umount2, MntFlags};
                let _ = umount2(&self.path, MntFlags::MNT_DETACH);
            }
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

fn hex_short(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
