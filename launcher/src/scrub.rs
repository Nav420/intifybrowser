//! Best-effort wipe of RAM-backed mount contents before unmount.
//!
//! On tmpfs this is mostly belt-and-suspenders: the kernel zeroes the
//! backing pages when the fs is destroyed, but an attacker with a
//! kernel-side read primitive (cold-boot, Spectre-class) may race us.
//! Overwriting every file in place before unmount shrinks that window.

use anyhow::Result;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto;

const BLOCK: usize = 1 << 20; // 1 MiB

pub fn wipe(root: &Path) -> Result<()> {
    for entry in walk(root)? {
        let meta = match std::fs::metadata(&entry) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        overwrite_file(&entry, meta.len())?;
        // Truncate + delete.
        let _ = std::fs::remove_file(&entry);
    }
    Ok(())
}

fn overwrite_file(path: &Path, len: u64) -> Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    let mut buf = vec![0u8; BLOCK];
    // One random pass is enough on flash/RAM — multi-pass only helps
    // against mechanical-disk remanence which does not apply to tmpfs.
    f.seek(SeekFrom::Start(0))?;
    let mut remaining = len;
    while remaining > 0 {
        let n = std::cmp::min(remaining as usize, BLOCK);
        crypto::random_bytes(&mut buf[..n]);
        f.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    f.sync_all()?;
    // Zero pass, to make "is this file all random?" harder to answer.
    f.seek(SeekFrom::Start(0))?;
    buf.iter_mut().for_each(|b| *b = 0);
    let mut remaining = len;
    while remaining > 0 {
        let n = std::cmp::min(remaining as usize, BLOCK);
        f.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    f.sync_all()?;
    Ok(())
}

fn walk(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let p = e.path();
            let md = match e.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    Ok(files)
}
