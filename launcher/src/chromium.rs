//! Spawn and configure the hardened Chromium child.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Launch Chromium with `--user-data-dir` pinned to the RAM mount and
/// with a privacy-leaning baseline set of flags. The build-time flags
/// in `chromium/args.gn` already strip telemetry; the runtime flags
/// here defend against anything that can still phone home at runtime
/// (component updater, sync, metrics, DNS, MediaRouter, etc).
pub fn spawn(binary: &Path, mount: &Path, extra: &[String]) -> Result<Child> {
    let user_data_dir = mount;
    let disk_cache_dir = mount.join("cache");
    std::fs::create_dir_all(&disk_cache_dir).ok();

    let mut cmd = Command::new(binary);
    cmd.arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg(format!("--disk-cache-dir={}", disk_cache_dir.display()))
        // First-run and default-browser dialogs can leak state.
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-breakpad")
        .arg("--disable-crash-reporter")
        // Disable every non-essential network call.
        .arg("--disable-background-networking")
        .arg("--disable-sync")
        .arg("--disable-component-update")
        .arg("--disable-domain-reliability")
        .arg("--disable-client-side-phishing-detection")
        .arg("--disable-default-apps")
        .arg("--disable-features=MediaRouter,OptimizationHints,OptimizationGuideModelDownloading,InterestFeedV2,Translate,AutofillServerCommunication,CalculateNativeWinOcclusion")
        // Stop DNS prefetching/speculative connections.
        .arg("--dns-prefetch-disable")
        // Pin the locale and disable spellcheck's phone-home.
        .arg("--disable-spell-checking")
        // Reduce attack surface exposed to renderers.
        .arg("--site-per-process")
        .arg("--enable-strict-mixed-content-checking")
        // Ensure Chromium doesn't write anything outside user-data-dir.
        .arg("--homedir=".to_string() + &mount.display().to_string())
        .env("HOME", mount)
        .env("XDG_CONFIG_HOME", mount)
        .env("XDG_CACHE_HOME", &disk_cache_dir)
        .env("TMPDIR", mount)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Forward user-supplied args last so they can override defaults
    // where necessary (e.g. --proxy-server="socks5://127.0.0.1:9050").
    for a in extra {
        cmd.arg(a);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("spawn chromium at {}", binary.display()))?;
    Ok(child)
}

/// Find an installed Chrome or Edge browser on Windows.
/// Checks standard install locations and LOCALAPPDATA.
#[cfg(windows)]
pub fn find_system_browser() -> Option<PathBuf> {
    // User-installed Chrome (most common)
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let p = PathBuf::from(&local).join(r"Google\Chrome\Application\chrome.exe");
        if p.exists() {
            return Some(p);
        }
    }

    let candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Spawn a system-installed Chrome/Edge with its profile pinned to
/// `profile_dir`.  Used by the GUI when the vault binary is not Chromium
/// itself but an external browser.
#[cfg(windows)]
pub fn spawn_system_browser(
    browser: &Path,
    profile_dir: &Path,
    extra: &[String],
) -> Result<Child> {
    let cache_dir = profile_dir.with_file_name("cache");
    std::fs::create_dir_all(&cache_dir).ok();

    let mut cmd = Command::new(browser);
    cmd.arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg(format!("--disk-cache-dir={}", cache_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-breakpad")
        .arg("--disable-crash-reporter")
        .arg("--disable-background-networking")
        .arg("--disable-sync")
        .arg("--disable-component-update")
        .arg("--disable-domain-reliability")
        .arg("--disable-features=MediaRouter,AutofillServerCommunication")
        .arg("--dns-prefetch-disable")
        .stdin(Stdio::null());

    for a in extra {
        cmd.arg(a);
    }

    cmd.spawn()
        .with_context(|| format!("spawn browser at {}", browser.display()))
}
