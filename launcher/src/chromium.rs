//! Spawn and configure the hardened Chromium child.

use anyhow::{Context, Result};
use std::path::Path;
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
