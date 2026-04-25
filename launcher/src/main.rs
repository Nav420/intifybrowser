//! Intifybrowser launcher binary.
//!
//! Flow: parse args → prompt for password/keyfile → derive keys →
//! decrypt vault header → stream-decrypt vault body into a RAM-backed
//! mount → spawn Chromium against the mount → supervise → on exit,
//! re-encrypt → scrub → unmount → zeroise keys.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod chromium;
mod container;
mod crypto;
mod memlock;
mod mount;
mod scrub;
mod watchdog;

#[derive(Parser)]
#[command(name = "ifb", about = "Intifybrowser encrypted Chromium launcher")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new encrypted vault.
    Init {
        #[arg(long)]
        vault: PathBuf,
        /// Nominal size of the outer volume, e.g. 2GiB.
        #[arg(long, default_value = "2GiB")]
        size: String,
        /// Optional keyfile mixed into the KDF.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Pre-populate the vault from a directory (e.g. a Chromium bundle).
        #[arg(long)]
        seed: Option<PathBuf>,
        /// Also provision a hidden-volume slot.
        #[arg(long)]
        with_hidden: bool,
    },
    /// Unlock, mount, launch Chromium, scrub on exit.
    Run {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Path to the Chromium binary inside the mount. Relative to mount root.
        #[arg(long, default_value = "chromium/chrome")]
        chromium: String,
        /// Extra args forwarded to Chromium.
        #[arg(last = true)]
        chromium_args: Vec<String>,
    },
    /// Change a password or add a hidden volume to an existing vault.
    Rekey {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        add_hidden: bool,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Lock process memory before we ever touch a secret.
    memlock::harden_process().context("process memory hardening")?;

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { vault, size, keyfile, seed, with_hidden } => {
            let size = parse_size(&size)?;
            container::init(&vault, size, keyfile.as_deref(), seed.as_deref(), with_hidden)
        }
        Cmd::Run { vault, keyfile, chromium, chromium_args } => {
            run_session(&vault, keyfile.as_deref(), &chromium, &chromium_args)
        }
        Cmd::Rekey { vault, add_hidden } => container::rekey(&vault, add_hidden),
    }
}

fn run_session(
    vault_path: &std::path::Path,
    keyfile: Option<&std::path::Path>,
    chromium_rel: &str,
    extra_args: &[String],
) -> Result<()> {
    // 1. Prompt. Both Argon2id slots are always evaluated so the user's
    //    intent (outer vs. hidden) is not leaked by timing.
    let pw = rpassword::prompt_password("Vault password: ")?;
    let secret = crypto::UserSecret::from_password_and_keyfile(&pw, keyfile)?;
    drop(pw); // Zeroize handled via the String → Vec conversion inside.

    // 2. Unlock — tries outer and hidden slots in constant time.
    let mut vault = container::Vault::open(vault_path)?;
    let session = vault.unlock(&secret)?;
    log::info!("vault unlocked (slot = {:?})", session.slot);

    // 3. Mount RAM-backed filesystem and stream-decrypt into it.
    let mount = mount::RamMount::create(session.plaintext_size())?;
    log::info!("mounted tmpfs at {}", mount.path().display());
    vault.decrypt_into(&session, mount.path())?;

    // 4. Launch Chromium with the mount as --user-data-dir.
    let chromium_bin = mount.path().join(chromium_rel);
    let mut child = chromium::spawn(&chromium_bin, mount.path(), extra_args)?;

    // 5. Supervise. Any tamper or integrity failure → kill child.
    let wd = watchdog::Watchdog::start(vault_path, mount.path(), child.id());

    // 6. Wait for Chromium to exit, normally or forced.
    let status = child.wait()?;
    wd.stop();
    log::info!("chromium exited: {}", status);

    // 7. Re-encrypt any writes back into the vault file, then scrub.
    vault.commit_from(&session, mount.path())?;

    // 8. Scrub tmpfs contents, unmount, zero keys.
    scrub::wipe(mount.path())?;
    mount.unmount()?;
    drop(session); // Zeroize master keys.

    Ok(())
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mul) = if let Some(stripped) = s.strip_suffix("GiB") {
        (stripped, 1u64 << 30)
    } else if let Some(stripped) = s.strip_suffix("MiB") {
        (stripped, 1u64 << 20)
    } else if let Some(stripped) = s.strip_suffix("KiB") {
        (stripped, 1u64 << 10)
    } else {
        (s, 1)
    };
    Ok(num.trim().parse::<u64>()? * mul)
}
