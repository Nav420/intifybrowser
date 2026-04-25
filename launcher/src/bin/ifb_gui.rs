//! Intifybrowser GUI launcher.
//!
//! A graphical front-end that replaces the CLI entirely for non-technical
//! users.  All vault and browser operations run on background threads so
//! the UI stays responsive during the 1-3 second Argon2id KDF.
//!
//! Vault body format (GUI-specific):
//!   [u64 LE: tar archive length][tar bytes][zero padding to region size]
//!
//! A fresh vault (created via this GUI) has tar_len == 0.  On open the
//! tar is extracted to a temp directory; Chrome runs against that dir;
//! on exit the directory is re-archived and encrypted back.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use eframe::egui;
use intifybrowser_launcher::{chromium as chrom_ops, container, crypto, mount, scrub};

// ---------------------------------------------------------------------------
// Worker ↔ UI message types
// ---------------------------------------------------------------------------

enum WorkerMsg {
    Progress(String),
    /// Vault created successfully.
    VaultCreated,
    /// Browser launched; UI should switch to BrowserRunning state.
    BrowserLaunched { vault_label: String },
    /// Browser session finished (re-encrypt + scrub complete).
    SessionDone,
    /// Something went wrong.
    Error(String),
}

// ---------------------------------------------------------------------------
// UI state machine
// ---------------------------------------------------------------------------

#[derive(Default)]
enum UiState {
    #[default]
    Idle,
    Working,
    BrowserRunning { vault_label: String },
}

// ---------------------------------------------------------------------------
// App struct
// ---------------------------------------------------------------------------

struct IntifyApp {
    // Create-vault form
    create_path: String,
    create_pw: String,
    create_confirm: String,
    create_size_mb: u64, // 512, 1024, 2048, 4096

    // Open-vault form
    open_path: String,
    open_pw: String,

    state: UiState,
    status: String,
    worker_rx: Option<mpsc::Receiver<WorkerMsg>>,

    // Stored so background threads can request a repaint.
    ctx: egui::Context,
}

impl IntifyApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Larger, readable font
        let mut style = (*cc.egui_ctx.style()).clone();
        use egui::{FontId, TextStyle};
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(20.0)),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Monospace, FontId::monospace(13.0)),
        ]
        .into();
        cc.egui_ctx.set_style(style);

        Self {
            create_path: String::new(),
            create_pw: String::new(),
            create_confirm: String::new(),
            create_size_mb: 1024,
            open_path: String::new(),
            open_pw: String::new(),
            state: UiState::Idle,
            status: "Ready.".to_owned(),
            worker_rx: None,
            ctx: cc.egui_ctx.clone(),
        }
    }

    fn is_busy(&self) -> bool {
        matches!(self.state, UiState::Working | UiState::BrowserRunning { .. })
    }

    /// Poll the worker channel; return true if something changed.
    fn poll_worker(&mut self) -> bool {
        let rx = match &self.worker_rx {
            Some(r) => r,
            None => return false,
        };
        match rx.try_recv() {
            Ok(msg) => {
                match msg {
                    WorkerMsg::Progress(s) => {
                        self.status = s;
                    }
                    WorkerMsg::VaultCreated => {
                        self.state = UiState::Idle;
                        self.status = "Vault created successfully.".to_owned();
                        self.create_pw.clear();
                        self.create_confirm.clear();
                        self.worker_rx = None;
                    }
                    WorkerMsg::BrowserLaunched { vault_label } => {
                        self.state = UiState::BrowserRunning { vault_label };
                        self.status = "Browser is running — close it when done.".to_owned();
                    }
                    WorkerMsg::SessionDone => {
                        self.state = UiState::Idle;
                        self.status = "Vault re-encrypted and session closed.".to_owned();
                        self.open_pw.clear();
                        self.worker_rx = None;
                    }
                    WorkerMsg::Error(e) => {
                        self.state = UiState::Idle;
                        self.status = format!("Error: {e}");
                        self.worker_rx = None;
                    }
                }
                true
            }
            Err(mpsc::TryRecvError::Empty) => false,
            Err(mpsc::TryRecvError::Disconnected) => {
                if matches!(self.state, UiState::Working) {
                    self.state = UiState::Idle;
                    self.status = "Worker thread exited unexpectedly.".to_owned();
                }
                self.worker_rx = None;
                true
            }
        }
    }

    fn spawn_create_vault(&mut self) {
        let path = PathBuf::from(&self.create_path);
        let pw = self.create_pw.clone();
        let size_bytes = self.create_size_mb * 1024 * 1024;

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.state = UiState::Working;
        self.status = "Deriving key (this takes a few seconds)…".to_owned();

        let ctx = self.ctx.clone();
        thread::spawn(move || {
            let result = create_vault_worker(&tx, &path, size_bytes, &pw);
            let msg = match result {
                Ok(()) => WorkerMsg::VaultCreated,
                Err(e) => WorkerMsg::Error(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }

    fn spawn_open_vault(&mut self) {
        let path = PathBuf::from(&self.open_path);
        let pw = self.open_pw.clone();

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.state = UiState::Working;
        self.status = "Unlocking vault (this takes a few seconds)…".to_owned();

        let ctx = self.ctx.clone();
        thread::spawn(move || {
            if let Err(e) = open_vault_worker(&tx, &ctx, &path, &pw) {
                let _ = tx.send(WorkerMsg::Error(format!("{e:#}")));
                ctx.request_repaint();
            }
        });
    }
}

// ---------------------------------------------------------------------------
// eframe::App implementation
// ---------------------------------------------------------------------------

impl eframe::App for IntifyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Intercept window-close while Chrome is running or an op is in flight.
        if ctx.input(|i| i.viewport().close_requested()) && self.is_busy() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.status =
                "Please close the browser first — your data will be re-encrypted automatically."
                    .to_owned();
        }

        // Poll background thread
        if self.poll_worker() {
            ctx.request_repaint();
        }
        // Keep repainting at ~10 fps while working so the spinner animates
        if self.is_busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.heading("Intifybrowser");
            ui.label("Encrypted browser launcher");
            ui.separator();
            ui.add_space(4.0);

            match &self.state {
                UiState::Idle => {
                    self.draw_create_panel(ui);
                    ui.add_space(8.0);
                    self.draw_open_panel(ui);
                }
                UiState::Working => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(32.0);
                        ui.spinner();
                        ui.add_space(8.0);
                        ui.label(&self.status.clone());
                    });
                }
                UiState::BrowserRunning { vault_label } => {
                    let label = vault_label.clone();
                    ui.vertical_centered(|ui| {
                        ui.add_space(24.0);
                        ui.heading("Browser is Running");
                        ui.add_space(8.0);
                        ui.label(format!("Vault: {label}"));
                        ui.add_space(12.0);
                        ui.label("Your profile is decrypted into a temp directory.");
                        ui.label("Close Chrome/Edge when done — your data will be");
                        ui.label("automatically re-encrypted into the vault.");
                        ui.add_space(16.0);
                        ui.colored_label(
                            egui::Color32::from_rgb(200, 120, 0),
                            "⚠  Do not close this window while the browser is open.",
                        );
                    });
                }
            }

            ui.add_space(8.0);
            ui.separator();
            let status = self.status.clone();
            ui.label(egui::RichText::new(status).small());
        });
    }
}

impl IntifyApp {
    fn draw_create_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("Create New Vault").strong());
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Vault file:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.create_path)
                        .hint_text("C:\\path\\to\\vault.ifb")
                        .desired_width(260.0),
                );
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Vault files", &["ifb"])
                        .set_file_name("myvault.ifb")
                        .save_file()
                    {
                        self.create_path = p.to_string_lossy().into_owned();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Password:  ");
                ui.add(
                    egui::TextEdit::singleline(&mut self.create_pw)
                        .password(true)
                        .desired_width(220.0),
                );
            });

            ui.horizontal(|ui| {
                ui.label("Confirm:   ");
                ui.add(
                    egui::TextEdit::singleline(&mut self.create_confirm)
                        .password(true)
                        .desired_width(220.0),
                );
            });

            ui.horizontal(|ui| {
                ui.label("Vault size:");
                egui::ComboBox::from_id_source("create_size")
                    .selected_text(size_label(self.create_size_mb))
                    .show_ui(ui, |ui| {
                        for &mb in &[512u64, 1024, 2048, 4096] {
                            ui.selectable_value(
                                &mut self.create_size_mb,
                                mb,
                                size_label(mb),
                            );
                        }
                    });
            });

            ui.add_space(4.0);
            let can_create = !self.create_path.is_empty()
                && !self.create_pw.is_empty()
                && self.create_pw == self.create_confirm;

            ui.add_enabled_ui(can_create, |ui| {
                if ui.button("  Create Vault  ").clicked() {
                    self.spawn_create_vault();
                }
            });

            if !self.create_pw.is_empty()
                && !self.create_confirm.is_empty()
                && self.create_pw != self.create_confirm
            {
                ui.colored_label(egui::Color32::RED, "Passwords do not match.");
            }
        });
    }

    fn draw_open_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("Open Existing Vault").strong());
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Vault file:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.open_path)
                        .hint_text("C:\\path\\to\\vault.ifb")
                        .desired_width(260.0),
                );
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Vault files", &["ifb"])
                        .pick_file()
                    {
                        self.open_path = p.to_string_lossy().into_owned();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Password:  ");
                ui.add(
                    egui::TextEdit::singleline(&mut self.open_pw)
                        .password(true)
                        .desired_width(220.0),
                );
            });

            ui.add_space(4.0);
            let can_open = !self.open_path.is_empty() && !self.open_pw.is_empty();

            ui.add_enabled_ui(can_open, |ui| {
                if ui.button("  Open Vault  ").clicked() {
                    self.spawn_open_vault();
                }
            });
        });
    }
}

// ---------------------------------------------------------------------------
// Worker functions (run on background threads)
// ---------------------------------------------------------------------------

fn create_vault_worker(
    tx: &mpsc::Sender<WorkerMsg>,
    path: &Path,
    size_bytes: u64,
    password: &str,
) -> Result<()> {
    let _ = tx.send(WorkerMsg::Progress("Deriving key (Argon2id 256 MiB)…".to_owned()));
    container::init_with_passwords(path, size_bytes, password, None, None)
        .context("vault creation failed")
}

fn open_vault_worker(
    tx: &mpsc::Sender<WorkerMsg>,
    ctx: &egui::Context,
    vault_path: &Path,
    password: &str,
) -> Result<()> {
    // 1. Unlock
    let _ = tx.send(WorkerMsg::Progress("Unlocking vault (Argon2id 256 MiB)…".to_owned()));
    ctx.request_repaint();

    let secret = crypto::UserSecret::from_password_and_keyfile(password, None)?;
    let mut vault = container::Vault::open(vault_path).context("open vault")?;
    let session = vault.unlock(&secret).context("unlock vault")?;

    // 2. Create temp mount
    let _ = tx.send(WorkerMsg::Progress("Decrypting vault…".to_owned()));
    ctx.request_repaint();

    let mnt = mount::RamMount::create(session.plaintext_size()).context("create temp dir")?;
    let temp_root = mnt.path().to_path_buf();

    // 3. Decrypt to image.bin
    vault.decrypt_into(&session, &temp_root).context("decrypt vault")?;

    // 4. Extract tar profile from image.bin
    let _ = tx.send(WorkerMsg::Progress("Preparing browser profile…".to_owned()));
    ctx.request_repaint();

    let image_bin = temp_root.join("image.bin");
    let profile_dir = temp_root.join("profile");
    unpack_profile(&image_bin, &profile_dir).context("unpack profile")?;

    // 5. Find browser
    #[cfg(windows)]
    let browser = chrom_ops::find_system_browser()
        .context("no Chrome or Edge found — please install Google Chrome or Microsoft Edge")?;

    #[cfg(not(windows))]
    let browser = {
        // On Linux/macOS fall back to the vault-embedded binary path.
        // This is the CLI flow; GUI on non-Windows is not the primary target.
        PathBuf::from("chromium")
    };

    // 6. Launch browser
    let _ = tx.send(WorkerMsg::Progress("Launching browser…".to_owned()));
    ctx.request_repaint();

    #[cfg(windows)]
    let mut child = chrom_ops::spawn_system_browser(&browser, &profile_dir, &[])
        .context("spawn browser")?;

    #[cfg(not(windows))]
    let mut child = chrom_ops::spawn(&browser, &profile_dir, &[]).context("spawn browser")?;

    let vault_label = vault_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| vault_path.to_string_lossy().into_owned());

    let _ = tx.send(WorkerMsg::BrowserLaunched { vault_label });
    ctx.request_repaint();

    // 7. Wait for browser to exit
    let _status = child.wait().context("wait for browser")?;

    // 8. Re-pack profile
    let _ = tx.send(WorkerMsg::Progress("Re-encrypting vault…".to_owned()));
    ctx.request_repaint();

    pack_profile(&profile_dir, &image_bin, session.plaintext_size())
        .context("pack profile")?;

    // 9. Re-encrypt
    vault.commit_from(&session, &temp_root).context("commit vault")?;

    // 10. Scrub temp dir and unmount
    let _ = tx.send(WorkerMsg::Progress("Scrubbing temp data…".to_owned()));
    ctx.request_repaint();

    scrub::wipe(&temp_root).context("scrub temp dir")?;
    mnt.unmount().context("unmount")?;

    let _ = tx.send(WorkerMsg::SessionDone);
    ctx.request_repaint();
    Ok(())
}

// ---------------------------------------------------------------------------
// Profile pack / unpack (tar with 8-byte length prefix)
// ---------------------------------------------------------------------------

/// Extract the Chrome profile from the GUI vault body format.
///
/// Format: `[u64 LE tar_len][tar bytes][padding]`
///
/// A tar_len of 0 means the vault is freshly created; Chrome will
/// build a new profile from scratch.
fn unpack_profile(image_bin: &Path, dest: &Path) -> Result<()> {
    use std::io::Read;

    std::fs::create_dir_all(dest)?;

    let mut f = std::fs::File::open(image_bin).context("open image.bin")?;
    let mut len_buf = [0u8; 8];
    f.read_exact(&mut len_buf).context("read tar length")?;
    let tar_len = u64::from_le_bytes(len_buf);

    if tar_len == 0 {
        // Fresh vault — Chrome will create the profile on first launch.
        return Ok(());
    }

    let reader = f.take(tar_len);
    let mut archive = tar::Archive::new(reader);
    archive.unpack(dest).context("unpack tar")?;
    Ok(())
}

/// Pack the Chrome profile directory back into `image_bin` using the GUI
/// vault body format, zero-padding to exactly `pad_to` bytes.
fn pack_profile(src: &Path, image_bin: &Path, pad_to: u64) -> Result<()> {
    use std::io::Write;

    // Stream tar to a temp file to measure its size before writing the prefix.
    let tar_tmp = image_bin.with_extension("tar.tmp");
    {
        let out = std::fs::File::create(&tar_tmp).context("create tar tmp")?;
        let mut builder = tar::Builder::new(out);
        builder.append_dir_all(".", src).context("tar profile dir")?;
        builder.finish().context("finish tar")?;
    }
    let tar_size = std::fs::metadata(&tar_tmp)?.len();

    let total_needed = 8u64.saturating_add(tar_size);
    if total_needed > pad_to {
        std::fs::remove_file(&tar_tmp).ok();
        anyhow::bail!(
            "Profile too large for vault ({} MiB used, {} MiB available). \
             Create a larger vault.",
            tar_size / (1 << 20),
            pad_to.saturating_sub(8) / (1 << 20)
        );
    }

    let mut out = std::fs::File::create(image_bin).context("create image.bin")?;
    out.write_all(&tar_size.to_le_bytes())?;

    let mut tar_f = std::fs::File::open(&tar_tmp)?;
    std::io::copy(&mut tar_f, &mut out)?;
    drop(tar_f);
    std::fs::remove_file(&tar_tmp).ok();

    // Zero-pad to the required plaintext region size.
    let pad_len = (pad_to - total_needed) as usize;
    if pad_len > 0 {
        let buf = vec![0u8; 1 << 20]; // 1 MiB at a time
        let mut remaining = pad_len;
        while remaining > 0 {
            let n = remaining.min(buf.len());
            out.write_all(&buf[..n])?;
            remaining -= n;
        }
    }

    out.sync_all()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn size_label(mb: u64) -> String {
    if mb >= 1024 { format!("{} GB", mb / 1024) } else { format!("{mb} MB") }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    // Best-effort memory hardening (VirtualLock on Windows).
    if let Err(e) = intifybrowser_launcher::memlock::harden_process() {
        eprintln!("warning: process hardening: {e:#}");
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([540.0, 520.0])
            .with_title("Intifybrowser"),
        ..Default::default()
    };

    if let Err(e) = eframe::run_native(
        "Intifybrowser",
        options,
        Box::new(|cc| Ok(Box::new(IntifyApp::new(cc)))),
    ) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
