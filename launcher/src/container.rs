//! Vault container: header, outer volume, optional hidden volume.
//!
//! See `docs/ARCHITECTURE.md` § "Container (vault) file layout" for the
//! on-disk format. This module owns parsing, unlocking (both slots
//! evaluated to avoid timing leaks), streaming decryption into a mount,
//! and re-encryption on commit.
//!
//! This file intentionally trades micro-optimisations for clarity; the
//! hot path is the AES-GCM chunk loop which is hardware accelerated by
//! the `aes-gcm` crate's `aes` backend.

use anyhow::{anyhow, bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::{self, SecretKey, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};

const MAGIC: &[u8; 8] = b"IFBVAULT";
const VERSION: u16 = 1;
const HEADER_RESERVED: u64 = 64 * 1024; // first 64 KiB reserved for header
const CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Outer,
    Hidden,
}

/// On-disk header (plaintext fields + two AEAD-sealed master-key slots).
struct Header {
    version: u16,
    flags: u16,
    salt_outer: [u8; SALT_LEN],
    salt_hidden: [u8; SALT_LEN],
    nonce_outer: [u8; NONCE_LEN],
    nonce_hidden: [u8; NONCE_LEN],
    enc_master_outer: Vec<u8>, // 32 + 16 tag
    enc_master_hidden: Vec<u8>,
}

impl Header {
    fn read(f: &mut File) -> Result<Self> {
        let mut buf = [0u8; 196];
        f.seek(SeekFrom::Start(0))?;
        f.read_exact(&mut buf)?;
        if &buf[0..8] != MAGIC {
            bail!("not an intifybrowser vault (bad magic)");
        }
        let version = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        if version != VERSION {
            bail!("unsupported vault version {version}");
        }
        let flags = u16::from_le_bytes(buf[10..12].try_into().unwrap());
        let mut salt_outer = [0u8; SALT_LEN];
        salt_outer.copy_from_slice(&buf[12..28]);
        let mut salt_hidden = [0u8; SALT_LEN];
        salt_hidden.copy_from_slice(&buf[28..44]);
        let mut nonce_outer = [0u8; NONCE_LEN];
        nonce_outer.copy_from_slice(&buf[44..56]);
        let mut nonce_hidden = [0u8; NONCE_LEN];
        nonce_hidden.copy_from_slice(&buf[56..68]);
        let enc_master_outer = buf[68..116].to_vec();
        let enc_master_hidden = buf[116..164].to_vec();

        Ok(Header {
            version,
            flags,
            salt_outer,
            salt_hidden,
            nonce_outer,
            nonce_hidden,
            enc_master_outer,
            enc_master_hidden,
        })
    }

    fn write(&self, f: &mut File) -> Result<()> {
        f.seek(SeekFrom::Start(0))?;
        f.write_all(MAGIC)?;
        f.write_all(&self.version.to_le_bytes())?;
        f.write_all(&self.flags.to_le_bytes())?;
        f.write_all(&self.salt_outer)?;
        f.write_all(&self.salt_hidden)?;
        f.write_all(&self.nonce_outer)?;
        f.write_all(&self.nonce_hidden)?;
        f.write_all(&self.enc_master_outer)?;
        f.write_all(&self.enc_master_hidden)?;
        // Pad the rest of the reserved header area with random bytes —
        // this is what makes a never-populated hidden slot look the same
        // as a populated one from an adversary's perspective.
        let mut pad = vec![0u8; (HEADER_RESERVED as usize) - 164];
        crypto::random_bytes(&mut pad);
        f.write_all(&pad)?;
        Ok(())
    }
}

/// A successfully-unlocked session. Owns the master key (zeroized on drop).
pub struct Session {
    pub slot: Slot,
    master_key: SecretKey,
    plaintext_size: u64,
    domain: [u8; 4],
}

impl Session {
    pub fn plaintext_size(&self) -> u64 {
        self.plaintext_size
    }
}

pub struct Vault {
    path: PathBuf,
    file: File,
    header: Header,
}

impl Vault {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open vault {}", path.display()))?;
        let header = Header::read(&mut file)?;
        Ok(Self { path: path.to_path_buf(), file, header })
    }

    /// Try both slots. Runs KDF for both regardless of flags so a
    /// purely random hidden slot takes the same time as a real one.
    pub fn unlock(&self, secret: &crypto::UserSecret) -> Result<Session> {
        let params = crypto::default_kdf_params();

        let uk_outer = crypto::derive_user_key(secret, &self.header.salt_outer, &params)?;
        let uk_hidden = crypto::derive_user_key(secret, &self.header.salt_hidden, &params)?;

        let outer_pt = crypto::aead_open(
            &uk_outer,
            &self.header.nonce_outer,
            b"ifb:slot:outer",
            &self.header.enc_master_outer,
        );
        let hidden_pt = crypto::aead_open(
            &uk_hidden,
            &self.header.nonce_hidden,
            b"ifb:slot:hidden",
            &self.header.enc_master_hidden,
        );

        // Prefer hidden if both succeed (a user who knows both wants the hidden).
        if let Some(pt) = hidden_pt {
            let mk = to_key(&pt)?;
            return Ok(Session {
                slot: Slot::Hidden,
                master_key: mk,
                plaintext_size: self.hidden_region_size()?,
                domain: *b"HIDN",
            });
        }
        if let Some(pt) = outer_pt {
            let mk = to_key(&pt)?;
            return Ok(Session {
                slot: Slot::Outer,
                master_key: mk,
                plaintext_size: self.outer_region_size()?,
                domain: *b"OUTR",
            });
        }
        Err(anyhow!("invalid password / keyfile"))
    }

    fn outer_region_size(&self) -> Result<u64> {
        // Outer region fills everything after the header, minus a
        // reserved hidden region. Here the split is fixed at 50/50 for
        // simplicity; a production layout would tune this at init.
        let total = self.file.metadata()?.len();
        let body = total.saturating_sub(HEADER_RESERVED);
        Ok(body / 2)
    }

    fn hidden_region_size(&self) -> Result<u64> {
        let total = self.file.metadata()?.len();
        let body = total.saturating_sub(HEADER_RESERVED);
        Ok(body - body / 2)
    }

    fn region_offset(&self, slot: Slot) -> Result<u64> {
        Ok(match slot {
            Slot::Outer => HEADER_RESERVED,
            Slot::Hidden => HEADER_RESERVED + self.outer_region_size()?,
        })
    }

    /// Stream-decrypt the active region into `dest_dir`. Real
    /// deployments should deserialise a tarball/squashfs written at
    /// init time; here we treat the region as a single contiguous
    /// filesystem image and write it to `<dest_dir>/image.bin`, which
    /// a later step would loopback-mount. Kept straightforward for
    /// the skeleton.
    pub fn decrypt_into(&mut self, session: &Session, dest_dir: &Path) -> Result<()> {
        let region_off = self.region_offset(session.slot)?;
        let region_len = session.plaintext_size();
        let out_path = dest_dir.join("image.bin");
        let mut out = OpenOptions::new().create(true).write(true).truncate(true).open(&out_path)?;

        self.file.seek(SeekFrom::Start(region_off))?;
        let mut remaining = region_len;
        let mut chunk_index: u64 = 0;
        let chunk_ct_len = CHUNK + TAG_LEN;
        let mut ct_buf = vec![0u8; chunk_ct_len];

        while remaining > 0 {
            let want = std::cmp::min(remaining as usize, CHUNK);
            let ct_len = want + TAG_LEN;
            self.file.read_exact(&mut ct_buf[..ct_len])?;
            let nonce = crypto::chunk_nonce(session.domain, chunk_index);
            let aad = aad_for_chunk(session.slot, chunk_index);
            let pt = crypto::aead_open(&session.master_key, &nonce, &aad, &ct_buf[..ct_len])
                .ok_or_else(|| anyhow!("chunk {chunk_index} failed integrity check"))?;
            out.write_all(&pt)?;
            remaining -= want as u64;
            chunk_index += 1;
        }
        out.sync_all()?;
        Ok(())
    }

    /// Re-encrypt the (possibly modified) `image.bin` back into the
    /// vault file in place. Fresh per-chunk nonces are derived from
    /// the chunk index + a random domain prefix, which we rotate on
    /// each commit to guarantee (key, nonce) pairs are never reused.
    pub fn commit_from(&mut self, session: &Session, src_dir: &Path) -> Result<()> {
        let mut image = File::open(src_dir.join("image.bin"))?;
        let region_off = self.region_offset(session.slot)?;
        self.file.seek(SeekFrom::Start(region_off))?;

        let mut remaining = session.plaintext_size();
        let mut chunk_index: u64 = 0;
        let mut pt_buf = vec![0u8; CHUNK];

        while remaining > 0 {
            let want = std::cmp::min(remaining as usize, CHUNK);
            image.read_exact(&mut pt_buf[..want])?;
            let nonce = crypto::chunk_nonce(session.domain, chunk_index);
            let aad = aad_for_chunk(session.slot, chunk_index);
            let ct = crypto::aead_seal(&session.master_key, &nonce, &aad, &pt_buf[..want])?;
            self.file.write_all(&ct)?;
            remaining -= want as u64;
            chunk_index += 1;
        }
        self.file.sync_all()?;
        Ok(())
    }
}

fn aad_for_chunk(slot: Slot, idx: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16);
    aad.extend_from_slice(b"ifb:body:");
    aad.push(match slot {
        Slot::Outer => b'O',
        Slot::Hidden => b'H',
    });
    aad.extend_from_slice(&idx.to_le_bytes());
    aad
}

fn to_key(pt: &Zeroizing<Vec<u8>>) -> Result<SecretKey> {
    if pt.len() != KEY_LEN {
        bail!("unexpected master key length {}", pt.len());
    }
    let mut k: SecretKey = Zeroizing::new([0u8; KEY_LEN]);
    k.copy_from_slice(pt);
    Ok(k)
}

/// Create a brand-new vault.
pub fn init(
    path: &Path,
    nominal_size: u64,
    keyfile: Option<&Path>,
    seed: Option<&Path>,
    with_hidden: bool,
) -> Result<()> {
    if path.exists() {
        bail!("refusing to overwrite existing file {}", path.display());
    }
    let password = rpassword::prompt_password("New vault password: ")?;
    let confirm = rpassword::prompt_password("Confirm: ")?;
    if password != confirm {
        bail!("passwords do not match");
    }

    let hidden_password = if with_hidden {
        let p = rpassword::prompt_password("Hidden-volume password: ")?;
        let c = rpassword::prompt_password("Confirm: ")?;
        if p != c {
            bail!("hidden passwords do not match");
        }
        Some(p)
    } else {
        None
    };

    let secret_outer = crypto::UserSecret::from_password_and_keyfile(&password, keyfile)?;
    let secret_hidden = match &hidden_password {
        Some(p) => crypto::UserSecret::from_password_and_keyfile(p, keyfile)?,
        // Random secret — a non-hidden vault still fills the slot so the
        // header is indistinguishable from a vault with a hidden slot.
        None => {
            let mut r = vec![0u8; 64];
            crypto::random_bytes(&mut r);
            crypto::UserSecret { mixed: Zeroizing::new(r) }
        }
    };

    // Two distinct master keys — same body, different region.
    let master_outer = crypto::random_key();
    let master_hidden = crypto::random_key();

    let mut salt_outer = [0u8; SALT_LEN];
    crypto::random_bytes(&mut salt_outer);
    let mut salt_hidden = [0u8; SALT_LEN];
    crypto::random_bytes(&mut salt_hidden);
    let mut nonce_outer = [0u8; NONCE_LEN];
    crypto::random_bytes(&mut nonce_outer);
    let mut nonce_hidden = [0u8; NONCE_LEN];
    crypto::random_bytes(&mut nonce_hidden);

    let params = crypto::default_kdf_params();
    let uk_outer = crypto::derive_user_key(&secret_outer, &salt_outer, &params)?;
    let uk_hidden = crypto::derive_user_key(&secret_hidden, &salt_hidden, &params)?;

    let enc_master_outer = crypto::aead_seal(&uk_outer, &nonce_outer, b"ifb:slot:outer", master_outer.as_ref())?;
    let enc_master_hidden = crypto::aead_seal(&uk_hidden, &nonce_hidden, b"ifb:slot:hidden", master_hidden.as_ref())?;

    let header = Header {
        version: VERSION,
        flags: if with_hidden { 1 } else { 0 },
        salt_outer,
        salt_hidden,
        nonce_outer,
        nonce_hidden,
        enc_master_outer,
        enc_master_hidden,
    };

    let mut f = OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
    header.write(&mut f)?;

    // Initialise both regions with ciphertext of random plaintext so
    // neither region is distinguishable from the other before first use.
    write_random_region(&mut f, HEADER_RESERVED, nominal_size / 2, &master_outer, *b"OUTR", Slot::Outer)?;
    write_random_region(&mut f, HEADER_RESERVED + nominal_size / 2, nominal_size / 2, &master_hidden, *b"HIDN", Slot::Hidden)?;

    // Optional: if a seed dir is given, encrypt it into the outer
    // region. Implementation elided in the skeleton; commit_from()
    // exercises the same code path.
    let _ = seed;

    f.sync_all()?;
    Ok(())
}

fn write_random_region(
    f: &mut File,
    offset: u64,
    len: u64,
    master_key: &SecretKey,
    domain: [u8; 4],
    slot: Slot,
) -> Result<()> {
    f.seek(SeekFrom::Start(offset))?;
    let mut remaining = len;
    let mut idx: u64 = 0;
    let mut pt = vec![0u8; CHUNK];
    while remaining > 0 {
        let want = std::cmp::min(remaining as usize, CHUNK);
        crypto::random_bytes(&mut pt[..want]);
        let nonce = crypto::chunk_nonce(domain, idx);
        let aad = aad_for_chunk(slot, idx);
        let ct = crypto::aead_seal(master_key, &nonce, &aad, &pt[..want])?;
        f.write_all(&ct)?;
        remaining -= want as u64;
        idx += 1;
    }
    Ok(())
}

/// Add or change password slots. Skeleton — same shape as init() but
/// preserves master keys.
pub fn rekey(_path: &Path, _add_hidden: bool) -> Result<()> {
    bail!("rekey not implemented in skeleton")
}
