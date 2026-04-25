//! Key derivation, keyfile mixing, AES-256-GCM primitives.
//!
//! The launcher never feeds a raw password into AES. Instead:
//!
//!     user_key = Argon2id(password ‖ keyfile_digest, salt)
//!     master_key = AES-256-GCM-Decrypt(user_key, enc_master_slot)
//!
//! `user_key` is unique per slot (per salt); `master_key` is the same
//! for every slot that unlocks the same logical volume so the volume can
//! be re-keyed without re-encrypting its body.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

/// Argon2id parameters. Tuned for ~1s on a 2024-era laptop; override via
/// the vault header so future vaults can raise costs without breaking
/// old ones.
pub fn default_kdf_params() -> Params {
    Params::new(256 * 1024, 4, 4, Some(KEY_LEN)).expect("valid params")
}

/// The secret material a user can supply. Zeroized on drop.
pub struct UserSecret {
    /// password ‖ BLAKE3(keyfile) — fed into Argon2id.
    pub mixed: Zeroizing<Vec<u8>>,
}

impl UserSecret {
    pub fn from_password_and_keyfile(password: &str, keyfile: Option<&Path>) -> Result<Self> {
        let mut mixed = Zeroizing::new(Vec::with_capacity(password.len() + 32));
        mixed.extend_from_slice(password.as_bytes());
        if let Some(path) = keyfile {
            let bytes = std::fs::read(path)?;
            let digest = blake3::hash(&bytes);
            mixed.extend_from_slice(digest.as_bytes());
            let mut b = bytes; // zeroize on drop
            b.zeroize();
        }
        Ok(Self { mixed })
    }
}

/// A 32-byte key wrapped so it is zeroed on drop.
pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;

pub fn derive_user_key(secret: &UserSecret, salt: &[u8; SALT_LEN], params: &Params) -> Result<SecretKey> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut out: SecretKey = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(&secret.mixed, salt, out.as_mut_slice())
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

/// AES-256-GCM encrypt. `aad` is bound into the tag.
pub fn aead_seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|e| anyhow!("aead seal: {e}"))?;
    Ok(ct)
}

/// AES-256-GCM decrypt. Returns `None` on tag failure (constant-time inside aes-gcm).
pub fn aead_open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    match cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad }) {
        Ok(pt) => Some(Zeroizing::new(pt)),
        Err(_) => None,
    }
}

/// Per-chunk nonce: 4-byte domain prefix || 8-byte little-endian chunk index.
pub fn chunk_nonce(domain: [u8; 4], chunk_index: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&domain);
    n[4..].copy_from_slice(&chunk_index.to_le_bytes());
    n
}

pub fn random_bytes(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub fn random_key() -> SecretKey {
    let mut k: SecretKey = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(k.as_mut_slice());
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let msg = b"intifybrowser";
        let ct = aead_seal(&key, &nonce, b"aad", msg).unwrap();
        let pt = aead_open(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt.as_slice(), msg);
        assert!(aead_open(&key, &nonce, b"other", &ct).is_none());
    }

    #[test]
    fn chunk_nonces_are_unique() {
        let a = chunk_nonce(*b"OUTR", 0);
        let b = chunk_nonce(*b"OUTR", 1);
        let c = chunk_nonce(*b"HIDN", 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
