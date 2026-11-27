//! Key manager: generate, inspect, import and convert SSH private keys. New keys are ed25519;
//! imports accept OpenSSH, PEM/PKCS#8 and PuTTY `.ppk` (v2 and v3) and always come out as
//! OpenSSH, encrypted with bcrypt-pbkdf + AES-256-CTR when a passphrase is given. FIDO2 `sk-`
//! keys are recognised and kept as-is: their private half lives on the authenticator, so they
//! sign through the system agent (see `ssh_auth`), never inside Bastion.

use rand::RngCore;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::{Cipher, Kdf, LineEnding};
use russh::keys::{self, Algorithm, HashAlg, PrivateKey};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// bcrypt-pbkdf rounds for new and converted keys (OpenSSH's `ssh-keygen -a` default is 16).
const KDF_ROUNDS: u32 = 24;
const KDF_SALT_LEN: usize = 16;
const MAX_COMMENT: usize = 256;
const MAX_KEY_TEXT: usize = 64 * 1024;

/// Where an imported key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyFormat {
    Openssh,
    Pem,
    Ppk,
}

/// What the UI shows for a key; never holds secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyInfo {
    pub algorithm: String,
    pub fingerprint: String,
    pub comment: String,
    pub public_openssh: String,
    pub format: KeyFormat,
    /// FIDO2 `sk-` key: signing needs the authenticator (touch), through the system agent.
    pub hardware: bool,
}

/// A key in OpenSSH form plus its description.
pub struct ManagedKey {
    pub private_openssh: Zeroizing<String>,
    pub info: KeyInfo,
}

fn detect_format(text: &str) -> Result<KeyFormat> {
    let head = text.trim_start();
    if head.starts_with("PuTTY-User-Key-File-") {
        Ok(KeyFormat::Ppk)
    } else if head.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        Ok(KeyFormat::Openssh)
    } else if head.starts_with("-----BEGIN ") {
        Ok(KeyFormat::Pem)
    } else {
        Err(CoreError::Invalid("Not a private key (OpenSSH, PEM or PuTTY .ppk)".into()))
    }
}

fn check_comment(comment: &str) -> Result<()> {
    if comment.len() > MAX_COMMENT || comment.chars().any(char::is_control) {
        return Err(CoreError::Invalid(format!("Comment must be one line, at most {MAX_COMMENT} characters")));
    }
    Ok(())
}

fn is_hardware(alg: &Algorithm) -> bool {
    matches!(alg, Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
}

fn describe(key: &PrivateKey, format: KeyFormat) -> Result<KeyInfo> {
    let public = key.public_key();
    Ok(KeyInfo {
        algorithm: key.algorithm().as_str().to_string(),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        comment: key.comment().to_string(),
        public_openssh: public.to_openssh().map_err(|e| CoreError::Invalid(e.to_string()))?,
        format,
        hardware: is_hardware(&key.algorithm()),
    })
}

/// Serialise to OpenSSH, encrypting when a non-empty passphrase is given.
fn to_openssh(key: &PrivateKey, passphrase: Option<&str>) -> Result<Zeroizing<String>> {
    let out = match passphrase.filter(|p| !p.is_empty()) {
        Some(pass) => {
            let mut salt = vec![0u8; KDF_SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            let kdf = Kdf::Bcrypt { salt, rounds: KDF_ROUNDS };
            key.encrypt_with(Cipher::Aes256Ctr, kdf, rand::thread_rng().next_u32(), pass)
                .map_err(|e| CoreError::Invalid(e.to_string()))?
        }
        None => key.clone(),
    };
    out.to_openssh(LineEnding::LF).map_err(|e| CoreError::Invalid(e.to_string()))
}

/// A new ed25519 key from the OS random source.
pub fn generate_ed25519(comment: &str, passphrase: Option<&str>) -> Result<ManagedKey> {
    check_comment(comment)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(seed.as_mut());
    let pair = Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::new(KeypairData::Ed25519(pair), comment).map_err(|e| CoreError::Invalid(e.to_string()))?;
    Ok(ManagedKey { private_openssh: to_openssh(&key, passphrase)?, info: describe(&key, KeyFormat::Openssh)? })
}

fn decode(text: &str, passphrase: Option<&str>) -> Result<(PrivateKey, KeyFormat)> {
    if text.len() > MAX_KEY_TEXT {
        return Err(CoreError::Invalid("Key file is too large".into()));
    }
    let format = detect_format(text)?;
    let key = keys::decode_secret_key(text, passphrase.filter(|p| !p.is_empty())).map_err(|e| match e {
        keys::Error::KeyIsEncrypted => CoreError::Invalid("Key is encrypted: enter its passphrase".into()),
        other => CoreError::Invalid(format!("Could not read key: {other}")),
    })?;
    Ok((key, format))
}

/// Describe a key file without converting it; encrypted keys need their passphrase.
/// Decode a private key (OpenSSH, PEM or `.ppk`) for use, e.g. to serve from the agent.
pub fn load(text: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    decode(text, passphrase).map(|(key, _)| key)
}

pub fn inspect(text: &str, passphrase: Option<&str>) -> Result<KeyInfo> {
    let (key, format) = decode(text, passphrase)?;
    describe(&key, format)
}

/// Import any supported key and re-encode it as OpenSSH under `new_passphrase` (none = plain).
/// An empty `comment` keeps the key's own.
pub fn convert(text: &str, passphrase: Option<&str>, new_passphrase: Option<&str>, comment: &str) -> Result<ManagedKey> {
    check_comment(comment)?;
    let (mut key, format) = decode(text, passphrase)?;
    if !comment.is_empty() {
        key.set_comment(comment);
    }
    Ok(ManagedKey { private_openssh: to_openssh(&key, new_passphrase)?, info: describe(&key, format)? })
}

#[cfg(test)]
#[path = "keymanager_tests.rs"]
mod tests;
