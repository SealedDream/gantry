//! Royal TS-style documents: a self-contained, versioned `.bastion` file holding one tree of
//! folders, connections, gateways and tunnels, plus — only when the document is password
//! protected — its credentials.
//!
//! On disk a document is a JSON envelope:
//!
//! ```text
//! { "format": "bastion-document", "version": 1, "id", "name", "revision",
//!   "contents": {...} }                                   // unprotected
//! { ..., "protection": { kdf params, salt, wrapped_key }, "sealed": { nonce, ciphertext } }
//! ```
//!
//! Protection reuses the vault crypto: Argon2id derives a key-encryption key from the password,
//! which unwraps a random 256-bit document key (XChaCha20-Poly1305); the document key seals the
//! contents. The id, name and revision are bound as associated data, so editing any clear field
//! fails authentication. Wrapping a random key (instead of sealing with the password directly)
//! lets a platform key store hold the same key for Touch ID / Windows Hello unlock while the
//! password always remains a fallback.
//!
//! An unprotected document never carries secrets: saving refuses one with credentials, and
//! export strips them unless the exported file is itself protected.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::export::{self, Selection};
use crate::model::{Connection, Document, Folder, Node, SCHEMA_VERSION};
use crate::store::{create_private_dir, write_atomic};
use crate::vault::Credential;

pub const FORMAT: &str = "bastion-document";
pub const VERSION: u32 = 1;
/// The newest format this app reads. A `VERSION + 1` document is one a later Bastion wrote
/// because it holds plugin data (`docs/specs/plugins.md` section 10). This app reads it with
/// the tolerant readers, keeps what it does not know, and saves it back as `VERSION + 1`. Since
/// PLUG-03b a save also raises a document to `VERSION + 1` when it holds plugin entries or other
/// data this app keeps without knowing it (see `to_envelope`).
pub const MAX_READ_VERSION: u32 = VERSION + 1;
/// The label inside the key-wrap bindings ([`key_aad`], [`wrap_aad`]). It is not the file's
/// format version: a password wrap cannot be redone without the password and a key-store blob
/// lives outside the file, so both must keep opening when a document moves to a later format.
const KEY_BINDING_VERSION: u32 = 1;
/// The document extension since the product rename (owner 2026-11-23).
pub const EXTENSION: &str = "gantry";
/// The extension documents made before the rename carry; they open as before.
pub const LEGACY_EXTENSION: &str = "bastion";
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const MIN_PASSWORD: usize = 8;
const MAX_BACKUPS: usize = 20;
const MAX_RECENT: usize = 10;
const MAX_NAME: usize = 120;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
/// Bounds for parameters read from a file: no unbounded memory/time, no trivially weak settings.
const ARGON2_M_COST_RANGE: std::ops::RangeInclusive<u32> = 19 * 1024..=1024 * 1024;
const ARGON2_T_COST_RANGE: std::ops::RangeInclusive<u32> = 2..=10;

pub type DocumentKey = Zeroizing<[u8; KEY_LEN]>;

/// Protection whose document key is held only by this device's key store (no password wrap).
pub const DEVICE_KDF: &str = "device";

fn device_protection() -> Protection {
    Protection { kdf: DEVICE_KDF.into(), salt: vec![], m_cost: 0, t_cost: 0, key_nonce: vec![], wrapped_key: vec![], biometric: false }
}

/// What a document holds. `credentials` is empty unless the document is protected.
#[derive(Clone, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct Contents {
    pub document: Document,
    /// Credentials of a kind this app does not know are kept and written back (`vault_unknown`).
    #[serde(default, skip_serializing_if = "crate::vault_unknown::CredentialList::is_empty")]
    pub credentials: crate::vault_unknown::CredentialList,
    /// The library's credential vault (named credentials, folders, inline per-connection
    /// secrets) as plain vault JSON. Only ever written inside the sealed payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<serde_json::Value>,
    /// Fields this app does not know, kept as read and written back unchanged (PLUG-03a).
    #[serde(flatten, skip_deserializing)]
    pub extra: crate::unknown::Extra,
}

crate::unknown::keeps_unknown_fields!(Contents);

#[derive(Clone, Serialize, Deserialize)]
struct Protection {
    kdf: String,
    #[serde(with = "b64")]
    salt: Vec<u8>,
    m_cost: u32,
    t_cost: u32,
    #[serde(with = "b64")]
    key_nonce: Vec<u8>,
    #[serde(with = "b64")]
    wrapped_key: Vec<u8>,
    /// A hint for the UI only: a platform key store may hold this document's key.
    #[serde(default)]
    biometric: bool,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: String,
    version: u32,
    id: Uuid,
    name: String,
    revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protection: Option<Protection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contents: Option<Contents>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<Sealed>,
}

/// The top-level fields that decide how a file is read; everything else is skipped.
#[derive(Deserialize)]
struct Probe {
    #[serde(default, deserialize_with = "present")]
    format: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "present")]
    version: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "present")]
    schema: Option<serde::de::IgnoredAny>,
}

/// `Some` whenever the field is there, also when its value is `null`.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> std::result::Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// An open document. Protected documents start locked: only the id and name are known until
/// [`DocumentFile::unlock`] succeeds, and [`DocumentFile::lock`] forgets the key and contents.
pub struct DocumentFile {
    path: Option<PathBuf>,
    id: Uuid,
    name: String,
    revision: u64,
    protection: Option<Protection>,
    key: Option<DocumentKey>,
    contents: Option<Contents>,
    /// Sealed bytes kept while locked, so unlocking needs no second read of the file.
    sealed: Option<Sealed>,
    /// Format version the file was read from (0 = a pre-document `library.json`). Saving
    /// writes [`Self::format_version`], raised to `VERSION + 1` when the contents hold unknown data.
    loaded_version: u32,
    dirty: bool,
}

/// Never prints contents or key material.
impl std::fmt::Debug for DocumentFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentFile").field("id", &self.id).field("name", &self.name).field("protected", &self.is_protected()).field("locked", &self.is_locked()).finish()
    }
}

fn locked() -> CoreError {
    CoreError::Invalid("the document is locked".into())
}

fn clean_name(name: &str) -> Result<String> {
    let n: String = name.trim().chars().filter(|c| !c.is_control()).take(MAX_NAME).collect();
    if n.is_empty() {
        return Err(CoreError::Invalid("a document needs a name".into()));
    }
    Ok(n)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn derive(password: &str, salt: &[u8], m_cost: u32, t_cost: u32) -> Result<DocumentKey> {
    let params = Params::new(m_cost, t_cost, 1, Some(KEY_LEN)).map_err(|e| CoreError::Invalid(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| CoreError::Invalid(e.to_string()))?;
    Ok(key)
}

fn key_aad(id: Uuid) -> Vec<u8> {
    format!("{FORMAT}/{KEY_BINDING_VERSION}/key/{id}").into_bytes()
}

/// The bytes of a document about to be written, or the refusal when they are more than
/// [`MAX_BYTES`]: `open` refuses such a file, so it is never written and the file on disk
/// stays as it is.
fn writable(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.len() > MAX_BYTES {
        return Err(CoreError::Invalid(format!("this document would be over {} MB, more than a document file may hold; nothing was saved", MAX_BYTES / (1024 * 1024))));
    }
    Ok(bytes)
}

/// Binds the sealed contents to every clear field of the envelope, the format `version`
/// included: a `VERSION + 1` document is sealed and opened under `VERSION + 1`, so editing the
/// version in the file (to make an app write it back in another format) fails authentication.
fn payload_aad(version: u32, id: Uuid, name: &str, revision: u64) -> Vec<u8> {
    format!("{FORMAT}/{version}/contents/{id}/{revision}/{name}").into_bytes()
}

fn seal(key: &[u8; KEY_LEN], aad: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = random::<NONCE_LEN>();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
        .map_err(|_| CoreError::Invalid("encryption failed".into()))?;
    Ok((nonce.to_vec(), ct))
}

/// Every authentication failure (wrong password, edited header, damaged ciphertext) is the
/// same `VaultAuth` error, so a refusal tells an attacker nothing about which part was wrong.
fn open_sealed(key: &[u8; KEY_LEN], aad: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::VaultAuth);
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CoreError::VaultAuth)
}

fn new_protection(id: Uuid, password: &str, key: &[u8; KEY_LEN]) -> Result<Protection> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(CoreError::Invalid(format!("use a document password of at least {MIN_PASSWORD} characters")));
    }
    let salt = random::<SALT_LEN>();
    let kek = derive(password, &salt, ARGON2_M_COST_KIB, ARGON2_T_COST)?;
    let (key_nonce, wrapped_key) = seal(&kek, &key_aad(id), key)?;
    Ok(Protection { kdf: "argon2id".into(), salt: salt.to_vec(), m_cost: ARGON2_M_COST_KIB, t_cost: ARGON2_T_COST, key_nonce, wrapped_key, biometric: false })
}

impl DocumentFile {
    /// A new, unsaved, unprotected document with an empty tree.
    pub fn new(name: &str) -> Result<Self> {
        let name = clean_name(name)?;
        let mut d = Self::from_document(Document::new(name));
        d.revision = 0;
        Ok(d)
    }

    /// A new, unsaved, encrypted document whose random key is kept by the device key store
    /// (`DEVICE_KDF`): the Personal library and every library created on this Mac.
    pub fn new_device(document: Document) -> Self {
        let mut d = Self::from_document(document);
        d.protection = Some(device_protection());
        d.key = Some(Zeroizing::new(random::<KEY_LEN>()));
        d
    }

    /// True when the key comes only from the device key store (no master password).
    pub fn is_device_keyed(&self) -> bool {
        self.protection.as_ref().is_some_and(|p| p.kdf == DEVICE_KDF)
    }

    /// True when a master password can unlock this document.
    pub fn has_password(&self) -> bool {
        self.protection.as_ref().is_some_and(|p| p.kdf != DEVICE_KDF)
    }

    /// Drop the master password but keep the contents encrypted under the same key, which the
    /// device key store then holds alone.
    pub fn remove_master_password(&mut self) -> Result<()> {
        if self.contents.is_none() {
            return Err(locked());
        }
        if self.protection.is_none() {
            return Err(CoreError::Invalid("the document is not encrypted".into()));
        }
        let biometric = self.biometric();
        self.protection = Some(Protection { biometric, ..device_protection() });
        self.dirty = true;
        Ok(())
    }

    /// The credential vault stored in this document (empty when none yet).
    pub fn vault(&self) -> Result<crate::vault::Vault> {
        match &self.contents()?.vault {
            None => Ok(crate::vault::Vault::default()),
            Some(v) => {
                let bytes = Zeroizing::new(serde_json::to_vec(v).map_err(|e| CoreError::Invalid(e.to_string()))?);
                crate::vault::Vault::from_plain(&bytes)
            }
        }
    }

    /// Replace the stored vault. Only encrypted documents hold one.
    pub fn set_vault(&mut self, vault: &crate::vault::Vault) -> Result<()> {
        if self.protection.is_none() {
            return Err(CoreError::Invalid("an unprotected document may not carry credentials".into()));
        }
        let plain = vault.to_plain()?;
        let value: serde_json::Value = serde_json::from_slice(&plain).map_err(|e| CoreError::Invalid(e.to_string()))?;
        let c = self.contents.as_mut().ok_or_else(locked)?;
        c.vault = Some(value);
        self.dirty = true;
        Ok(())
    }

    /// Wrap an existing tree (the old single library) as an unsaved, unprotected document.
    pub fn from_document(document: Document) -> Self {
        DocumentFile {
            path: None,
            id: document.id,
            name: clean_name(&document.name).unwrap_or_else(|_| "Personal".into()),
            revision: document.revision,
            protection: None,
            key: None,
            contents: Some(Contents { document, credentials: Default::default(), vault: None, extra: Default::default() }),
            sealed: None,
            loaded_version: VERSION,
            dirty: true,
        }
    }

    /// Read `path`. A protected document comes back locked.
    pub fn open(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path)?;
        if !meta.is_file() || meta.len() > MAX_BYTES as u64 {
            return Err(CoreError::Invalid(format!("choose a regular file under {} MB", MAX_BYTES / (1024 * 1024))));
        }
        let mut doc = Self::parse(&fs::read(path)?)?;
        doc.path = Some(path.to_path_buf());
        Ok(doc)
    }

    /// Parse document bytes (untrusted). Version 0 is a pre-document `library.json` (a bare
    /// `Document`), opened as an unprotected document.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bytes = crate::store::skip_bom(bytes);
        if bytes.len() > MAX_BYTES {
            return Err(CoreError::Invalid("document is too large".into()));
        }
        // A first pass reads only what decides how the file is read (format marker, version,
        // old-library schema) and checks that it is JSON; the second reads it into its types.
        // Nothing builds a tree of the whole file in between.
        if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err(CoreError::Corrupt("not a Gantry document: not a JSON object".into()));
        }
        let probe: Probe = serde_json::from_slice(bytes).map_err(|e| CoreError::Corrupt(format!("not a Gantry document: {e}")))?;
        if probe.format.is_none() && probe.schema.is_some() {
            let document: Document = crate::unknown::reading(|| serde_json::from_slice(bytes)).map_err(|e| e.or_else(|e| CoreError::Corrupt(e.to_string())))?;
            if document.schema > SCHEMA_VERSION {
                return Err(CoreError::Corrupt(format!("schema {} is newer than supported {SCHEMA_VERSION}", document.schema)));
            }
            crate::unknown::check(&document, &Default::default())?;
            let mut d = Self::from_document(document);
            d.loaded_version = 0;
            d.dirty = false;
            return Ok(d);
        }
        if probe.format.as_ref().and_then(|f| f.as_str()) != Some(FORMAT) {
            return Err(CoreError::Corrupt("not a Gantry document (missing format marker)".into()));
        }
        let version = probe.version.as_ref().and_then(|v| v.as_u64()).ok_or_else(|| CoreError::Corrupt("document has no version".into()))?;
        if version > MAX_READ_VERSION as u64 {
            return Err(CoreError::Invalid(format!("this document was saved by a newer Gantry (format {version}; this app reads up to {MAX_READ_VERSION})")));
        }
        if version < VERSION as u64 {
            return Err(CoreError::Corrupt(format!("unknown document format {version}")));
        }
        let version = version as u32; // VERSION or VERSION + 1
        let env: Envelope = crate::unknown::reading(|| serde_json::from_slice(bytes)).map_err(|e| e.or_else(|e| CoreError::Corrupt(format!("invalid document: {e}"))))?;
        let name = clean_name(&env.name)?;
        let (protection, contents, sealed) = match (env.protection, env.contents, env.sealed) {
            (None, Some(c), None) => {
                if !c.credentials.is_empty() || c.vault.is_some() {
                    return Err(CoreError::Corrupt("an unprotected document may not carry credentials".into()));
                }
                if c.document.schema > SCHEMA_VERSION {
                    return Err(CoreError::Corrupt(format!("schema {} is newer than supported {SCHEMA_VERSION}", c.document.schema)));
                }
                crate::unknown::check(&c.document, &c.extra)?;
                (None, Some(c), None)
            }
            (Some(p), None, Some(s)) if p.kdf == DEVICE_KDF => {
                if !p.salt.is_empty() || !p.key_nonce.is_empty() || !p.wrapped_key.is_empty() {
                    return Err(CoreError::Corrupt("a device-keyed document carries no password wrap".into()));
                }
                (Some(p), None, Some(s))
            }
            (Some(p), None, Some(s)) => {
                if p.kdf != "argon2id" || !ARGON2_M_COST_RANGE.contains(&p.m_cost) || !ARGON2_T_COST_RANGE.contains(&p.t_cost) || p.salt.len() < SALT_LEN {
                    return Err(CoreError::Corrupt("document key-derivation parameters out of allowed range".into()));
                }
                (Some(p), None, Some(s))
            }
            _ => return Err(CoreError::Corrupt("document is neither plainly stored nor sealed".into())),
        };
        Ok(DocumentFile { path: None, id: env.id, name, revision: env.revision, protection, key: None, contents, sealed, loaded_version: version, dirty: false })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn is_protected(&self) -> bool {
        self.protection.is_some()
    }
    pub fn is_locked(&self) -> bool {
        self.contents.is_none()
    }
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn biometric(&self) -> bool {
        self.protection.as_ref().is_some_and(|p| p.biometric)
    }
    /// Version the file was read in (0 for an old `library.json`); saving writes
    /// [`Self::format_version`].
    pub fn loaded_version(&self) -> u32 {
        self.loaded_version
    }

    /// The format this document is in now: `VERSION + 1` when it was read or last saved as that
    /// (never silently downgraded), otherwise [`VERSION`]. A save raises it to `VERSION + 1` when
    /// the contents hold plugin or other unknown data (PLUG-03b).
    pub fn format_version(&self) -> u32 {
        if self.loaded_version == MAX_READ_VERSION {
            MAX_READ_VERSION
        } else {
            VERSION
        }
    }

    /// Unlock with the document password.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if !self.is_locked() {
            return Ok(());
        }
        let p = self.protection.as_ref().ok_or_else(|| CoreError::Invalid("the document has no password".into()))?;
        if p.kdf == DEVICE_KDF {
            // W2: name the platform's own key holder (Windows: this PC's device key).
            let holder = if cfg!(windows) { "this PC's device key" } else { "this Mac's key" };
            return Err(CoreError::Invalid(format!("this library has no master password; it opens with {holder}")));
        }
        let kek = derive(password, &p.salt, p.m_cost, p.t_cost)?;
        let raw = open_sealed(&kek, &key_aad(self.id), &p.key_nonce, &p.wrapped_key)?;
        let key: [u8; KEY_LEN] = raw.as_slice().try_into().map_err(|_| CoreError::VaultAuth)?;
        self.unlock_with_key(Zeroizing::new(key))
    }

    /// Unlock with the document key itself (released by Touch ID / Windows Hello).
    pub fn unlock_with_key(&mut self, key: DocumentKey) -> Result<()> {
        if !self.is_locked() {
            return Ok(());
        }
        let s = self.sealed.as_ref().ok_or(CoreError::VaultAuth)?;
        let plain = open_sealed(&key, &payload_aad(self.format_version(), self.id, &self.name, self.revision), &s.nonce, &s.ciphertext)?;
        let contents: Contents = crate::unknown::reading(|| serde_json::from_slice(&plain)).map_err(|e| e.or_else(|_| CoreError::VaultAuth))?;
        // Authenticated, so this is what the writer sealed; what it holds that this app does
        // not know is still capped (PLUG-03a). The document stays locked when it is refused.
        crate::unknown::check(&contents.document, &contents.extra)?;
        self.contents = Some(contents);
        self.key = Some(key);
        Ok(())
    }

    /// Forget the key and the decrypted contents (credentials are zeroized on drop). An
    /// unprotected document has nothing to lock. Unsaved changes are lost, so callers save first.
    pub fn lock(&mut self) -> bool {
        if self.protection.is_none() || self.is_locked() || self.sealed.is_none() {
            return false;
        }
        self.key = None;
        self.contents = None;
        self.dirty = false;
        true
    }

    /// Lock even though the current contents could not be saved: re-seal them in memory under
    /// the document key, then forget the key and plaintext. The unsaved changes come back on
    /// the next unlock and stay dirty, so the next save writes them (FFI F07).
    pub fn lock_keeping_changes(&mut self) -> Result<bool> {
        if self.protection.is_none() || self.is_locked() {
            return Ok(false);
        }
        let key = self.key.as_ref().ok_or_else(locked)?;
        let contents = self.contents.as_ref().ok_or_else(locked)?;
        let plain = Zeroizing::new(serde_json::to_vec(contents).map_err(|e| CoreError::Invalid(e.to_string()))?);
        let (nonce, ciphertext) = seal(key, &payload_aad(self.format_version(), self.id, &self.name, self.revision), &plain)?;
        self.sealed = Some(Sealed { nonce, ciphertext });
        self.key = None;
        self.contents = None;
        self.dirty = true;
        Ok(true)
    }

    /// The document key, for storing in a platform key store (Touch ID / Windows Hello).
    pub fn key(&self) -> Result<DocumentKey> {
        self.key.clone().ok_or_else(locked)
    }

    pub fn set_biometric(&mut self, on: bool) -> Result<()> {
        let p = self.protection.as_mut().ok_or_else(|| CoreError::Invalid("set a document password before enabling biometric unlock".into()))?;
        p.biometric = on;
        self.dirty = true;
        Ok(())
    }

    pub fn contents(&self) -> Result<&Contents> {
        self.contents.as_ref().ok_or_else(locked)
    }

    pub fn document(&self) -> Result<&Document> {
        Ok(&self.contents()?.document)
    }

    pub fn document_mut(&mut self) -> Result<&mut Document> {
        let c = self.contents.as_mut().ok_or_else(locked)?;
        self.dirty = true;
        Ok(&mut c.document)
    }

    /// Replace the tree (the frontends edit a working copy and hand it back).
    pub fn set_document(&mut self, document: Document) -> Result<()> {
        let c = self.contents.as_mut().ok_or_else(locked)?;
        c.document = Document { id: self.id, name: self.name.clone(), revision: self.revision, ..document };
        self.dirty = true;
        Ok(())
    }

    /// Treat every login reference in the document as a sender's, not yet the user's choice
    /// (A1-CORE-01-FU5): `logins::mark_received` over the tree and the type defaults, as an
    /// import does. Whatever the file says about confirmation is dropped. With `changed` the
    /// marks are a change to save; without it they hold in memory only (a library the user
    /// has not answered for yet). Fails on a locked document.
    pub fn mark_as_received(&mut self, changed: bool) -> Result<()> {
        let c = self.contents.as_mut().ok_or_else(locked)?;
        crate::logins::mark_received(&mut c.document.root);
        c.document.type_defaults.values_mut().for_each(crate::logins::mark_settings);
        self.dirty |= changed;
        Ok(())
    }

    pub fn rename(&mut self, name: &str) -> Result<()> {
        let name = clean_name(name)?;
        self.document_mut()?.name = name.clone();
        self.name = name;
        Ok(())
    }

    /// Set, change (`Some`) or remove (`None`) the password. Changing it rewraps the same
    /// document key, so a stored biometric key keeps working. Removing it is refused while the
    /// document holds credentials, since they would otherwise be written in the clear.
    pub fn set_password(&mut self, password: Option<&str>) -> Result<()> {
        let contents = self.contents.as_ref().ok_or_else(locked)?;
        match password {
            None => {
                if !contents.credentials.is_empty() || contents.vault.is_some() {
                    return Err(CoreError::Invalid("remove this document's credentials before removing its password".into()));
                }
                self.protection = None;
                self.key = None;
                self.sealed = None;
            }
            Some(pw) => {
                let key = self.key.clone().unwrap_or_else(|| Zeroizing::new(random::<KEY_LEN>()));
                let biometric = self.biometric();
                let mut p = new_protection(self.id, pw, &key)?;
                p.biometric = biometric;
                self.protection = Some(p);
                self.key = Some(key);
            }
        }
        self.dirty = true;
        Ok(())
    }

    pub fn credentials(&self) -> Result<&[Credential]> {
        Ok(&self.contents()?.credentials)
    }

    /// Tests only: replace the document's credential list (to hold unknown kinds).
    #[cfg(test)]
    pub(crate) fn set_credentials_for_tests(&mut self, list: crate::vault_unknown::CredentialList) {
        if let Some(c) = self.contents.as_mut() {
            c.credentials = list;
            self.dirty = true;
        }
    }

    /// Credentials a newer app stored here, of a kind this app cannot use: listed, never used.
    pub fn unsupported_credentials(&self) -> Result<&[crate::vault_unknown::UnknownCredential]> {
        Ok(self.contents()?.credentials.unsupported())
    }

    /// Store a credential in the document (replacing one with the same id). Only protected
    /// documents hold credentials.
    pub fn put_credential(&mut self, c: Credential) -> Result<()> {
        if self.protection.is_none() {
            return Err(CoreError::Invalid("set a document password before storing credentials in it".into()));
        }
        let contents = self.contents.as_mut().ok_or_else(locked)?;
        contents.credentials.put(c)?;
        self.dirty = true;
        Ok(())
    }

    pub fn remove_credential(&mut self, id: Uuid) -> Result<bool> {
        let contents = self.contents.as_mut().ok_or_else(locked)?;
        let removed = contents.credentials.remove_id(id);
        self.dirty = true;
        Ok(removed)
    }

    /// Serialize at `revision` (the revision written to disk).
    fn to_envelope(&self, revision: u64) -> Result<Envelope> {
        let contents = self.contents.as_ref().ok_or_else(locked)?;
        // Never write what `parse` or an unlock would refuse.
        crate::unknown::check(&contents.document, &contents.extra)?;
        // PLUG-03b, spec section 10 step 3: a document holding plugin entries or any data this
        // app keeps without knowing it is written as `VERSION + 1`. The version is chosen here,
        // once, and the same value goes into the envelope and the sealing AAD below, so raising
        // and re-sealing are one step: there is no state in which the file says one version and
        // the contents are bound to another. Raising happens only on a save, never on open.
        let version = if crate::unknown::holds_unknown(&contents.document, &contents.extra) { MAX_READ_VERSION } else { self.format_version() };
        let mut env = Envelope { format: FORMAT.into(), version, id: self.id, name: self.name.clone(), revision, protection: None, contents: None, sealed: None };
        match &self.protection {
            None => {
                if !contents.credentials.is_empty() || contents.vault.is_some() {
                    return Err(CoreError::Invalid("an unprotected document may not carry credentials".into()));
                }
                let mut c = contents.clone();
                c.document.revision = revision;
                env.contents = Some(c);
            }
            Some(p) => {
                let key = self.key.as_ref().ok_or_else(locked)?;
                let plain = Zeroizing::new(serde_json::to_vec(contents).map_err(|e| CoreError::Invalid(e.to_string()))?);
                let (nonce, ciphertext) = seal(key, &payload_aad(version, self.id, &self.name, revision), &plain)?;
                env.protection = Some(p.clone());
                env.sealed = Some(Sealed { nonce, ciphertext });
            }
        }
        Ok(env)
    }

    /// The bytes a save would write, without writing (export to a share target).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        writable(serde_json::to_vec_pretty(&self.to_envelope(self.revision + 1)?).map_err(|e| CoreError::Invalid(e.to_string()))?)
    }

    /// Save to the document's own path, refusing if someone else saved it since it was read.
    pub fn save(&mut self) -> Result<()> {
        let path = self.path.clone().ok_or_else(|| CoreError::Invalid("choose where to save this document".into()))?;
        self.write(&path, true)
    }

    /// Save to `path` and make it the document's path. Overwrites whatever is there (the save
    /// panel already asked), after keeping a backup of it.
    pub fn save_as(&mut self, path: &Path) -> Result<()> {
        self.write(path, false)?;
        self.path = Some(path.to_path_buf());
        Ok(())
    }

    /// Read, check, back up and replace run under [`crate::store::with_save_lock`], so two
    /// instances saving from the same revision cannot both succeed.
    fn write(&mut self, path: &Path, check_revision: bool) -> Result<()> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        crate::store::with_save_lock(path, || self.write_locked(path, check_revision))
    }

    fn write_locked(&mut self, path: &Path, check_revision: bool) -> Result<()> {
        let on_disk = if path.exists() {
            // A read-only document stays read-only: the atomic rename would replace it silently on
            // macOS/Linux (Windows refuses the rename with "Access is denied").
            if fs::metadata(path)?.permissions().readonly() {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "The document is read-only; save it under another name with Save As.").into());
            }
            let on_disk = fs::read(path)?;
            if check_revision {
                let found = Self::parse(&on_disk)?.revision;
                if found != self.revision {
                    return Err(CoreError::Conflict { expected: self.revision, found });
                }
            }
            Some(on_disk)
        } else {
            None
        };
        // Everything that can refuse this save comes before anything is written: a refused
        // save must leave the file and its backups as they are (only 20 backups are kept, so
        // refused saves that each wrote one would push the real ones out).
        let next = self.revision + 1;
        let env = self.to_envelope(next)?;
        let bytes = writable(serde_json::to_vec_pretty(&env).map_err(|e| CoreError::Invalid(e.to_string()))?)?;
        if let Some(on_disk) = on_disk {
            backup(path, &on_disk)?;
        }
        write_atomic(path, &bytes)?;
        self.revision = next;
        if let Some(c) = self.contents.as_mut() {
            c.document.revision = next;
        }
        // Keep `sealed` matching the file so a later lock/unlock round-trips without a read.
        self.sealed = env.sealed;
        self.loaded_version = env.version;
        self.dirty = false;
        Ok(())
    }
}

/// Backups sit in `<file>.backups/` as the exact previous bytes, so a protected document's
/// backups stay encrypted.
fn backup(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = backups_dir(path);
    create_private_dir(&dir)?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros()).unwrap_or(0);
    write_atomic(&dir.join(format!("{stamp:018}.{EXTENSION}")), bytes)?;
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    entries.reverse();
    for stale in entries.into_iter().skip(MAX_BACKUPS) {
        fs::remove_file(stale)?;
    }
    Ok(())
}

pub fn backups_dir(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".backups");
    path.with_file_name(name)
}

// ---------------------------------------------------------------------------------------------
// Export / import

/// What an export writes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportSummary {
    pub folders: usize,
    pub connections: usize,
    /// Credentials carried in the file (0 when secrets are stripped).
    pub credentials: usize,
    /// Credential references in the exported tree.
    pub credential_refs: usize,
    pub stripped_fields: Vec<String>,
}

/// Build a shareable document from `selection` of `source`. Secrets are stripped unless
/// `include_secrets`, which requires a `password` for the new file (it is protected then).
/// A `password` without secrets still protects the exported tree.
pub fn export(source: &DocumentFile, selection: &Selection, name: &str, include_secrets: bool, password: Option<&str>) -> Result<(DocumentFile, ExportSummary)> {
    if include_secrets && password.is_none() {
        return Err(CoreError::Invalid("a password is required to export secrets".into()));
    }
    let contents = source.contents()?;
    let (document, preview) = export::prepare_with(&contents.document, selection, include_secrets);
    let mut out = DocumentFile::new(name)?;
    out.set_document(document)?;
    let credentials: Vec<Credential> = if include_secrets {
        contents
            .credentials
            .iter()
            .filter(|c| preview.credential_refs.contains(&c.id) || (c.owner.is_none() && preview.credential_names.contains(&c.name)))
            .cloned()
            .collect()
    } else {
        vec![]
    };
    let summary = ExportSummary {
        folders: preview.folders,
        connections: preview.connections,
        credentials: credentials.len(),
        credential_refs: preview.credential_refs.len(),
        stripped_fields: preview.stripped_fields,
    };
    if let Some(pw) = password {
        out.set_password(Some(pw))?;
    }
    for c in credentials {
        out.put_credential(c)?;
    }
    Ok((out, summary))
}

/// What importing a document adds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportPlan {
    pub source_name: String,
    pub connections: usize,
    /// Connections skipped because the target already has the same protocol/host/port/user.
    pub duplicates: Vec<String>,
    pub credentials: usize,
    /// Credentials that cannot come in because the target document is not protected.
    pub credentials_dropped: usize,
}

type Identity = (String, String, Option<u16>, Option<String>);

fn identity(c: &Connection) -> Identity {
    (format!("{:?}", c.protocol), c.host.to_lowercase(), c.settings.port, c.settings.username.clone())
}

fn identities(f: &Folder, out: &mut BTreeSet<Identity>) {
    for n in &f.children {
        match n {
            Node::Folder(sub) => identities(sub, out),
            Node::Connection(c) => {
                out.insert(identity(c));
            }
        }
    }
}

/// Drop duplicates, give every node a fresh id and clear references to credentials that are
/// not coming along.
fn prune(f: &Folder, existing: &BTreeSet<Identity>, keep_creds: &BTreeSet<Uuid>, plan: &mut ImportPlan) -> Folder {
    // An imported folder is never a dynamic folder (B15, C9).
    let mut out = Folder { id: Uuid::new_v4(), children: vec![], dynamic_task_id: None, ..f.clone() };
    if out.defaults.credential_id.is_some_and(|id| !keep_creds.contains(&id)) {
        out.defaults.credential_id = None;
    }
    for n in &f.children {
        match n {
            Node::Folder(sub) => out.children.push(Node::Folder(prune(sub, existing, keep_creds, plan))),
            // A type this app does not know stays behind: its own data may hold references
            // this app cannot clear, and the target may be a `VERSION` document (PLUG-03a).
            Node::Connection(c) if c.protocol == crate::model::Protocol::Unsupported => {}
            Node::Connection(c) if existing.contains(&identity(c)) => plan.duplicates.push(c.name.clone()),
            Node::Connection(c) => {
                let mut c = c.clone();
                c.id = Uuid::new_v4();
                if c.settings.credential_id.is_some_and(|id| !keep_creds.contains(&id)) {
                    c.settings.credential_id = None;
                }
                plan.connections += 1;
                out.children.push(Node::Connection(c));
            }
        }
    }
    out
}

/// Plan (and with `apply`, perform) importing unlocked `source` into `target` as a new
/// top-level folder `Imported <source name>`. Returns the plan and, when applied, the folder id.
pub fn import_into(target: &mut DocumentFile, source: &DocumentFile, apply: bool) -> Result<(ImportPlan, Option<Uuid>)> {
    let src = source.contents()?;
    let target_protected = target.is_protected();
    let tcontents = target.contents()?;
    let mut existing = BTreeSet::new();
    identities(&tcontents.document.root, &mut existing);
    // Unknown-kind ids count as taken, so an import never replaces one.
    let known: BTreeSet<Uuid> = tcontents.credentials.ids().collect();
    let incoming: Vec<Credential> = if target_protected { src.credentials.iter().filter(|c| !known.contains(&c.id)).cloned().collect() } else { vec![] };
    let mut keep: BTreeSet<Uuid> = incoming.iter().map(|c| c.id).collect();
    keep.extend(known);
    let mut plan = ImportPlan {
        source_name: source.name.clone(),
        credentials: incoming.len(),
        credentials_dropped: if target_protected { 0 } else { src.credentials.len() },
        ..Default::default()
    };
    let mut folder = prune(&src.document.root, &existing, &keep, &mut plan);
    crate::unknown::strip_folder(&mut folder);
    folder.name = format!("Imported {}", source.name);
    // What the source says about logins is the sender's choice, not yet the user's.
    crate::logins::mark_received(&mut folder);
    if !apply {
        return Ok((plan, None));
    }
    let id = folder.id;
    for c in incoming {
        target.put_credential(c)?;
    }
    target.document_mut()?.insert(None, Node::Folder(folder))?;
    Ok((plan, Some(id)))
}

// ---------------------------------------------------------------------------------------------
// Recent documents

/// The Recent Documents list, newest first, kept as a small owner-only JSON file.
pub struct RecentDocuments {
    path: PathBuf,
}

impl RecentDocuments {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        RecentDocuments { path: path.into() }
    }

    pub fn list(&self) -> Vec<PathBuf> {
        let list: Vec<PathBuf> = fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        list.into_iter().take(MAX_RECENT).collect()
    }

    pub fn add(&self, doc: &Path) -> Result<Vec<PathBuf>> {
        let mut list: Vec<PathBuf> = self.list().into_iter().filter(|p| p != doc).collect();
        list.insert(0, doc.to_path_buf());
        list.truncate(MAX_RECENT);
        self.write(&list)?;
        Ok(list)
    }

    pub fn remove(&self, doc: &Path) -> Result<Vec<PathBuf>> {
        let list: Vec<PathBuf> = self.list().into_iter().filter(|p| p != doc).collect();
        self.write(&list)?;
        Ok(list)
    }

    fn write(&self, list: &[PathBuf]) -> Result<()> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        write_atomic(&self.path, &serde_json::to_vec_pretty(list).map_err(|e| CoreError::Invalid(e.to_string()))?)
    }
}

fn wrap_aad(id: Uuid) -> Vec<u8> {
    format!("{FORMAT}/{KEY_BINDING_VERSION}/keywrap/{id}").into_bytes()
}

/// A fresh 32-byte key for wrapping document keys on this device (keep it in the OS key store).
pub fn new_wrapping_key() -> DocumentKey {
    Zeroizing::new(random::<KEY_LEN>())
}

impl DocumentFile {
    /// The unlocked document key sealed under `wrapping_key` (XChaCha20-Poly1305, bound to this
    /// document's id), as hex `nonce || ciphertext`. The app keeps it in a biometry-protected
    /// Keychain item; it is useless without the device wrapping key and never holds the password.
    pub fn export_wrapped_key(&self, wrapping_key: &DocumentKey) -> Result<Zeroizing<String>> {
        let key = self.key()?;
        let (nonce, ct) = seal(wrapping_key, &wrap_aad(self.id), key.as_ref())?;
        Ok(Zeroizing::new(hex::encode([nonce, ct].concat())))
    }

    /// Unlock with a blob from [`Self::export_wrapped_key`]. Any mismatch is `VaultAuth`.
    pub fn unlock_with_wrapped_key(&mut self, blob: &str, wrapping_key: &DocumentKey) -> Result<()> {
        let raw = Zeroizing::new(hex::decode(blob.trim()).map_err(|_| CoreError::VaultAuth)?);
        if raw.len() <= NONCE_LEN {
            return Err(CoreError::VaultAuth);
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let plain = open_sealed(wrapping_key, &wrap_aad(self.id), nonce, ct)?;
        let key: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| CoreError::VaultAuth)?;
        self.unlock_with_key(Zeroizing::new(key))
    }
}

/// Hex form of a document key for a string-based platform key store.
pub fn key_to_hex(key: &DocumentKey) -> Zeroizing<String> {
    Zeroizing::new(hex::encode(key.as_ref()))
}

pub fn key_from_hex(s: &str) -> Result<DocumentKey> {
    let raw = Zeroizing::new(hex::decode(s.trim()).map_err(|_| CoreError::VaultAuth)?);
    let key: [u8; KEY_LEN] = raw.as_slice().try_into().map_err(|_| CoreError::VaultAuth)?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
#[path = "docfile_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "docfile_tolerant_tests.rs"]
mod tolerant_tests;
