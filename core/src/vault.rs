//! Portable encrypted credential vault: Argon2id key derivation + XChaCha20-Poly1305 AEAD.
//! Platform keychains (macOS Keychain, Windows Credential Manager) wrap the vault key in the
//! frontends; this module never writes plaintext secrets to disk.
use std::collections::BTreeMap;
use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CoreError, Result};
use crate::vault_unknown::{read_list, Out, UnknownCredential};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CredentialKind {
    Password { username: String, password: Secret },
    SshKey { username: String, private_key: Secret, passphrase: Option<Secret> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub name: String,
    pub folder: Option<String>,
    /// Customer this credential belongs to; enforced by `Policy::check_credential_scope`.
    #[serde(default)]
    pub scope: Option<String>,
    /// Set for a connection's inline secret (`Vault::set_inline`): the connection it belongs to.
    /// Inline entries are not listed, never offered for other connections, and leave with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Uuid>,
    pub kind: CredentialKind,
}

/// Non-secret view used for search and UI listing.
#[derive(Clone, Debug, PartialEq)]
pub struct CredentialInfo {
    pub id: Uuid,
    pub name: String,
    pub folder: Option<String>,
    pub username: String,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    v: u32,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    m_cost: u32,
    t_cost: u32,
}

/// Decrypted layout once the vault has Credentials-section folders.
#[derive(Serialize)]
struct Plain<'a> {
    credentials: Vec<Out<'a>>,
    folders: Vec<&'a crate::credtree::CredentialFolder>,
    placement: &'a BTreeMap<Uuid, Uuid>,
}

#[derive(Deserialize)]
struct PlainOwned {
    credentials: Vec<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    folders: Vec<crate::credtree::CredentialFolder>,
    #[serde(default)]
    placement: BTreeMap<Uuid, Uuid>,
}

const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
/// Bounds applied to parameters read from a vault file, so a crafted file can neither demand
/// unbounded memory/time (DoS) nor be accepted with trivially weak settings.
const ARGON2_M_COST_RANGE: std::ops::RangeInclusive<u32> = 19 * 1024..=1024 * 1024;
const ARGON2_T_COST_RANGE: std::ops::RangeInclusive<u32> = 2..=10;

#[derive(Default)]
pub struct Vault {
    pub(crate) entries: BTreeMap<Uuid, Credential>,
    /// Credentials-section folders (`credtree`), by stable id.
    pub(crate) folders: BTreeMap<Uuid, crate::credtree::CredentialFolder>,
    /// Credential id → the folder it sits in; absent means the section root.
    pub(crate) placement: BTreeMap<Uuid, Uuid>,
    /// Credentials of a kind this app does not know, kept as read (`vault_unknown`).
    pub(crate) unsupported: BTreeMap<Uuid, UnknownCredential>,
}



impl Vault {
    /// Store `c` and return its id. An id taken by a credential of an unknown kind is never
        /// overwritten (that would destroy what a newer app saved): `c` then gets a new id.
    pub fn add(&mut self, mut c: Credential) -> Uuid {
        if self.unsupported.contains_key(&c.id) {
            c.id = Uuid::new_v4();
        }
        let id = c.id;
        self.entries.insert(id, c);
        id
    }
    pub fn get(&self, id: Uuid) -> Option<&Credential> {
        self.entries.get(&id)
    }
    pub fn remove(&mut self, id: Uuid) -> Option<Credential> {
        self.placement.remove(&id);
        self.unsupported.remove(&id);
        self.entries.remove(&id)
    }

    /// Whether `id` is a saved credential of a kind this app cannot use. It cannot be edited
    /// here (that would lose what a newer app wrote), only deleted.
    pub fn is_unsupported(&self, id: Uuid) -> bool {
        self.unsupported.get(&id).is_some_and(|c| c.owner.is_none())
    }

    /// Whether `id` is a connection's inline secret of an unknown kind (never listed or removed by id).
    pub fn is_unsupported_inline(&self, id: Uuid) -> bool {
        self.unsupported.get(&id).is_some_and(|c| c.owner.is_some())
    }

    /// The saved credentials of a kind this app cannot use, for listing. Their user name is
    /// [`crate::vault_unknown::UNSUPPORTED_CREDENTIAL`]; nothing of their secret is read.
    pub fn list_unsupported(&self) -> Vec<CredentialInfo> {
        self.unsupported
            .values()
            .filter(|c| c.owner.is_none())
            .map(|c| CredentialInfo {
                id: c.id,
                name: c.name.clone(),
                folder: self.folder_path(c.id).or_else(|| c.folder.clone()),
                username: crate::vault_unknown::UNSUPPORTED_CREDENTIAL.into(),
            })
            .collect()
    }
    pub fn list(&self) -> Vec<CredentialInfo> {
        self.entries
            .values()
            .filter(|c| c.owner.is_none())
            .map(|c| CredentialInfo {
                id: c.id,
                name: c.name.clone(),
                folder: self.folder_path(c.id).or_else(|| c.folder.clone()),
                username: match &c.kind {
                    CredentialKind::Password { username, .. } | CredentialKind::SshKey { username, .. } => username.clone(),
                },
            })
            .collect()
    }

    /// Store `kind` as the inline secret of `connection` (replacing any). Its id is the
    /// connection's id, so a `Vault` login with that id reads it like any saved credential.
    pub fn set_inline(&mut self, connection: Uuid, kind: CredentialKind) {
        self.entries.insert(connection, Credential { id: connection, name: "Inline".into(), folder: None, scope: None, owner: Some(connection), kind });
    }

    /// The inline secret of `connection`, if it has one.
    pub fn inline(&self, connection: Uuid) -> Option<&Credential> {
        self.entries.get(&connection).filter(|c| c.owner == Some(connection))
    }

    pub fn remove_inline(&mut self, connection: Uuid) -> bool {
        if self.inline(connection).is_none() {
            return false;
        }
        self.entries.remove(&connection).is_some()
    }

    /// Delete inline secrets whose connection is not in `live` (deleted connections); returns
    /// how many were removed.
    pub fn prune_inline(&mut self, live: &std::collections::BTreeSet<Uuid>) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, c| c.owner.is_none_or(|o| live.contains(&o)));
        // Inline credentials of an unknown kind are kept: a newer app may still need them.
        before - self.entries.len()
    }

    pub fn seal(&self, master: &str) -> Result<Vec<u8>> {
        Self::seal_plain(&self.to_plain()?, master)
    }

    /// Seal plaintext from [`Vault::to_plain`]. The Argon2id derivation takes 100-250 ms, so a caller that holds the
    /// vault behind a lock reads the plaintext under it and seals here without it (WIN-SSH-OPEN-STALL).
    pub fn seal_plain(plain: &[u8], master: &str) -> Result<Vec<u8>> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let key = derive(master, &salt, ARGON2_M_COST_KIB, ARGON2_T_COST)?;
        let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
            .encrypt(XNonce::from_slice(&nonce), plain)
            .map_err(|_| CoreError::Invalid("encryption failed".into()))?;
        let sealed = Sealed {
            v: 1,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            ciphertext,
            m_cost: ARGON2_M_COST_KIB,
            t_cost: ARGON2_T_COST,
        };
        serde_json::to_vec(&sealed).map_err(|e| CoreError::Invalid(e.to_string()))
    }

    pub fn open(bytes: &[u8], master: &str) -> Result<Vault> {
        let sealed: Sealed = serde_json::from_slice(bytes).map_err(|e| CoreError::Corrupt(e.to_string()))?;
        if sealed.nonce.len() != 24 {
            return Err(CoreError::Corrupt("bad nonce".into()));
        }
        if !ARGON2_M_COST_RANGE.contains(&sealed.m_cost) || !ARGON2_T_COST_RANGE.contains(&sealed.t_cost) {
            return Err(CoreError::Corrupt("vault key-derivation parameters out of allowed range".into()));
        }
        let key = derive(master, &sealed.salt, sealed.m_cost, sealed.t_cost)?;
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new(key.as_ref().into())
                .decrypt(XNonce::from_slice(&sealed.nonce), sealed.ciphertext.as_slice())
                .map_err(|_| CoreError::VaultAuth)?,
        );
        Self::from_plain(&plain)
    }

    /// The vault's plaintext (credentials, folders, placement), for sealing inside a document.
    pub fn to_plain(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut entries: Vec<Out<'_>> = self.entries.values().map(Out::Known).collect();
        for c in self.unsupported.values() {
            entries.push(Out::Raw(c.raw()?));
        }
        // A vault without Credentials-section folders keeps the original array layout, so an
        // older build can still open it.
        let plain = if self.folders.is_empty() && self.placement.is_empty() {
            serde_json::to_vec(&entries)
        } else {
            serde_json::to_vec(&Plain { credentials: entries, folders: self.folders.values().collect(), placement: &self.placement })
        };
        Ok(Zeroizing::new(plain.map_err(|e| CoreError::Invalid(e.to_string()))?))
    }

    /// Inverse of [`Vault::to_plain`].
    pub fn from_plain(plain: &[u8]) -> Result<Vault> {
        let (list, folders, placement) = match serde_json::from_slice::<Vec<Box<serde_json::value::RawValue>>>(plain) {
            Ok(list) => (list, Vec::new(), BTreeMap::new()),
            Err(_) => {
                let p: PlainOwned = serde_json::from_slice(plain).map_err(|e| CoreError::Corrupt(e.to_string()))?;
                (p.credentials, p.folders, p.placement)
            }
        };
        let (known, unknown) = read_list(list)?;
        let entries: BTreeMap<Uuid, Credential> = known.into_iter().map(|c| (c.id, c)).collect();
        let unsupported: BTreeMap<Uuid, UnknownCredential> = unknown.into_iter().map(|c| (c.id, c)).collect();
        let mut vault = Vault { entries, folders: folders.into_iter().map(|f| (f.id, f)).collect(), placement, unsupported };
        vault.repair_tree();
        Ok(vault)
    }

    pub fn len(&self) -> usize {
        self.entries.len() + self.unsupported.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.unsupported.is_empty()
    }
    /// Every credential id (named and inline), for migration checks.
    pub fn ids(&self) -> std::collections::BTreeSet<Uuid> {
        self.entries.keys().chain(self.unsupported.keys()).copied().collect()
    }
}

fn derive(master: &str, salt: &[u8], m_cost: u32, t_cost: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_cost, t_cost, 1, Some(32)).map_err(|e| CoreError::Invalid(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(master.as_bytes(), salt, key.as_mut())
        .map_err(|e| CoreError::Invalid(e.to_string()))?;
    Ok(key)
}

/// Rough strength estimate in bits (charset size × length). For UI indicators only.
pub fn strength_bits(pw: &str) -> f64 {
    let classes: [(fn(&char) -> bool, u32); 4] = [
        (|c| c.is_ascii_lowercase(), 26),
        (|c| c.is_ascii_uppercase(), 26),
        (|c| c.is_ascii_digit(), 10),
        (|c| !c.is_ascii_alphanumeric(), 33),
    ];
    let pool: u32 = classes.iter().filter(|(f, _)| pw.chars().any(|c| f(&c))).map(|(_, n)| n).sum();
    if pool == 0 {
        return 0.0;
    }
    pw.chars().count() as f64 * (pool as f64).log2()
}

pub fn generate_password(len: usize) -> Secret {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
    let mut out = String::with_capacity(len);
    let mut rng = rand::rngs::OsRng;
    while out.len() < len {
        let b = (rng.next_u32() & 0x7f) as usize;
        // Rejection sampling avoids modulo bias.
        if b < CHARS.len() {
            out.push(CHARS[b] as char);
        }
    }
    Secret(out)
}
