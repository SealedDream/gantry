//! Credentials of a kind this app does not know (`docs/specs/plugins-amendment-1.md`, A1-03a2.3).
//!
//! A newer app may add a credential kind (client certificates are planned). This reader keeps
//! such a credential exactly as read and writes it back unchanged, so one of them no longer
//! makes the whole vault, or the document that holds it, "corrupt". What is kept is secret
//! and untrusted: it is never interpreted, logged, released to a connection or exported; it
//! is wiped from memory on drop, and it is capped in size like `unknown`.
use serde::Deserialize;
use serde_json::value::RawValue;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::unknown::{MAX_UNKNOWN_ENTRY_BYTES, MAX_UNKNOWN_TOTAL_BYTES};

/// What the apps show in place of the user name of a credential this app cannot use.
pub const UNSUPPORTED_CREDENTIAL: &str = "Unsupported";
/// Why such a credential cannot be edited or used here (the answer to an edit).
pub const UNSUPPORTED_CREDENTIAL_DETAIL: &str = "This credential was saved by a newer version and can only be deleted here";

/// The credential kinds this app knows, as they are tagged in the vault.
const KNOWN_KINDS: [&str; 2] = ["Password", "SshKey"];
/// Longest unknown kind tag that is kept; it is made of ASCII letters and digits only.
const MAX_KIND_TAG_BYTES: usize = 64;

/// One credential of an unknown kind, kept byte for byte.
#[derive(Clone)]
pub struct UnknownCredential {
    pub id: Uuid,
    pub name: String,
    pub folder: Option<String>,
    pub owner: Option<Uuid>,
    raw: Zeroizing<String>,
}

impl UnknownCredential {
    /// The credential exactly as read, for writing back.
    pub(crate) fn raw(&self) -> Result<&RawValue> {
        serde_json::from_str(&self.raw).map_err(|e| CoreError::Invalid(e.to_string()))
    }
}

impl std::fmt::Debug for UnknownCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnknownCredential").field("id", &self.id).field("name", &self.name).finish_non_exhaustive()
    }
}

/// The fields every credential has, read without its kind.
#[derive(Deserialize)]
struct Head {
    id: Uuid,
    name: String,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    owner: Option<Uuid>,
    kind: Box<RawValue>,
}

/// The tag of an externally tagged kind: `"Tag"` or `{"Tag": …}`. Only the tag is read; the
/// value under it (the secret) stays raw.
fn kind_tag(kind: &RawValue) -> Option<String> {
    if let Ok(tag) = serde_json::from_str::<String>(kind.get()) {
        return Some(tag);
    }
    let map: std::collections::BTreeMap<String, &RawValue> = serde_json::from_str(kind.get()).ok()?;
    (map.len() == 1).then(|| map.into_keys().next()).flatten()
}

/// Read one credential that did not parse as a known kind. It is kept only when its kind tag
/// is well formed and unknown; a known kind that does not parse is still corrupt.
pub(crate) fn read_unknown(raw: Box<RawValue>, total: &mut usize) -> Result<UnknownCredential> {
    let raw: Zeroizing<String> = Zeroizing::new(String::from(Box::<str>::from(raw)));
    if raw.len() > MAX_UNKNOWN_ENTRY_BYTES {
        return Err(CoreError::Corrupt("a credential of an unknown kind is too large".into()));
    }
    *total += raw.len();
    if *total > MAX_UNKNOWN_TOTAL_BYTES {
        return Err(CoreError::Corrupt("too many credentials of an unknown kind".into()));
    }
    let head: Head = serde_json::from_str(&raw).map_err(|_| CoreError::Corrupt("a credential could not be read".into()))?;
    let well_formed = kind_tag(&head.kind)
        .is_some_and(|t| !t.is_empty() && t.len() <= MAX_KIND_TAG_BYTES && t.bytes().all(|b| b.is_ascii_alphanumeric()) && !KNOWN_KINDS.contains(&t.as_str()));
    // `head.kind` holds secret material: wipe it before it is freed.
    drop_raw(head.kind);
    if !well_formed {
        return Err(CoreError::Corrupt("a credential could not be read".into()));
    }
    Ok(UnknownCredential { id: head.id, name: head.name, folder: head.folder, owner: head.owner, raw })
}

/// Turn a raw value that parsed into a known credential into a wiped buffer, so the copy of the
/// secret in it does not linger.
pub(crate) fn drop_raw(raw: Box<RawValue>) {
    drop(Zeroizing::new(String::from(Box::<str>::from(raw))));
}

/// Split raw credentials into the ones this app knows and the ones it keeps unread.
pub(crate) fn read_list(list: Vec<Box<RawValue>>) -> Result<(Vec<crate::vault::Credential>, Vec<UnknownCredential>)> {
    let (mut known, mut unknown) = (Vec::new(), Vec::new());
    let mut unknown_bytes = 0;
    let mut ids = std::collections::HashSet::new();
    let mut items = list.into_iter();
    while let Some(raw) = items.next() {
        let id = match serde_json::from_str::<crate::vault::Credential>(raw.get()) {
            Ok(c) => {
                drop_raw(raw);
                let id = c.id;
                known.push(c);
                Ok(id)
            }
            Err(_) => read_unknown(raw, &mut unknown_bytes).map(|u| {
                let id = u.id;
                unknown.push(u);
                id
            }),
        };
        // Two credentials with one id would lose one of them at the next save: refuse the file.
        let id = id.and_then(|id| if ids.insert(id) { Ok(id) } else { Err(CoreError::Corrupt("two credentials have the same id".into())) });
        if let Err(e) = id {
            // Wipe the secrets still waiting in the list before they are freed.
            items.for_each(drop_raw);
            return Err(e);
        }
    }
    Ok((known, unknown))
}

/// One credential as written: a known one, or an unknown one byte for byte.
#[derive(serde::Serialize)]
#[serde(untagged)]
pub(crate) enum Out<'a> {
    Known(&'a crate::vault::Credential),
    Raw(&'a RawValue),
}

/// The credential list of a protected document (`docfile::Contents::credentials`): the known
/// credentials, used as a `Vec`, plus the unknown ones, kept and written back.
#[derive(Clone, Default)]
pub struct CredentialList {
    known: Vec<crate::vault::Credential>,
    unsupported: Vec<UnknownCredential>,
}

impl CredentialList {
    /// True when the document holds no credential at all, unknown ones included. Removing a
    /// document's password checks this, so unknown secrets are never written in the clear.
    pub fn is_empty(&self) -> bool {
        self.known.is_empty() && self.unsupported.is_empty()
    }
    /// The credentials of a kind this app cannot use (never exported or copied by an import).
    pub fn unsupported(&self) -> &[UnknownCredential] {
        &self.unsupported
    }
    /// Remove the credential `id`, known or not; true when one was removed.
    pub fn remove_id(&mut self, id: Uuid) -> bool {
        let before = self.known.len() + self.unsupported.len();
        self.known.retain(|c| c.id != id);
        self.unsupported.retain(|c| c.id != id);
        before != self.known.len() + self.unsupported.len()
    }
    /// Store `c`, replacing a known credential with the same id. An id taken by a credential of
    /// an unknown kind is refused: replacing it would destroy what a newer app saved.
    pub fn put(&mut self, c: crate::vault::Credential) -> Result<()> {
        if self.unsupported.iter().any(|u| u.id == c.id) {
            return Err(CoreError::Invalid(UNSUPPORTED_CREDENTIAL_DETAIL.into()));
        }
        self.known.retain(|k| k.id != c.id);
        self.known.push(c);
        Ok(())
    }

    /// Ids of every credential here, unknown ones included.
    pub fn ids(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.known.iter().map(|c| c.id).chain(self.unsupported.iter().map(|c| c.id))
    }
}

impl From<Vec<crate::vault::Credential>> for CredentialList {
    fn from(known: Vec<crate::vault::Credential>) -> Self {
        CredentialList { known, unsupported: Vec::new() }
    }
}

impl std::ops::Deref for CredentialList {
    type Target = Vec<crate::vault::Credential>;
    fn deref(&self) -> &Self::Target {
        &self.known
    }
}

impl serde::Serialize for CredentialList {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut seq = s.serialize_seq(Some(self.known.len() + self.unsupported.len()))?;
        for c in &self.known {
            seq.serialize_element(&Out::Known(c))?;
        }
        for c in &self.unsupported {
            seq.serialize_element(&Out::Raw(c.raw().map_err(S::Error::custom)?))?;
        }
        seq.end()
    }
}

impl<'de> serde::Deserialize<'de> for CredentialList {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let list = Vec::<Box<RawValue>>::deserialize(d)?;
        let (known, unsupported) = read_list(list).map_err(D::Error::custom)?;
        Ok(CredentialList { known, unsupported })
    }
}
