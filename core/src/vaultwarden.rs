//! Vaultwarden / Bitwarden as a credential provider. Logs in with the account's master password
//! (password grant), syncs once, and keeps the login items in memory until `lock`. Only names
//! and usernames are kept decrypted; each password stays an EncString and is decrypted on
//! `fetch`, so no plaintext password cache sits in memory.
//! The master password and keys never touch disk; only `https://` servers are accepted, except
//! `http://` on loopback (a local test server).
//!
//! Crypto follows the Bitwarden client: master key = PBKDF2-SHA256 or Argon2id over the master
//! password (salt: e-mail), stretched with HKDF-Expand into an AES-256 key and an HMAC key; the
//! account's user key and every field are EncStrings of type 2 (`2.iv|ciphertext|mac`,
//! AES-256-CBC + HMAC-SHA256, encrypt-then-MAC). Organisation items need RSA org keys and are
//! skipped (counted in `skipped`).
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2_010::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::provider::{CredentialProvider, ProviderStatus};
use crate::vault::Secret;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// Refuse absurd KDF settings from a (possibly hostile) server.
const PBKDF2_ITERATIONS: std::ops::RangeInclusive<u32> = 5_000..=2_000_000;
const ARGON2_MEMORY_MIB: std::ops::RangeInclusive<u32> = 16..=1024;
const ARGON2_ITERATIONS: std::ops::RangeInclusive<u32> = 2..=10;
const ARGON2_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=16;
/// Bitwarden device type 7 = macOS desktop; Vaultwarden only records it.
const DEVICE_TYPE: &str = "7";
/// Sent as `Bitwarden-Client-Version`; servers log an auth error for requests without it.
const CLIENT_VERSION: &str = "2025.1.0";

/// Server-supplied key-derivation settings (`/identity/accounts/prelogin`).
#[derive(Debug, Clone, PartialEq)]
pub enum Kdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

/// A 64-byte symmetric key: AES-256 key then HMAC-SHA256 key.
pub(crate) struct SymKey {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl SymKey {
    fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 64 {
            return Err(CoreError::Corrupt(format!("symmetric key is {} bytes, expected 64", b.len())));
        }
        let (mut enc, mut mac) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
        enc.copy_from_slice(&b[..32]);
        mac.copy_from_slice(&b[32..]);
        Ok(SymKey { enc, mac })
    }
}

pub fn master_key(password: &str, email: &str, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    let email = email.trim().to_lowercase();
    let mut key = Zeroizing::new([0u8; 32]);
    match *kdf {
        Kdf::Pbkdf2 { iterations } => {
            if !PBKDF2_ITERATIONS.contains(&iterations) {
                return Err(CoreError::Invalid(format!("server asked for {iterations} PBKDF2 iterations")));
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), email.as_bytes(), iterations, key.as_mut());
        }
        Kdf::Argon2id { iterations, memory_mib, parallelism } => {
            if !ARGON2_ITERATIONS.contains(&iterations) || !ARGON2_MEMORY_MIB.contains(&memory_mib) || !ARGON2_PARALLELISM.contains(&parallelism) {
                return Err(CoreError::Invalid("server asked for Argon2 settings outside the allowed range".into()));
            }
            let salt = Sha256::digest(email.as_bytes());
            let params = argon2::Params::new(memory_mib * 1024, iterations, parallelism, Some(32)).map_err(|e| CoreError::Invalid(e.to_string()))?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt, key.as_mut())
                .map_err(|e| CoreError::Invalid(e.to_string()))?;
        }
    }
    Ok(key)
}

/// What the server stores and checks instead of the password: PBKDF2(master key, password, 1).
pub fn master_password_hash(master_key: &[u8; 32], password: &str) -> String {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, out.as_mut());
    B64.encode(out.as_ref())
}

fn stretch(master_key: &[u8; 32]) -> Result<SymKey> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(master_key).map_err(|_| CoreError::Invalid("bad master key".into()))?;
    let mut b = Zeroizing::new([0u8; 64]);
    hk.expand(b"enc", &mut b[..32]).map_err(|_| CoreError::Invalid("hkdf".into()))?;
    hk.expand(b"mac", &mut b[32..]).map_err(|_| CoreError::Invalid("hkdf".into()))?;
    SymKey::from_bytes(b.as_ref())
}

/// Decrypt a type-2 EncString. The MAC is checked (constant time) before decrypting.
pub(crate) fn decrypt(enc: &str, key: &SymKey) -> Result<Zeroizing<Vec<u8>>> {
    let body = enc.strip_prefix("2.").ok_or_else(|| CoreError::Corrupt("unsupported encryption type (only AES-CBC-256 + HMAC)".into()))?;
    let parts: Vec<&str> = body.split('|').collect();
    let [iv, ct, mac] = parts.as_slice() else { return Err(CoreError::Corrupt("malformed encrypted value".into())) };
    let dec = |s: &str| B64.decode(s).map_err(|_| CoreError::Corrupt("bad base64 in encrypted value".into()));
    let (iv, ct, mac) = (dec(iv)?, dec(ct)?, dec(mac)?);
    let mut m = HmacSha256::new_from_slice(key.mac.as_ref()).map_err(|_| CoreError::Invalid("hmac key".into()))?;
    m.update(&iv);
    m.update(&ct);
    m.verify_slice(&mac).map_err(|_| CoreError::Corrupt("encrypted value failed its integrity check".into()))?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| CoreError::Corrupt("bad IV length".into()))?;
    let plain = Aes256CbcDec::new(key.enc.as_ref().into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| CoreError::Corrupt("bad padding".into()))?;
    Ok(Zeroizing::new(plain))
}

fn decrypt_text(enc: &str, key: &SymKey) -> Result<String> {
    String::from_utf8(decrypt(enc, key)?.to_vec()).map_err(|_| CoreError::Corrupt("decrypted text is not UTF-8".into()))
}

/// Case-insensitive JSON field (Vaultwarden answers in PascalCase or camelCase by version).
fn field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v.as_object()?.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v)
}

fn field_str<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    field(v, name).and_then(Value::as_str)
}

fn field_u32(v: &Value, name: &str) -> Option<u32> {
    field(v, name).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok())
}

pub fn parse_kdf(prelogin: &Value) -> Result<Kdf> {
    let iterations = field_u32(prelogin, "kdfIterations").ok_or_else(|| CoreError::Corrupt("prelogin without kdfIterations".into()))?;
    match field_u32(prelogin, "kdf").unwrap_or(0) {
        0 => Ok(Kdf::Pbkdf2 { iterations }),
        1 => Ok(Kdf::Argon2id {
            iterations,
            memory_mib: field_u32(prelogin, "kdfMemory").unwrap_or(64),
            parallelism: field_u32(prelogin, "kdfParallelism").unwrap_or(4),
        }),
        other => Err(CoreError::Invalid(format!("unsupported KDF type {other}"))),
    }
}

/// A password still encrypted, with the key that opens it.
pub(crate) struct EncPassword {
    enc: String,
    key: Arc<SymKey>,
}

impl EncPassword {
    fn reveal(&self) -> Result<Secret> {
        Ok(Secret::new(decrypt_text(&self.enc, &self.key)?))
    }
}

/// One login item. Name and username are decrypted; the password is decrypted only on demand.
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    password: Option<EncPassword>,
}

/// Non-secret listing for the UI.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultItemInfo {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
}

pub struct SyncResult {
    pub items: Vec<VaultItem>,
    /// Organisation or undecryptable items left out.
    pub skipped: usize,
}

/// Decrypt the login items of an `/api/sync` response with the account's user key.
pub(crate) fn decrypt_sync(sync: &Value, user_key: &Arc<SymKey>) -> SyncResult {
    let mut items = Vec::new();
    let mut skipped = 0;
    for c in field(sync, "ciphers").and_then(Value::as_array).into_iter().flatten() {
        if field_u32(c, "type") != Some(1) {
            continue;
        }
        if field_str(c, "organizationId").is_some() {
            skipped += 1;
            continue;
        }
        match decrypt_cipher(c, user_key) {
            Ok(item) => items.push(item),
            Err(_) => skipped += 1,
        }
    }
    items.sort_by_key(|i| i.name.to_lowercase());
    SyncResult { items, skipped }
}

fn decrypt_cipher(c: &Value, user_key: &Arc<SymKey>) -> Result<VaultItem> {
    // Newer clients encrypt each item with its own key, itself encrypted with the user key.
    let key = match field_str(c, "key") {
        Some(k) => Arc::new(SymKey::from_bytes(&decrypt(k, user_key)?)?),
        None => Arc::clone(user_key),
    };
    let id = field_str(c, "id").ok_or_else(|| CoreError::Corrupt("item without id".into()))?.to_string();
    let name = decrypt_text(field_str(c, "name").unwrap_or_default(), &key)?;
    let login = field(c, "login");
    let opt = |n: &str| -> Result<Option<String>> { login.and_then(|l| field_str(l, n)).map(|s| decrypt_text(s, &key)).transpose() };
    let password = match login.and_then(|l| field_str(l, "password")) {
        // Check it opens now so a broken item is skipped at sync, not at connect time.
        Some(enc) => {
            decrypt(enc, &key)?;
            Some(EncPassword { enc: enc.to_string(), key: Arc::clone(&key) })
        }
        None => None,
    };
    Ok(VaultItem { id, name, username: opt("username")?, password })
}

/// Normalised server base URL (no trailing `/`), used by the Vaultwarden and HashiCorp Vault
/// providers. The address is parsed as a URL, so the host checked is the real authority (never
/// text before an `@`). Only `https://`, or `http://` to `localhost`, `127.0.0.1` or `[::1]`;
/// credentials in the address, queries and fragments are refused.
pub fn check_url(base: &str) -> Result<String> {
    let base = base.trim();
    let invalid = |why: &str| CoreError::Invalid(format!("server address {why}"));
    // The scheme must be written in lowercase, as typed elsewhere in the app; the parser would
    // otherwise normalise `HTTP://` and hide it from the check below.
    if !(base.starts_with("https://") || base.starts_with("http://")) {
        return Err(invalid("must start with https://"));
    }
    // URL parsers disagree on `\` (WHATWG reads it as `/`); refuse it rather than rely on one.
    if base.contains('\\') {
        return Err(invalid("must not contain \\"));
    }
    let url = url::Url::parse(base).map_err(|e| invalid(&format!("is not valid ({e})")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("must not contain a user name or password"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("must not contain ? or #"));
    }
    let host = url.host().ok_or_else(|| invalid("has no host"))?;
    if url.scheme() == "http" {
        let loopback = match host {
            url::Host::Domain(d) => d == "localhost",
            url::Host::Ipv4(ip) => ip == std::net::Ipv4Addr::LOCALHOST,
            url::Host::Ipv6(ip) => ip == std::net::Ipv6Addr::LOCALHOST,
        };
        if !loopback {
            return Err(CoreError::Invalid("Vaultwarden must be reached over https (http only on loopback)".into()));
        }
    } else if url.scheme() != "https" {
        return Err(invalid("must start with https://"));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn http_err(e: ureq::Error) -> CoreError {
    match e {
        ureq::Error::Status(400 | 401, r) => {
            let body: Value = r.into_json().unwrap_or(Value::Null);
            if field(&body, "TwoFactorProviders").is_some() || field(&body, "TwoFactorProviders2").is_some() {
                CoreError::TwoFactorRequired
            } else {
                CoreError::AuthFailed
            }
        }
        ureq::Error::Status(429, _) => CoreError::Invalid("too many login attempts; Vaultwarden asks to wait a minute".into()),
        ureq::Error::Status(code, _) => CoreError::Invalid(format!("Vaultwarden answered HTTP {code}")),
        ureq::Error::Transport(t) => CoreError::Invalid(format!("could not reach Vaultwarden: {t}")),
    }
}

fn json(r: std::result::Result<ureq::Response, ureq::Error>) -> Result<Value> {
    r.map_err(http_err)?.into_json().map_err(|e| CoreError::Corrupt(e.to_string()))
}

/// Bitwarden two-step provider id for authenticator apps (TOTP).
const TWO_FACTOR_AUTHENTICATOR: &str = "0";

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(HTTP_TIMEOUT).redirects(0).build()
}

/// A logged-in account, kept in memory only: the refresh token and the account key let
/// `resync` fetch items again without the master password. Dropped (and zeroized) on lock.
pub struct VaultwardenLogin {
    base: String,
    refresh_token: Zeroizing<String>,
    user_key: Arc<SymKey>,
}

impl VaultwardenLogin {
    /// Refresh the access token and sync again. A revoked or expired refresh token fails with
    /// `AuthFailed`; the caller then asks for the master password.
    pub fn resync(&mut self) -> Result<SyncResult> {
        let agent = agent();
        let token = json(agent.post(&format!("{}/identity/connect/token", self.base)).send_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "desktop"),
            ("refresh_token", self.refresh_token.as_str()),
        ]))?;
        let access = Zeroizing::new(field_str(&token, "access_token").ok_or(CoreError::AuthFailed)?.to_string());
        if let Some(r) = field_str(&token, "refresh_token") {
            self.refresh_token = Zeroizing::new(r.to_string());
        }
        sync(&agent, &self.base, &access, &self.user_key)
    }
}

fn sync(agent: &ureq::Agent, base: &str, access: &str, user_key: &Arc<SymKey>) -> Result<SyncResult> {
    let sync = json(
        agent
            .get(&format!("{base}/api/sync?excludeDomains=true"))
            .set("Authorization", &format!("Bearer {access}"))
            .set("Bitwarden-Client-Version", CLIENT_VERSION)
            .set("Device-Type", DEVICE_TYPE)
            .call(),
    )?;
    Ok(decrypt_sync(&sync, user_key))
}

/// Log in and sync. Blocking: call it off the UI thread. `device_id` should be stable per
/// install so the server does not record a new device on every unlock. An account with
/// two-step login fails with `TwoFactorRequired` until `totp` carries the current authenticator
/// code; the device is never remembered, so every unlock asks again.
pub fn login(base: &str, email: &str, password: &str, device_id: &str, totp: Option<&str>) -> Result<(SyncResult, VaultwardenLogin)> {
    let base = check_url(base)?;
    let agent = agent();
    let prelogin = json(agent.post(&format!("{base}/identity/accounts/prelogin")).send_json(serde_json::json!({ "email": email })))?;
    let mk = master_key(password, email, &parse_kdf(&prelogin)?)?;
    let hash = Zeroizing::new(master_password_hash(&mk, password));
    let mut form = vec![
        ("grant_type", "password"),
        ("username", email),
        ("password", hash.as_str()),
        ("scope", "api offline_access"),
        ("client_id", "desktop"),
        ("deviceType", DEVICE_TYPE),
        ("deviceIdentifier", device_id),
        ("deviceName", "Gantry"),
    ];
    let code = totp.map(|c| c.trim().replace(' ', ""));
    if let Some(code) = code.as_deref() {
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(CoreError::Invalid("an authenticator code is 6 digits".into()));
        }
        form.extend([("twoFactorToken", code), ("twoFactorProvider", TWO_FACTOR_AUTHENTICATOR), ("twoFactorRemember", "0")]);
    }
    let token = json(agent.post(&format!("{base}/identity/connect/token")).send_form(&form))?;
    let access = Zeroizing::new(field_str(&token, "access_token").ok_or(CoreError::AuthFailed)?.to_string());
    let refresh_token = Zeroizing::new(field_str(&token, "refresh_token").unwrap_or_default().to_string());
    let protected = field_str(&token, "Key").ok_or_else(|| CoreError::Corrupt("token response without the account key".into()))?;
    let user_key = Arc::new(SymKey::from_bytes(&decrypt(protected, &stretch(&mk)?)?)?);
    let result = sync(&agent, &base, &access, &user_key)?;
    Ok((result, VaultwardenLogin { base, refresh_token, user_key }))
}

/// `login` without two-step login, discarding the session (tests and one-shot use).
pub fn login_and_sync(base: &str, email: &str, password: &str, device_id: &str) -> Result<SyncResult> {
    Ok(login(base, email, password, device_id, None)?.0)
}

/// Serves Vaultwarden login items: `item` is the item id (password) or `<id>#username`.
#[derive(Default)]
pub struct VaultwardenProvider {
    items: Mutex<Option<BTreeMap<String, VaultItem>>>,
}

impl VaultwardenProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the unlocked items (after `login_and_sync`).
    pub fn unlock(&self, result: SyncResult) {
        let map = result.items.into_iter().map(|i| (i.id.clone(), i)).collect();
        *self.items.lock().unwrap_or_else(|e| e.into_inner()) = Some(map);
    }

    pub fn lock(&self) {
        *self.items.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn list(&self) -> Vec<VaultItemInfo> {
        let g = self.items.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<VaultItemInfo> =
            g.iter().flat_map(|m| m.values()).map(|i| VaultItemInfo { id: i.id.clone(), name: i.name.clone(), username: i.username.clone() }).collect();
        out.sort_by_key(|i| i.name.to_lowercase());
        out
    }
}

impl CredentialProvider for VaultwardenProvider {
    fn id(&self) -> &'static str {
        "vaultwarden"
    }
    fn status(&self) -> ProviderStatus {
        match self.items.lock() {
            Ok(g) if g.is_some() => ProviderStatus::Available,
            _ => ProviderStatus::Locked,
        }
    }
    fn fetch(&self, item: &str) -> Result<Secret> {
        let g = self.items.lock().map_err(|_| CoreError::Invalid("provider state poisoned".into()))?;
        let items = g.as_ref().ok_or(CoreError::VaultAuth)?;
        let (id, want_user) = match item.strip_suffix("#username") {
            Some(id) => (id, true),
            None => (item, false),
        };
        let i = items.get(id).ok_or_else(|| CoreError::NotFound(item.into()))?;
        if want_user {
            return i.username.clone().map(Secret::new).ok_or_else(|| CoreError::NotFound(item.into()));
        }
        i.password.as_ref().ok_or_else(|| CoreError::NotFound(item.into()))?.reveal()
    }
    fn store(&self, _: &str, _: &Secret) -> Result<()> {
        Err(CoreError::Invalid("Vaultwarden items are edited in Vaultwarden".into()))
    }
    fn delete(&self, _: &str) -> Result<()> {
        Err(CoreError::Invalid("Vaultwarden items are edited in Vaultwarden".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncryptMut;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    /// Test-side encryption, as a Bitwarden client would produce it.
    fn encrypt(plain: &[u8], key: &SymKey) -> String {
        let iv = [7u8; 16];
        let ct = Aes256CbcEnc::new(key.enc.as_ref().into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut m = HmacSha256::new_from_slice(key.mac.as_ref()).unwrap();
        m.update(&iv);
        m.update(&ct);
        format!("2.{}|{}|{}", B64.encode(iv), B64.encode(&ct), B64.encode(m.finalize().into_bytes()))
    }

    fn key(byte: u8) -> SymKey {
        SymKey::from_bytes(&[byte; 64]).unwrap()
    }

    #[test]
    fn encstring_round_trip_and_tamper_rejected() {
        let k = key(1);
        let e = encrypt(b"hunter2", &k);
        assert_eq!(decrypt(&e, &k).unwrap().as_slice(), b"hunter2");
        assert!(decrypt(&e, &key(2)).is_err(), "wrong key fails the MAC");
        let mut parts: Vec<String> = e.split('|').map(String::from).collect();
        parts[1] = B64.encode(b"0123456789abcdef");
        assert!(decrypt(&parts.join("|"), &k).is_err(), "changed ciphertext fails the MAC");
        assert!(decrypt("0.abc|def", &k).is_err(), "other encryption types are refused");
    }

    #[test]
    fn kdf_settings_are_parsed_and_bounded() {
        let v = serde_json::json!({"Kdf": 1, "KdfIterations": 3, "KdfMemory": 64, "KdfParallelism": 4});
        assert_eq!(parse_kdf(&v).unwrap(), Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 });
        assert_eq!(parse_kdf(&serde_json::json!({"kdf": 0, "kdfIterations": 600000})).unwrap(), Kdf::Pbkdf2 { iterations: 600_000 });
        assert!(master_key("pw", "a@b.c", &Kdf::Pbkdf2 { iterations: 1 }).is_err(), "weak server settings refused");
        assert!(master_key("pw", "a@b.c", &Kdf::Argon2id { iterations: 3, memory_mib: 100_000, parallelism: 4 }).is_err());
        // The e-mail is the salt, normalised.
        let kdf = Kdf::Pbkdf2 { iterations: 5000 };
        assert_eq!(*master_key("pw", " A@B.c ", &kdf).unwrap(), *master_key("pw", "a@b.c", &kdf).unwrap());
    }

    #[test]
    fn sync_decrypts_personal_logins_and_skips_org_items() {
        let mk = master_key("correct horse", "user@example.com", &Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
        let protected = encrypt(&[9u8; 64], &stretch(&mk).unwrap());
        let user_key = Arc::new(SymKey::from_bytes(&decrypt(&protected, &stretch(&mk).unwrap()).unwrap()).unwrap());
        let item_key = key(5);
        let sync = serde_json::json!({ "ciphers": [
            { "id": "a", "type": 1, "name": encrypt(b"db admin", &user_key),
              "login": { "username": encrypt(b"root", &user_key), "password": encrypt(b"s3cret", &user_key) } },
            { "Id": "b", "Type": 1, "Key": encrypt(&[5u8; 64], &user_key), "Name": encrypt(b"api", &item_key),
              "Login": { "Password": encrypt(b"tok", &item_key) } },
            { "id": "c", "type": 1, "organizationId": "org", "name": "2.x|y|z" },
            { "id": "d", "type": 2, "name": encrypt(b"a note", &user_key) },
        ]});
        let r = decrypt_sync(&sync, &user_key);
        assert_eq!(r.skipped, 1);
        let p = VaultwardenProvider::new();
        assert_eq!(p.status(), ProviderStatus::Locked);
        p.unlock(r);
        assert_eq!(p.list().iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), vec!["api", "db admin"]);
        assert_eq!(p.fetch("a").unwrap().expose(), "s3cret");
        assert_eq!(p.fetch("a#username").unwrap().expose(), "root");
        assert_eq!(p.fetch("b").unwrap().expose(), "tok");
        assert!(p.fetch("b#username").is_err());
        p.lock();
        assert!(p.fetch("a").is_err());
    }

    #[test]
    fn only_https_or_loopback_http() {
        assert!(check_url("https://vault.example.com/").is_ok());
        assert!(check_url("http://127.0.0.1:8080").is_ok());
        assert!(check_url("http://vault.example.com").is_err());
        assert!(check_url("http://127.0.0.1.evil.com").is_err());
        assert!(check_url("ftp://x").is_err());
        assert!(check_url("https://").is_err());
    }

    /// Codex C01: the host is the URL's real authority, not text before the first `/` or `:`.
    #[test]
    fn crafted_authorities_cannot_pass_as_loopback() {
        for bad in [
            "http://localhost:80@attacker.example",
            "http://127.0.0.1:8080@attacker.example/",
            "http://localhost@attacker.example",
            "http://user:pw@127.0.0.1:8080",
            "https://user:pw@vault.example.com",
            "http://localhost.attacker.example",
            "http://127.0.0.1\\@attacker.example",
            "https://vault.example.com/?x=1",
            "https://vault.example.com/#frag",
            "HTTP://attacker.example",
        ] {
            assert!(check_url(bad).is_err(), "{bad} must be refused");
        }
        assert_eq!(check_url(" https://Vault.Example.com/base/ ").unwrap(), "https://vault.example.com/base");
        assert_eq!(check_url("http://localhost:8200").unwrap(), "http://localhost:8200");
        assert_eq!(check_url("http://[::1]:8200/").unwrap(), "http://[::1]:8200");
        assert!(crate::hcvault::HcVaultProvider::new("http://localhost:80@attacker.example", crate::hcvault::KvVersion::V2, None).is_err());
    }

    /// Test fixture only: register `email` on a throwaway local server and add one login item,
    /// encrypting exactly as a Bitwarden client does (so the provider is checked against the
    /// server's real handling, not against itself alone).
    /// Returns an access token and the master-password hash for further setup calls.
    fn seed_account(url: &str, email: &str, pw: &str) -> (String, String) {
        let iterations = 600_000;
        let mk = master_key(pw, email, &Kdf::Pbkdf2 { iterations }).unwrap();
        let mut raw = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
        let user_key = SymKey::from_bytes(&raw).unwrap();
        let agent = ureq::agent();
        // Current servers register in two steps; with SIGNUPS_VERIFY=false the first returns the token.
        let verify = agent
            .post(&format!("{url}/identity/accounts/register/send-verification-email"))
            .send_json(serde_json::json!({ "email": email, "name": "Bastion test" }))
            .expect("send-verification-email")
            .into_string()
            .unwrap();
        let body = serde_json::json!({
            "email": email, "emailVerificationToken": verify.trim().trim_matches('"'),
            "masterPasswordHash": master_password_hash(&mk, pw),
            "userSymmetricKey": encrypt(&raw, &stretch(&mk).unwrap()), "kdf": 0, "kdfIterations": iterations,
        });
        if let Err(ureq::Error::Status(code, r)) = agent.post(&format!("{url}/identity/accounts/register/finish")).send_json(body) {
            panic!("register/finish {code}: {}", r.into_string().unwrap_or_default());
        }
        let token = json(agent.post(&format!("{url}/identity/connect/token")).send_form(&[
            ("grant_type", "password"), ("username", email), ("password", &master_password_hash(&mk, pw)),
            ("scope", "api offline_access"), ("client_id", "web"), ("deviceType", "9"),
            ("deviceIdentifier", "bastion-seed"), ("deviceName", "seed"),
        ])).expect("token");
        let access = field_str(&token, "access_token").unwrap();
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(access.split('.').nth(1).unwrap()).unwrap();
        let user_id = serde_json::from_slice::<Value>(&claims).unwrap()["sub"].as_str().unwrap().to_string();
        let cipher = serde_json::json!({ "type": 1, "encryptedFor": user_id, "name": encrypt(b"lab sshd", &user_key), "notes": null,
            "folderId": null, "organizationId": null, "favorite": false, "reprompt": 0, "fields": [], "passwordHistory": [],
            "login": { "username": encrypt(b"tester", &user_key), "password": encrypt(b"test-pass-123", &user_key), "uris": [], "totp": null } });
        if let Err(ureq::Error::Status(code, r)) = agent.post(&format!("{url}/api/ciphers")).set("Authorization", &format!("Bearer {access}")).send_json(cipher) {
            panic!("add cipher {code}: {}", r.into_string().unwrap_or_default());
        }
        (access.to_string(), master_password_hash(&mk, pw))
    }

    /// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) — what an authenticator app shows. Test-only.
    fn totp(secret: &[u8], unix: u64) -> String {
        let mut m = Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
        m.update(&(unix / 30).to_be_bytes());
        let h = m.finalize().into_bytes();
        let o = (h[19] & 0x0f) as usize;
        let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]) % 1_000_000;
        format!("{n:06}")
    }

    fn base32_decode(s: &str) -> Vec<u8> {
        const A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
        for c in s.trim_end_matches('=').chars() {
            buf = (buf << 5) | A.find(c.to_ascii_uppercase()).expect("base32") as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    /// The server refuses a code twice in one 30 s window (replay protection), so a login right
    /// after enabling waits for the next window.
    fn fresh_code(secret: &[u8]) -> String {
        let next = (now() / 30 + 1) * 30;
        std::thread::sleep(std::time::Duration::from_secs(next - now() + 1));
        totp(secret, now())
    }

    /// Live: a fresh account with authenticator two-step login on the same local server.
    /// No code → `TwoFactorRequired`; wrong code refused; right code unlocks; re-sync works
    /// with the in-memory refresh token and sees an item added after the unlock.
    #[test]
    fn live_vaultwarden_totp_and_resync() {
        let Ok(spec) = std::env::var("BASTION_VAULTWARDEN_TEST") else {
            eprintln!("SKIPPED live_vaultwarden_totp_and_resync: set BASTION_VAULTWARDEN_TEST=url,email,password");
            return;
        };
        let mut it = spec.splitn(3, ',');
        let (url, _, pw) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
        let email = format!("totp-{}@bastion.test", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let (access, hash) = seed_account(url, &email, pw);
        // The server proposes the key and a verification token; enabling proves a current code.
        let auth = |path: &str, body: Value| -> Value {
            match ureq::post(&format!("{url}/api/two-factor/{path}")).set("Authorization", &format!("Bearer {access}")).send_json(body) {
                Ok(r) => r.into_json().unwrap(),
                Err(ureq::Error::Status(code, r)) => panic!("{path} {code}: {}", r.into_string().unwrap_or_default()),
                Err(e) => panic!("{path}: {e}"),
            }
        };
        let proposal = auth("get-authenticator", serde_json::json!({ "masterPasswordHash": hash }));
        // Newer servers nest the proposal as {"authenticator": {"enabled", "key"}, "userVerificationToken"}.
        let key = field(&proposal, "authenticator").and_then(|a| field_str(a, "key")).or_else(|| field_str(&proposal, "key")).unwrap().to_string();
        let secret = base32_decode(&key);
        let enable = serde_json::json!({ "key": key, "token": totp(&secret, now()), "masterPasswordHash": hash,
            "userVerificationToken": field_str(&proposal, "userVerificationToken").unwrap_or_default() });
        let enabled = auth("authenticator", enable);
        let enabled = field(&enabled, "authenticator").unwrap_or(&enabled);
        assert_eq!(field(enabled, "enabled").and_then(Value::as_bool), Some(true));
        if std::env::var("BASTION_VAULTWARDEN_PRINT_TOTP").is_ok() {
            // Throwaway local test account only: lets a screenshot run answer the code prompt.
            eprintln!("TOTP_ACCOUNT {email} {key}");
        }
        assert!(matches!(login(url, &email, pw, "bastion-test", None), Err(CoreError::TwoFactorRequired)));
        let wrong = format!("{:06}", (totp(&secret, now()).parse::<u32>().unwrap() + 1) % 1_000_000);
        assert!(matches!(login(url, &email, pw, "bastion-test", Some(&wrong)), Err(CoreError::TwoFactorRequired | CoreError::AuthFailed)));
        assert!(login(url, &email, pw, "bastion-test", Some("12a456")).is_err(), "non-digit codes refused before sending");
        let (r, mut session) = login(url, &email, pw, "bastion-test", Some(&fresh_code(&secret))).expect("login with code");
        assert_eq!(r.items.len(), 1);
        // The device was not remembered: the next login asks for a code again.
        assert!(matches!(login(url, &email, pw, "bastion-test", None), Err(CoreError::TwoFactorRequired)));
        let again = session.resync().expect("re-sync with the refresh token, no password");
        assert_eq!(again.items.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), vec!["lab sshd"]);
    }

    /// Live: `BASTION_VAULTWARDEN_TEST=<url>,<email>,<password>` against a local Vaultwarden
    /// with at least one personal login item (`BASTION_VAULTWARDEN_SEED=1` creates both first).
    #[test]
    fn live_vaultwarden_login_and_sync() {
        let Ok(spec) = std::env::var("BASTION_VAULTWARDEN_TEST") else {
            eprintln!("SKIPPED live_vaultwarden_login_and_sync: set BASTION_VAULTWARDEN_TEST=url,email,password");
            return;
        };
        let mut it = spec.splitn(3, ',');
        let (url, email, pw) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
        if std::env::var("BASTION_VAULTWARDEN_SEED").is_ok() {
            seed_account(url, email, pw);
        }
        assert!(matches!(login_and_sync(url, email, "wrong password", "bastion-test"), Err(CoreError::AuthFailed)));
        let r = login_and_sync(url, email, pw, "bastion-test").unwrap();
        assert!(!r.items.is_empty(), "expected at least one login item");
        for i in &r.items {
            eprintln!("item {} name={} user={:?} has_password={}", i.id, i.name, i.username, i.password.is_some());
        }
        let p = VaultwardenProvider::new();
        let lab = r.items.iter().find(|i| i.name == "lab sshd").map(|i| i.id.clone());
        p.unlock(r);
        if let Some(id) = lab {
            assert_eq!(p.fetch(&format!("{id}#username")).unwrap().expose(), "tester");
            assert_eq!(p.fetch(&id).unwrap().expose(), "test-pass-123");
        }
    }
}
