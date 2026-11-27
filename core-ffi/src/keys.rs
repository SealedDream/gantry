//! Key manager bridge (`bastion_core::keymanager`): generate ed25519, inspect and convert
//! OpenSSH / PEM / PuTTY `.ppk` keys. Results cross as JSON, the same shapes the C ABI returns:
//! info = `{"algorithm","fingerprint","comment","public_openssh","format","hardware"}`; generate
//! and convert add `"private_openssh"`, which the caller stores in the vault and never logs.
use bastion_core::keymanager::{self, ManagedKey};

use crate::{FfiError, FfiResult};

fn to_json<T: serde::Serialize>(v: &T) -> FfiResult<String> {
    serde_json::to_string(v).map_err(|e| FfiError::failed(e.to_string()))
}

/// A writer whose buffer is wiped whenever it grows or is dropped, so serializing a private
/// key leaves no stale copies in freed heap memory (F09).
struct WipingWriter(zeroize::Zeroizing<Vec<u8>>);

impl std::io::Write for WipingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let need = self.0.len() + buf.len();
        if need > self.0.capacity() {
            let mut grown = zeroize::Zeroizing::new(Vec::with_capacity(need.max(self.0.capacity() * 2)));
            grown.extend_from_slice(&self.0);
            self.0 = grown; // the old buffer is zeroized as it drops
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct WithPrivate<'a, T: serde::Serialize> {
    #[serde(flatten)]
    info: &'a T,
    private_openssh: &'a str,
}

/// Info plus `private_openssh`, serialized straight from the zeroizing key: no `Value` copy.
fn managed_json(key: ManagedKey) -> FfiResult<String> {
    let mut w = WipingWriter(zeroize::Zeroizing::new(Vec::with_capacity(key.private_openssh.len() * 2 + 512)));
    serde_json::to_writer(&mut w, &WithPrivate { info: &key.info, private_openssh: &key.private_openssh })
        .map_err(|e| FfiError::failed(e.to_string()))?;
    let bytes = std::mem::take(&mut *w.0);
    String::from_utf8(bytes).map_err(|e| FfiError::failed(e.to_string()))
}

/// A new ed25519 key; an empty or absent passphrase leaves it unencrypted.
#[uniffi::export]
pub fn keys_generate(comment: String, passphrase: Option<String>) -> FfiResult<String> {
    managed_json(keymanager::generate_ed25519(&comment, passphrase.as_deref())?)
}

/// Describe a private key file (needs its passphrase when encrypted).
#[uniffi::export]
pub fn keys_inspect(key_text: String, passphrase: Option<String>) -> FfiResult<String> {
    to_json(&keymanager::inspect(&key_text, passphrase.as_deref())?)
}

/// Import any supported key as OpenSSH under `new_passphrase`; empty `comment` keeps the key's own.
#[uniffi::export]
pub fn keys_convert(key_text: String, passphrase: Option<String>, new_passphrase: Option<String>, comment: String) -> FfiResult<String> {
    managed_json(keymanager::convert(&key_text, passphrase.as_deref(), new_passphrase.as_deref(), &comment)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_inspect_convert_round_trip() {
        let v: serde_json::Value = serde_json::from_str(&keys_generate("ffi".into(), Some("pw".into())).unwrap()).unwrap();
        assert_eq!(v["algorithm"], "ssh-ed25519");
        assert_eq!(v["format"], "openssh");
        let private = v["private_openssh"].as_str().unwrap().to_string();
        assert!(keys_inspect(private.clone(), None).is_err());
        let info: serde_json::Value = serde_json::from_str(&keys_inspect(private.clone(), Some("pw".into())).unwrap()).unwrap();
        assert_eq!(info["fingerprint"], v["fingerprint"]);
        assert!(info.get("private_openssh").is_none(), "inspect never returns key material");
        let out: serde_json::Value = serde_json::from_str(&keys_convert(private, Some("pw".into()), None, "new".into()).unwrap()).unwrap();
        assert_eq!(out["comment"], "new");
    }

    /// F09: the private key is written once, with the same JSON shape as before.
    #[test]
    fn managed_json_keeps_the_shape() {
        let v: serde_json::Value = serde_json::from_str(&keys_generate("shape".into(), None).unwrap()).unwrap();
        assert!(v["private_openssh"].as_str().unwrap().contains("OPENSSH PRIVATE KEY"));
        assert_eq!(v["comment"], "shape");
        assert!(v["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    }
}
