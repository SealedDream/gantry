//! HashiCorp Vault KV (v1 or v2) as a read-only credential provider.
//!
//! Every `fetch` asks the server; nothing is cached here, and the token lives only in memory
//! (cleared by [`HcVaultProvider::lock`]). Item format: `<mount>/<path>#<field>`, for example
//! `secret/prod/db#password`. `store` and `delete` are refused: Bastion never writes to Vault.
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::error::{CoreError, Result};
use crate::provider::{CredentialProvider, ProviderStatus};
use crate::vault::Secret;
use crate::vaultwarden::check_url;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvVersion {
    V1,
    V2,
}

pub struct HcVaultProvider {
    base: String,
    kv: KvVersion,
    namespace: Option<String>,
    token: Mutex<Option<Secret>>,
}

impl HcVaultProvider {
    /// `base` must be https (http only on loopback), like every other network provider.
    pub fn new(base: &str, kv: KvVersion, namespace: Option<String>) -> Result<Self> {
        Ok(HcVaultProvider { base: check_url(base)?, kv, namespace: namespace.filter(|n| !n.is_empty()), token: Mutex::new(None) })
    }

    pub fn unlock(&self, token: Secret) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(token);
    }

    pub fn lock(&self) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn url(&self, item: &str) -> Result<(String, String)> {
        let (path, field) = item.rsplit_once('#').ok_or_else(|| CoreError::Invalid("Vault item must be <mount>/<path>#<field>".into()))?;
        let (mount, rest) = path.trim_matches('/').split_once('/').ok_or_else(|| CoreError::Invalid("Vault item needs a mount and a path".into()))?;
        let bad = |s: &str| s.split('/').any(|p| p.is_empty() || p == "." || p == "..") || s.contains(['?', '%', ' ']);
        if bad(mount) || bad(rest) || field.is_empty() {
            return Err(CoreError::Invalid("Vault item path is not valid".into()));
        }
        let url = match self.kv {
            KvVersion::V1 => format!("{}/v1/{mount}/{rest}", self.base),
            KvVersion::V2 => format!("{}/v1/{mount}/data/{rest}", self.base),
        };
        Ok((url, field.to_string()))
    }
}

fn http_err(e: ureq::Error) -> CoreError {
    match e {
        ureq::Error::Status(401 | 403, _) => CoreError::AuthFailed,
        ureq::Error::Status(404, _) => CoreError::NotFound("Vault secret".into()),
        ureq::Error::Status(code, _) => CoreError::Invalid(format!("Vault answered HTTP {code}")),
        ureq::Error::Transport(t) => CoreError::Invalid(format!("could not reach Vault: {t}")),
    }
}

fn read_only() -> CoreError {
    CoreError::PolicyDenied("HashiCorp Vault is read-only in Gantry".into())
}

impl CredentialProvider for HcVaultProvider {
    fn id(&self) -> &'static str {
        "hcvault"
    }

    fn status(&self) -> ProviderStatus {
        match *self.token.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(_) => ProviderStatus::Available,
            None => ProviderStatus::Locked,
        }
    }

    fn fetch(&self, item: &str) -> Result<Secret> {
        let (url, field) = self.url(item)?;
        let token = self.token.lock().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(|| CoreError::Invalid("Vault is locked; sign in first".into()))?;
        let agent = ureq::AgentBuilder::new().timeout(HTTP_TIMEOUT).redirects(0).build();
        let mut req = agent.get(&url).set("X-Vault-Token", token.expose());
        if let Some(ns) = &self.namespace {
            req = req.set("X-Vault-Namespace", ns);
        }
        let body: Value = req.call().map_err(http_err)?.into_json().map_err(|e| CoreError::Corrupt(e.to_string()))?;
        let data = match self.kv {
            KvVersion::V1 => body.get("data"),
            KvVersion::V2 => body.get("data").and_then(|d| d.get("data")),
        };
        match data.and_then(|d| d.get(&field)) {
            Some(Value::String(s)) => Ok(Secret::new(s.clone())),
            Some(_) => Err(CoreError::Invalid(format!("Vault field {field} is not text"))),
            None => Err(CoreError::NotFound(format!("Vault field {field}"))),
        }
    }

    fn store(&self, _item: &str, _secret: &Secret) -> Result<()> {
        Err(read_only())
    }

    fn delete(&self, _item: &str) -> Result<()> {
        Err(read_only())
    }
}
