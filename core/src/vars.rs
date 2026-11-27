//! `$Name$`-style variable substitution for tasks, with a guard against leaking secrets.
use std::collections::BTreeMap;

use crate::error::{CoreError, Result};

#[derive(Default)]
pub struct Variables {
    plain: BTreeMap<String, String>,
    secret: BTreeMap<String, String>,
    /// Environment variables a template may read via `$ENV:NAME$`. Empty by default so a
    /// task cannot exfiltrate arbitrary environment secrets (e.g. cloud credentials).
    allowed_env: std::collections::BTreeSet<String>,
}

impl Variables {
    pub fn set(&mut self, k: &str, v: &str) {
        self.plain.insert(k.to_uppercase(), v.into());
    }
    pub fn set_secret(&mut self, k: &str, v: &str) {
        self.secret.insert(k.to_uppercase(), v.into());
    }
    pub fn allow_env(&mut self, name: &str) {
        self.allowed_env.insert(name.to_string());
    }

    /// Substitute `$VAR$` (and `$ENV:NAME$`). Secret variables are refused unless
    /// `allow_secrets` is set by an explicit, user-authorized task setting. Unknown
    /// variables are an error rather than silently becoming empty. `$$` is a literal `$`.
    pub fn substitute(&self, template: &str, allow_secrets: bool) -> Result<String> {
        let mut out = String::new();
        let mut rest = template;
        while let Some(start) = rest.find('$') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('$') else {
                out.push_str(&rest[start..]);
                return Ok(out);
            };
            let name = &after[..end];
            if name.is_empty() {
                out.push('$');
            } else {
                out.push_str(&self.lookup(name, allow_secrets)?);
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    fn lookup(&self, name: &str, allow_secrets: bool) -> Result<String> {
        let key = name.to_uppercase();
        if let Some(v) = self.plain.get(&key) {
            return Ok(v.clone());
        }
        if let Some(v) = self.secret.get(&key) {
            return if allow_secrets { Ok(v.clone()) } else { Err(CoreError::SecretLeak(name.into())) };
        }
        if let Some(env) = name.strip_prefix("ENV:") {
            if !self.allowed_env.contains(env) {
                return Err(CoreError::Invalid(format!("environment variable `{env}` is not allowlisted for tasks")));
            }
            if let Ok(v) = std::env::var(env) {
                return Ok(v);
            }
        }
        Err(CoreError::Invalid(format!("unknown variable `{name}`")))
    }

    /// Replace any secret value appearing in `text` (task output, logs) with `***`.
    pub fn redact(&self, text: &str) -> String {
        self.secret
            .values()
            .filter(|s| !s.is_empty())
            .fold(text.to_string(), |acc, s| acc.replace(s.as_str(), "***"))
    }
}
