//! Connection templates (B9, `docs/plans/B9-TEMPLATES.md`).
//!
//! A template is a normal [`Connection`] kept in [`Document::templates`], outside the tree, so
//! nothing that walks the tree (connect, search, bulk edit, status) can ever reach one. Fields
//! that accept `$Token$` placeholders: name, host (and web URL), port, username, notes, tags.
//! Token values are plain text from the "New from Template…" dialog: no secrets, no environment.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Connection, Document, Node};
use crate::properties;
use crate::vars::Variables;

/// Longest token value accepted (bytes).
pub const MAX_TOKEN_VALUE: usize = 1024;
const MAX_TOKEN_NAME: usize = 32;
const MAX_TOKENS: usize = 32;

/// A saved template. `port` holds the port as text so it may be a token (`$Port$`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Template {
    pub connection: Connection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
}

impl Template {
    pub fn id(&self) -> Uuid {
        self.connection.id
    }

    /// The token names in first-seen order, without duplicates (case-insensitive).
    pub fn tokens(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for text in self.token_fields() {
            for t in scan(text)? {
                if !out.iter().any(|o| o.eq_ignore_ascii_case(&t)) {
                    out.push(t);
                }
            }
        }
        if out.len() > MAX_TOKENS {
            return Err(CoreError::Invalid(format!("A template may have at most {MAX_TOKENS} tokens.")));
        }
        Ok(out)
    }

    fn token_fields(&self) -> Vec<&str> {
        let c = &self.connection;
        let mut v = vec![c.name.as_str(), c.host.as_str(), c.notes.as_str()];
        v.extend(self.port.as_deref());
        v.extend(c.settings.username.as_deref());
        v.extend(c.tags.iter().map(String::as_str));
        v
    }
}

/// Token names in `text`, using the `vars.rs` syntax (`$Name$`, `$$` is a literal `$`).
fn scan(text: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('$') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('$') else { break };
        let name = &after[..end];
        if !name.is_empty() {
            check_token_name(name)?;
            out.push(name.to_string());
        }
        rest = &after[end + 1..];
    }
    Ok(out)
}

fn check_token_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    if !first_ok || name.len() > MAX_TOKEN_NAME || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(CoreError::Invalid(format!(
            "Token `{name}`: use a letter, then letters, digits or _, at most {MAX_TOKEN_NAME} characters."
        )));
    }
    Ok(())
}

/// Refuse tokens anywhere but the token fields, so a credential or other setting is never
/// built from dialog text.
fn check_no_tokens_elsewhere(c: &Connection) -> Result<()> {
    let mut settings = c.settings.clone();
    settings.username = None;
    let rest = serde_json::to_string(&(&settings, &c.metadata)).map_err(|e| CoreError::Invalid(e.to_string()))?;
    let found = serde_json::from_str::<serde_json::Value>(&rest)
        .ok()
        .map(|v| strings(&v).into_iter().any(|s| scan(&s).map(|t| !t.is_empty()).unwrap_or(true)))
        .unwrap_or(false);
    if found {
        return Err(CoreError::Invalid(
            "Tokens are allowed only in name, computer name, port, username, notes and tags.".into(),
        ));
    }
    Ok(())
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a.iter().flat_map(strings).collect(),
        serde_json::Value::Object(o) => o.values().flat_map(strings).collect(),
        _ => vec![],
    }
}

/// The connection a template turns into with `vars`, every token field checked by the
/// normal property rules (same messages as an edit).
fn build(t: &Template, vars: &Variables) -> Result<Connection> {
    let src = &t.connection;
    let sub = |s: &str| vars.substitute(s, false);
    let mut c = Connection { id: Uuid::new_v4(), name: String::new(), host: String::new(), notes: String::new(), tags: vec![], ..src.clone() };
    c.settings.port = None;
    c.settings.username = None;
    c = properties::apply_field(&c, "name", Some(&sub(&src.name)?))?;
    c = properties::apply_field(&c, "host", Some(&sub(&src.host)?))?;
    if let Some(p) = &t.port {
        c = properties::apply_field(&c, "port", Some(&sub(p)?))?;
    } else {
        c.settings.port = src.settings.port;
    }
    if let Some(u) = &src.settings.username {
        c = properties::apply_field(&c, "username", Some(&sub(u)?))?;
    }
    c = properties::apply_field(&c, "notes", Some(&sub(&src.notes)?))?;
    let tags: Vec<String> = src.tags.iter().map(|t| sub(t)).collect::<Result<_>>()?;
    c = properties::apply_field(&c, "tags", Some(&tags.join(",")))?;
    properties::check_url_scheme(&c)?;
    Ok(c)
}

/// Template-mode check (design 4a): every token replaced by a harmless dummy, then the
/// normal rules. `https://$Host$:8443` passes; `file://$Host$` and a token in a password
/// field do not.
fn check_template(t: &Template) -> Result<()> {
    check_no_tokens_elsewhere(&t.connection)?;
    let mut vars = Variables::default();
    for name in t.tokens()? {
        vars.set(&name, if is_port_token(t, &name) { "1" } else { "example.invalid" });
    }
    build(t, &vars).map(|_| ())
}

fn is_port_token(t: &Template, name: &str) -> bool {
    t.port.as_deref().is_some_and(|p| scan(p).map(|v| v.iter().any(|n| n.eq_ignore_ascii_case(name))).unwrap_or(false))
}

/// A copy safe to keep as a template: new id, credential *reference* kept, confirmations
/// cleared, and secret values (Wake-on-LAN SecureOn password) dropped.
fn sanitised(c: &Connection) -> Connection {
    let mut copy = Connection { id: Uuid::new_v4(), favorite: false, ..c.clone() };
    copy.settings.wol_secureon = None;
    copy.settings.credential_confirmed = Vec::new();
    copy.settings.credential_unconfirmed = None;
    copy
}

impl Document {
    pub fn templates(&self) -> &[Template] {
        &self.templates
    }

    pub fn template(&self, id: Uuid) -> Result<&Template> {
        self.templates.iter().find(|t| t.id() == id).ok_or_else(|| CoreError::NotFound(id.to_string()))
    }

    /// "Save as Template…": copy connection `id` from the tree into the Templates list.
    pub fn save_as_template(&mut self, id: Uuid, name: &str) -> Result<Uuid> {
        let original = self.resolve(id)?.connection;
        let mut connection = sanitised(&original);
        connection.name = name.to_string();
        let port = connection.settings.port.map(|p| p.to_string());
        self.add_template(Template { connection, port })
    }

    /// Add a template after checking it (template mode, design 4a).
    pub fn add_template(&mut self, template: Template) -> Result<Uuid> {
        let mut t = Template { connection: sanitised(&template.connection), port: template.port };
        t.connection.id = template.connection.id;
        check_template(&t)?;
        if self.templates.iter().any(|x| x.id() == t.id()) {
            return Err(CoreError::Invalid("A template with this id already exists.".into()));
        }
        let id = t.id();
        self.templates.push(t);
        Ok(id)
    }

    /// Replace a template (same id). On error nothing changes.
    pub fn update_template(&mut self, template: Template) -> Result<()> {
        let id = template.id();
        let at = self.templates.iter().position(|t| t.id() == id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        let mut t = Template { connection: sanitised(&template.connection), port: template.port };
        t.connection.id = id;
        check_template(&t)?;
        self.templates[at] = t;
        Ok(())
    }

    pub fn delete_template(&mut self, id: Uuid) -> Result<()> {
        let before = self.templates.len();
        self.templates.retain(|t| t.id() != id);
        if self.templates.len() == before {
            return Err(CoreError::NotFound(id.to_string()));
        }
        Ok(())
    }

    /// The tokens "New from Template…" asks for, once each, in order.
    pub fn template_tokens(&self, id: Uuid) -> Result<Vec<String>> {
        self.template(id)?.tokens()
    }

    /// "New from Template…": a new connection under `parent` (root when `None`). Every token
    /// needs a value and no other value is accepted. Credential use starts unconfirmed (owner
    /// decision 2026-11-14), so the first connect asks. On error nothing is written.
    pub fn instantiate_template(&mut self, id: Uuid, values: &BTreeMap<String, String>, parent: Option<Uuid>) -> Result<Uuid> {
        let t = self.template(id)?.clone();
        let tokens = t.tokens()?;
        let vars = token_values(&tokens, values)?;
        let mut c = build(&t, &vars)?;
        c.settings.credential_confirmed = Vec::new();
        c.settings.credential_unconfirmed = c.settings.credential_id.map(|_| true);
        let new_id = c.id;
        self.insert(parent, Node::Connection(c))?;
        Ok(new_id)
    }
}

fn token_values(tokens: &[String], values: &BTreeMap<String, String>) -> Result<Variables> {
    let mut vars = Variables::default();
    for (k, v) in values {
        let Some(name) = tokens.iter().find(|t| t.eq_ignore_ascii_case(k)) else {
            return Err(CoreError::Invalid(format!("`{k}` is not a token of this template.")));
        };
        if v.len() > MAX_TOKEN_VALUE {
            return Err(CoreError::Invalid(format!("{name}: at most {MAX_TOKEN_VALUE} characters.")));
        }
        if v.chars().any(char::is_control) {
            return Err(CoreError::Invalid(format!("{name}: control characters are not allowed.")));
        }
        vars.set(name, v);
    }
    if let Some(missing) = tokens.iter().find(|t| !values.keys().any(|k| k.eq_ignore_ascii_case(t))) {
        return Err(CoreError::Invalid(format!("{missing}: a value is required.")));
    }
    Ok(vars)
}

#[cfg(test)]
#[path = "templates_tests.rs"]
mod tests;
