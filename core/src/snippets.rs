//! Command snippets: named text the user sends to a terminal (the focused one, or every tab in a
//! broadcast). Stored in `snippets.json` next to `settings.json`, owner-only. Snippets are typed
//! into the shell like a paste, so the frontend confirms multi-line ones; they never run on their
//! own and never hold secrets on purpose (a snippet that looks like one is refused).
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

const MAX_NAME: usize = 80;
const MAX_TEXT: usize = 16 * 1024;
pub const MAX_SNIPPETS: usize = 500;
const MAX_FILE: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    pub id: String,
    pub name: String,
    pub text: String,
}

impl Snippet {
    /// More than one line: sending it may run several commands at once.
    pub fn is_multiline(&self) -> bool {
        self.text.trim_end_matches(['\n', '\r']).contains(['\n', '\r'])
    }
}

pub struct SnippetStore {
    path: PathBuf,
    items: Vec<Snippet>,
}

impl SnippetStore {
    pub fn file(dir: &Path) -> PathBuf {
        dir.join("snippets.json")
    }

    pub fn open(path: PathBuf) -> Result<SnippetStore> {
        let items = match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
            Ok(m) if m.len() > MAX_FILE => return Err(CoreError::Invalid("snippets.json is too large".into())),
            Ok(_) => serde_json::from_slice(&std::fs::read(&path)?).map_err(|e| CoreError::Corrupt(format!("snippets.json: {e}")))?,
        };
        Ok(SnippetStore { path, items })
    }

    /// By name, case-insensitively.
    pub fn list(&self) -> Vec<Snippet> {
        let mut v = self.items.clone();
        v.sort_by_key(|s| s.name.to_lowercase());
        v
    }

    /// Name contains every word of `query` (case-insensitive); empty query lists all.
    pub fn search(&self, query: &str) -> Vec<Snippet> {
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        self.list().into_iter().filter(|s| words.iter().all(|w| s.name.to_lowercase().contains(w) || s.text.to_lowercase().contains(w))).collect()
    }

    /// Add (empty `id`) or replace a snippet; returns its id.
    pub fn put(&mut self, name: &str, text: &str, id: Option<&str>) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
            return Err(CoreError::Invalid(format!("Snippet name must be 1 to {MAX_NAME} characters.")));
        }
        if text.trim().is_empty() || text.len() > MAX_TEXT {
            return Err(CoreError::Invalid(format!("Snippet text must be 1 to {MAX_TEXT} bytes.")));
        }
        if looks_secret(text) {
            return Err(CoreError::Invalid("This looks like it contains a password or key. Keep secrets in the vault, not in snippets.".into()));
        }
        if self.items.iter().any(|s| Some(s.id.as_str()) != id && s.name.eq_ignore_ascii_case(name)) {
            return Err(CoreError::Invalid(format!("A snippet named {name} already exists.")));
        }
        let mut next = self.items.clone();
        let id = match id {
            Some(id) => {
                let slot = next.iter_mut().find(|s| s.id == id).ok_or_else(|| CoreError::NotFound(format!("snippet {id}")))?;
                *slot = Snippet { id: id.to_string(), name: name.into(), text: text.into() };
                id.to_string()
            }
            None => {
                if next.len() >= MAX_SNIPPETS {
                    return Err(CoreError::Invalid(format!("At most {MAX_SNIPPETS} snippets.")));
                }
                let id = uuid::Uuid::new_v4().to_string();
                next.push(Snippet { id: id.clone(), name: name.into(), text: text.into() });
                id
            }
        };
        self.save(next)?;
        Ok(id)
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        let next: Vec<Snippet> = self.items.iter().filter(|s| s.id != id).cloned().collect();
        if next.len() == self.items.len() {
            return Err(CoreError::NotFound(format!("snippet {id}")));
        }
        self.save(next)
    }

    fn save(&mut self, next: Vec<Snippet>) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&next).map_err(|e| CoreError::Corrupt(e.to_string()))?;
        crate::store::write_atomic(&self.path, &bytes)?;
        self.items = next;
        Ok(())
    }
}

/// Obvious secrets in a snippet: key blocks, inline passwords. A heuristic, not a guarantee.
pub fn looks_secret(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    ["-----begin", "private key", "password=", "passwd=", "pwd=", "--password", "sshpass -p", "token=", "secret=", "api_key=", "apikey="]
        .iter()
        .any(|p| t.contains(p))
}
