//! Bridge for triggers (`bastion_core::triggers`): the per-user rules in `triggers.json` and
//! applying them to a terminal (highlights on screen, notifications from new output).
use std::path::PathBuf;
use std::sync::Arc;

use bastion_core::triggers::{Highlight, Trigger, TriggerSet, TriggerStore};

use crate::{parse_id, FfiError, FfiResult, Terminal};

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TriggerView {
    /// Empty for a new trigger.
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub case_insensitive: bool,
    pub enabled: bool,
    /// Highlight matches on screen.
    pub highlight: bool,
    /// 0xRRGGBB, or `None` to keep the program's colour.
    pub fg: Option<u32>,
    pub bg: Option<u32>,
    pub bold: bool,
    /// Notify when a new line matches.
    pub notify: bool,
}

impl From<&Trigger> for TriggerView {
    fn from(t: &Trigger) -> Self {
        let h = t.highlight.unwrap_or_default();
        TriggerView {
            id: t.id.to_string(),
            name: t.name.clone(),
            pattern: t.pattern.clone(),
            case_insensitive: t.case_insensitive,
            enabled: t.enabled,
            highlight: t.highlight.is_some(),
            fg: h.fg,
            bg: h.bg,
            bold: h.bold,
            notify: t.notify,
        }
    }
}

impl TriggerView {
    fn to_core(&self) -> FfiResult<Trigger> {
        let id = if self.id.is_empty() { uuid::Uuid::new_v4() } else { parse_id(&self.id)? };
        Ok(Trigger {
            id,
            name: self.name.clone(),
            pattern: self.pattern.clone(),
            case_insensitive: self.case_insensitive,
            enabled: self.enabled,
            highlight: self.highlight.then_some(Highlight { fg: self.fg, bg: self.bg, bold: self.bold }),
            notify: self.notify,
        })
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TriggerEventView {
    pub trigger_id: String,
    pub name: String,
    pub line: String,
}

/// The triggers file. Each call reads it fresh, so several windows stay in step.
#[derive(uniffi::Object)]
pub struct TriggerLibrary {
    path: PathBuf,
}

impl TriggerLibrary {
    fn store(&self) -> FfiResult<TriggerStore> {
        Ok(TriggerStore::open(&self.path)?)
    }
}

#[uniffi::export]
impl TriggerLibrary {
    /// `path` is `triggers.json` beside the library; a missing file is an empty list.
    #[uniffi::constructor]
    pub fn open(path: String) -> FfiResult<Arc<Self>> {
        let lib = TriggerLibrary { path: PathBuf::from(path) };
        lib.store()?;
        Ok(Arc::new(lib))
    }

    pub fn list(&self) -> FfiResult<Vec<TriggerView>> {
        Ok(self.store()?.list().iter().map(Into::into).collect())
    }

    /// Add (empty id) or replace a trigger; returns its id.
    pub fn save(&self, trigger: TriggerView) -> FfiResult<String> {
        let t = trigger.to_core()?;
        let id = t.id.to_string();
        self.store()?.save(t)?;
        Ok(id)
    }

    pub fn remove(&self, id: String) -> FfiResult<()> {
        Ok(self.store()?.remove(parse_id(&id)?)?)
    }

    pub fn export_json(&self) -> FfiResult<String> {
        Ok(self.store()?.export_json())
    }

    /// Returns how many triggers the file held; an id or name already here is replaced.
    pub fn import_json(&self, json: String) -> FfiResult<u32> {
        Ok(u32::try_from(self.store()?.import_json(&json)?).unwrap_or(u32::MAX))
    }
}

#[uniffi::export]
impl Terminal {
    /// Apply the enabled triggers of `library` to this terminal (call again after edits), or turn
    /// them off with `None`.
    pub fn set_triggers(&self, library: Option<Arc<TriggerLibrary>>) -> FfiResult<()> {
        let set = match library {
            None => None,
            Some(l) => Some(Arc::new(TriggerSet::compile(l.store()?.list()).map_err(|e| FfiError::failed(e.to_string()))?)),
        };
        self.session().set_triggers(set);
        Ok(())
    }

    /// Notifications raised since the last call, oldest first.
    pub fn take_trigger_events(&self) -> Vec<TriggerEventView> {
        self.session().take_trigger_events().into_iter().map(|e| TriggerEventView { trigger_id: e.trigger_id.to_string(), name: e.name, line: e.line }).collect()
    }
}
