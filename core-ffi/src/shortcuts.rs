//! Keyboard shortcut bridge: the core's command list, chords and conflict rules, and the per-user
//! `shortcuts.json` next to the library. Chords cross as the core's neutral form
//! (`primary+shift+p`); the frontend renders them natively. `platform` is `macos` or `windows`.
use std::sync::Mutex;

use bastion_core::shortcuts::{self, Chord, Conflict, Platform, Shortcuts, ShortcutsStore};

use crate::{FfiError, FfiResult};

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct ShortcutView {
    /// The command's router target (`quick-connect`, `tab:3`, …).
    pub id: String,
    pub label: String,
    pub group: String,
    pub group_label: String,
    /// Current chord; `None` when the command has none.
    pub chord: Option<String>,
    pub default_chord: Option<String>,
    pub is_default: bool,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct ShortcutConflict {
    /// The command that has the chord; `None` when the system owns it.
    pub command_id: Option<String>,
    pub label: String,
}

fn platform(p: &str) -> FfiResult<Platform> {
    Ok(Platform::parse(p)?)
}

/// Ids of commands whose label, group or keywords contain every word of `query`.
#[uniffi::export]
pub fn search_shortcuts(query: String) -> Vec<String> {
    shortcuts::search(&query).into_iter().map(|d| d.id).collect()
}

/// `shortcuts.json`. A damaged file fails to open rather than being replaced by defaults.
#[derive(uniffi::Object)]
pub struct ShortcutsFile {
    store: ShortcutsStore,
    values: Mutex<Shortcuts>,
}

#[uniffi::export]
impl ShortcutsFile {
    #[uniffi::constructor]
    pub fn open(path: String) -> FfiResult<Self> {
        let store = ShortcutsStore::new(path);
        let values = Mutex::new(store.load()?);
        Ok(ShortcutsFile { store, values })
    }

    /// Every command in display order with its current chord.
    pub fn list(&self, platform: String) -> FfiResult<Vec<ShortcutView>> {
        let p = self::platform(&platform)?;
        let s = self.lock();
        Ok(shortcuts::definitions()
            .into_iter()
            .map(|d| ShortcutView {
                chord: s.chord(&d.id, p).map(|c| c.to_string()),
                default_chord: Some(d.default_on(p).to_string()).filter(|c| !c.is_empty()),
                is_default: s.is_default(&d.id),
                group: d.group.id().into(),
                group_label: d.group.label().into(),
                label: d.label,
                id: d.id,
            })
            .collect())
    }

    /// What `chord` would collide with if bound to `id`; an error when it is not a valid shortcut.
    pub fn conflict(&self, id: String, chord: String, platform: String) -> FfiResult<Option<ShortcutConflict>> {
        let c = Chord::parse(&chord)?;
        Ok(self.lock().conflict(&id, &c, self::platform(&platform)?).map(|c| match c {
            Conflict::Command { id, label } => ShortcutConflict { command_id: Some(id), label },
            Conflict::Reserved { label } => ShortcutConflict { command_id: None, label },
        }))
    }

    /// Bind (`None` removes the shortcut) and save. A chord another command has is refused
    /// unless `replace`, which takes it from that command. On error nothing changes.
    pub fn set(&self, id: String, chord: Option<String>, platform: String, replace: bool) -> FfiResult<()> {
        let p = self::platform(&platform)?;
        self.change(|s| s.set(&id, chord.as_deref(), p, replace).map_err(FfiError::from))
    }

    pub fn reset(&self, id: String) -> FfiResult<()> {
        self.change(|s| {
            s.reset(&id);
            Ok(())
        })
    }

    pub fn reset_all(&self) -> FfiResult<()> {
        self.change(|s| {
            s.reset_all();
            Ok(())
        })
    }

    /// Command ids sharing a chord with an earlier command (a hand-edited file); the frontend
    /// leaves them unbound and says so.
    pub fn shadowed(&self, platform: String) -> FfiResult<Vec<String>> {
        Ok(self.lock().conflicts(self::platform(&platform)?).into_iter().map(|(_, b)| b).collect())
    }
}

impl ShortcutsFile {
    fn lock(&self) -> std::sync::MutexGuard<'_, Shortcuts> {
        self.values.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn change(&self, body: impl FnOnce(&mut Shortcuts) -> FfiResult<()>) -> FfiResult<()> {
        let mut values = self.lock();
        let mut next = values.clone();
        body(&mut next)?;
        self.store.save(&next)?;
        *values = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(d: &tempfile::TempDir) -> ShortcutsFile {
        ShortcutsFile::open(d.path().join("shortcuts.json").to_string_lossy().into_owned()).unwrap()
    }

    fn chord(f: &ShortcutsFile, id: &str) -> Option<String> {
        f.list("macos".into()).unwrap().into_iter().find(|v| v.id == id).unwrap().chord
    }

    #[test]
    fn set_persists_and_conflicts_are_reported() {
        let d = tempfile::tempdir().unwrap();
        let f = open(&d);
        assert_eq!(chord(&f, "quick-connect").as_deref(), Some("primary+l"));
        let c = f.conflict("quick-connect".into(), "primary+d".into(), "macos".into()).unwrap().unwrap();
        assert_eq!((c.command_id.as_deref(), c.label.as_str()), (Some("split-right"), "Split Right"));
        assert!(f.conflict("quick-connect".into(), "primary+q".into(), "macos".into()).unwrap().unwrap().command_id.is_none());
        assert!(f.conflict("quick-connect".into(), "cmd+k".into(), "macos".into()).is_err());
        assert!(f.set("quick-connect".into(), Some("primary+d".into()), "macos".into(), false).is_err());
        f.set("quick-connect".into(), Some("primary+alt+j".into()), "macos".into(), false).unwrap();
        f.set("split-right".into(), None, "macos".into(), false).unwrap();
        let again = open(&d);
        assert_eq!(chord(&again, "quick-connect").as_deref(), Some("primary+alt+j"));
        assert_eq!(chord(&again, "split-right"), None);
        again.reset_all().unwrap();
        assert_eq!(chord(&open(&d), "split-right").as_deref(), Some("primary+d"));
        assert!(f.list("linux".into()).is_err());
    }

    #[test]
    fn shadowed_lists_the_later_command_of_a_hand_edited_pair() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("shortcuts.json"), r#"{"bindings":{"palette":"primary+l"}}"#).unwrap();
        assert_eq!(open(&d).shadowed("macos".into()).unwrap(), vec!["palette".to_string()]);
        assert_eq!(search_shortcuts("palette".into()), vec!["palette".to_string()]);
    }
}
