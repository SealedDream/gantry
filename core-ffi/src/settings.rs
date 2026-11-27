//! Settings bridge: the core definitions (categories, controls, validation, search) and the
//! per-user `settings.json`. Every `set` is validated by the core and saved at once.
use std::sync::Mutex;

use bastion_core::settings::{self, Category, Kind, SettingDef, Settings as CoreSettings, SettingsStore};

use crate::FfiResult;

#[derive(uniffi::Record)]
pub struct SettingCategoryView {
    pub id: String,
    pub label: String,
    pub icon: String,
}

#[derive(uniffi::Record)]
pub struct SettingOptionView {
    pub id: String,
    pub label: String,
}

#[derive(uniffi::Record)]
pub struct SettingDefView {
    pub id: String,
    pub category: String,
    pub label: String,
    pub help: String,
    /// `choice`, `toggle`, `integer` or `link`.
    pub kind: String,
    pub options: Vec<SettingOptionView>,
    pub min: i64,
    pub max: i64,
    pub unit: String,
    pub default_value: String,
    /// For `link`: the page or command the frontend opens.
    pub link: Option<String>,
}

fn view(d: SettingDef) -> SettingDefView {
    let (kind, options, min, max, unit, link) = match d.kind {
        Kind::Choice(o) => ("choice", o.iter().map(|(id, label)| SettingOptionView { id: id.to_string(), label: label.to_string() }).collect(), 0, 0, "", None),
        Kind::Toggle => ("toggle", vec![], 0, 0, "", None),
        Kind::Integer { min, max, unit } => ("integer", vec![], min, max, unit, None),
        Kind::Link(t) => ("link", vec![], 0, 0, "", Some(t.to_string())),
        Kind::Text { max_len, multiline } => (if multiline { "multiline" } else { "text" }, vec![], 0, max_len as i64, "", None),
    };
    SettingDefView {
        id: d.id.into(),
        category: d.category.id().into(),
        label: d.label.into(),
        help: d.help.into(),
        kind: kind.into(),
        options,
        min,
        max,
        unit: unit.into(),
        default_value: d.default.into(),
        link,
    }
}

fn refs(links: &[String]) -> Vec<&str> {
    links.iter().map(String::as_str).collect()
}

/// Categories to list, given the link targets this frontend handles.
#[uniffi::export]
pub fn setting_categories(handled_links: Vec<String>) -> Vec<SettingCategoryView> {
    settings::categories(&refs(&handled_links))
        .into_iter()
        .map(|c: Category| SettingCategoryView { id: c.id().into(), label: c.label().into(), icon: c.icon().into() })
        .collect()
}

/// Every visible setting, in display order.
#[uniffi::export]
pub fn setting_definitions(handled_links: Vec<String>) -> Vec<SettingDefView> {
    settings::visible(&refs(&handled_links)).into_iter().map(view).collect()
}

/// Ids of visible settings matching every word of `query`.
#[uniffi::export]
pub fn search_settings(query: String, handled_links: Vec<String>) -> Vec<String> {
    settings::search(&query, &refs(&handled_links)).into_iter().map(|d| d.id.to_string()).collect()
}

/// Whether credentials should lock for this `security.auto-lock` value after `idle_secs` without
/// input — or because a managed inactivity limit was reached, whatever the user chose (TM-03).
#[uniffi::export]
pub fn auto_lock_due(value: String, idle_secs: u64) -> bool {
    auto_lock_due_with(&value, idle_secs, crate::policy::managed_inactivity_secs())
}

fn auto_lock_due_with(value: &str, idle_secs: u64, managed_secs: Option<u64>) -> bool {
    let managed = bastion_core::policy::Policy { inactivity_lock_secs: managed_secs, ..Default::default() };
    match managed_secs {
        Some(_) => settings::auto_lock_due_under(value, idle_secs, &managed),
        None => settings::auto_lock_due(value, idle_secs),
    }
}

/// Seconds a copied password stays on the clipboard (A3-S1), read from `settings.json` at `path`
/// now, at copy time. A file that cannot be read gives the shortest lifetime, never a longer one.
#[uniffi::export]
pub fn secret_clipboard_seconds(path: String) -> u64 {
    let stored = SettingsStore::new(path).load().and_then(|s| s.get(settings::SECRET_CLIPBOARD_SETTING)).ok();
    settings::secret_clipboard_seconds(stored.as_deref())
}

#[cfg(test)]
mod managed_idle_tests {
    use super::auto_lock_due_with;

    /// TM-03: a managed limit locks the vault even when the user turned auto-lock off.
    #[test]
    fn managed_inactivity_locks_whatever_the_user_chose() {
        assert!(!auto_lock_due_with("off", 1_000_000, None));
        assert!(auto_lock_due_with("off", 60, Some(60)));
        assert!(!auto_lock_due_with("off", 59, Some(60)));
        assert!(auto_lock_due_with("60", 120, Some(120)), "the stricter of the two wins");
        assert!(auto_lock_due_with("1", 60, Some(3_600)), "the user's shorter value still applies");
    }
}

/// `settings.json` next to the library.
#[derive(uniffi::Object)]
pub struct SettingsFile {
    store: SettingsStore,
    values: Mutex<CoreSettings>,
}

#[uniffi::export]
impl SettingsFile {
    /// Fails on a damaged file rather than replacing it with defaults.
    #[uniffi::constructor]
    pub fn open(path: String) -> FfiResult<Self> {
        let store = SettingsStore::new(path);
        let values = Mutex::new(store.load()?);
        Ok(SettingsFile { store, values })
    }

    /// True while the file does not exist (nothing saved yet).
    pub fn is_new(&self) -> bool {
        !self.store.exists()
    }

    pub fn get(&self, id: String) -> FfiResult<String> {
        Ok(self.lock().get(&id)?)
    }

    /// Validate, store and save; on error nothing changes.
    pub fn set(&self, id: String, value: String) -> FfiResult<()> {
        let mut values = self.lock();
        let mut next = values.clone();
        next.set(&id, &value)?;
        self.store.save(&next)?;
        *values = next;
        Ok(())
    }

    /// Several values in one save (used once to import pre-existing preferences).
    pub fn set_many(&self, values: std::collections::HashMap<String, String>) -> FfiResult<()> {
        let mut current = self.lock();
        let mut next = current.clone();
        for (id, value) in &values {
            next.set(id, value)?;
        }
        self.store.save(&next)?;
        *current = next;
        Ok(())
    }
}

impl SettingsFile {
    fn lock(&self) -> std::sync::MutexGuard<'_, CoreSettings> {
        self.values.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_persists_and_rejects_invalid_values() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json").to_string_lossy().into_owned();
        let f = SettingsFile::open(path.clone()).unwrap();
        assert!(f.is_new());
        f.set("terminal.font-size".into(), "15".into()).unwrap();
        assert!(f.set("terminal.font-size".into(), "99".into()).is_err());
        let back = SettingsFile::open(path).unwrap();
        assert!(!back.is_new());
        assert_eq!(back.get("terminal.font-size".into()).unwrap(), "15");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn definitions_carry_controls_and_links() {
        let defs = setting_definitions(vec!["credential-manager".into()]);
        let size = defs.iter().find(|d| d.id == "terminal.font-size").unwrap();
        assert_eq!((size.kind.as_str(), size.min, size.max), ("integer", 9, 24));
        assert!(defs.iter().any(|d| d.link.as_deref() == Some("credential-manager")));
        assert!(!defs.iter().any(|d| d.link.as_deref() == Some("vaultwarden")), "unhandled link hidden");
        assert_eq!(search_settings("font".into(), vec![]), vec!["terminal.font-size".to_string()]);
    }

    /// A3-S1: the copied-password lifetime, and the shortest one when settings cannot be read.
    #[test]
    fn secret_clipboard_lifetime_follows_the_setting_and_fails_short() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json").to_string_lossy().into_owned();
        assert_eq!(secret_clipboard_seconds(path.clone()), 60, "no file yet: the default");
        let f = SettingsFile::open(path.clone()).unwrap();
        f.set("security.clipboard-clear-seconds".into(), "30".into()).unwrap();
        assert_eq!(secret_clipboard_seconds(path.clone()), 30, "read at copy time, from the file");
        f.set("security.clipboard-clear-seconds".into(), "45".into()).unwrap();
        assert_eq!(secret_clipboard_seconds(path.clone()), 45);
        std::fs::write(&path, b"{ not json").unwrap();
        assert_eq!(secret_clipboard_seconds(path.clone()), 30, "a damaged file: the shortest lifetime");
        std::fs::remove_dir_all(&dir).unwrap();
        let defs = setting_definitions(vec!["secret-clipboard-lifetime".into()]);
        let d = defs.iter().find(|d| d.id == "security.clipboard-clear-seconds").unwrap();
        assert_eq!((d.kind.as_str(), d.default_value.as_str(), d.options.len()), ("choice", "60", 3));
    }
}
