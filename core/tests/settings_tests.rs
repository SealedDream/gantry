use bastion_core::settings::{self, Category, Kind, Settings, SettingsStore};
use bastion_core::terminal::TerminalTheme;
use bastion_core::{icons, CoreError};

const ALL_LINKS: &[&str] = &[
    "defaults:ssh",
    "defaults:rdp",
    "defaults:vnc",
    "defaults:web",
    "ssh-sources",
    "ssh-import",
    "credential-manager",
    "vaultwarden",
    "lock-credentials",
    "check-updates",
    "workspace-manager",
];

#[test]
fn ids_are_unique_and_defaults_validate() {
    let defs = settings::definitions();
    let mut ids: Vec<_> = defs.iter().map(|d| d.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), defs.len(), "duplicate setting id");
    for d in &defs {
        assert!(!d.label.is_empty() && !d.help.is_empty(), "{} needs a label and help", d.id);
        assert!(d.help.len() <= 120, "{} help is a paragraph", d.id);
        match d.kind {
            Kind::Link(_) => assert_eq!(d.default, "", "{} is a link", d.id),
            _ => assert_eq!(d.validate(d.default).unwrap(), d.default, "{} default", d.id),
        }
    }
}

#[test]
fn every_category_has_a_known_icon() {
    for c in Category::ALL {
        assert!(icons::by_id(c.icon()).is_some(), "{:?} icon {}", c, c.icon());
    }
}

#[test]
fn terminal_theme_options_match_the_core_presets() {
    let presets: Vec<_> = bastion_core::termthemes::BUNDLED.iter().map(|b| b.id).collect();
    let options: Vec<_> = settings::TERMINAL_THEMES.iter().map(|(id, _)| *id).collect();
    // "Match app theme" first, then every bundled theme.
    assert_eq!(options[0], bastion_core::termthemes::MATCH_APP);
    assert_eq!(presets, options[1..]);
}

#[test]
fn links_appear_only_when_the_frontend_handles_them() {
    let none = settings::visible(&[]);
    assert!(none.iter().all(|d| d.link_target().is_none()));
    let cats = settings::categories(&[]);
    assert!(!cats.contains(&Category::ConnectionDefaults), "a category of unhandled links is hidden");
    assert!(cats.contains(&Category::Appearance) && cats.contains(&Category::About));

    assert!(!cats.contains(&Category::Updates), "no update channel: the update settings mean nothing");
    assert!(none.iter().all(|d| d.id != "updates.check-at-launch"));

    let all = settings::categories(ALL_LINKS);
    assert!(all.contains(&Category::ConnectionDefaults) && all.contains(&Category::Vaultwarden));
    assert!(all.contains(&Category::Workspaces) && !cats.contains(&Category::Workspaces), "Workspaces only with a workspace manager");
    assert!(all.windows(2).all(|w| w[0] < w[1]), "categories keep display order");
}

#[test]
fn search_matches_labels_help_options_and_keywords() {
    let ids = |q: &str| settings::search(q, ALL_LINKS).into_iter().map(|d| d.id).collect::<Vec<_>>();
    assert_eq!(ids("font"), vec!["terminal.font-size"]);
    assert!(ids("dark").contains(&"appearance.mode"), "matches an option label");
    assert!(ids("bitwarden").contains(&"vaultwarden.provider"), "matches a keyword");
    assert_eq!(ids("LOCK idle"), vec!["document.auto-lock-minutes", "document.remember-unlock", "security.auto-lock"], "every word, case-insensitive");
    assert!(ids("   ").is_empty());
    assert!(ids("no such setting").is_empty());
    assert!(settings::search("defaults", &[]).is_empty(), "unhandled links are not found");
}

#[test]
fn set_validates_and_get_falls_back_to_the_default() {
    let mut s = Settings::default();
    assert_eq!(s.get("terminal.font-size").unwrap(), "13");
    s.set("terminal.font-size", " 16 ").unwrap();
    assert_eq!(s.get("terminal.font-size").unwrap(), "16");
    assert!(matches!(s.set("terminal.font-size", "40"), Err(CoreError::Invalid(_))));
    assert!(matches!(s.set("appearance.mode", "purple"), Err(CoreError::Invalid(_))));
    assert!(matches!(s.set("updates.check-at-launch", "yes"), Err(CoreError::Invalid(_))));
    assert!(matches!(s.set("updates.check-now", "true"), Err(CoreError::Invalid(_))), "links hold no value");
    assert!(matches!(s.set("no.such", "1"), Err(CoreError::NotFound(_))));
    assert_eq!(s.get("terminal.font-size").unwrap(), "16", "a rejected value changes nothing");

    s.set("terminal.font-size", "13").unwrap();
    assert!(s.is_default("terminal.font-size"), "setting the default removes the stored value");

    s.values.insert("appearance.mode".into(), "purple".into());
    assert_eq!(s.get("appearance.mode").unwrap(), "system", "an invalid stored value reads as the default");
}

#[test]
fn store_round_trips_and_keeps_unknown_ids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let store = SettingsStore::new(&path);
    assert!(!store.exists());
    assert_eq!(store.load().unwrap(), Settings::default());

    let mut s = Settings::default();
    s.set("appearance.mode", "dark").unwrap();
    s.set("security.auto-lock", "15").unwrap();
    s.values.insert("future.setting".into(), "x".into());
    store.save(&s).unwrap();

    let back = SettingsStore::new(&path).load().unwrap();
    assert_eq!(back.get("appearance.mode").unwrap(), "dark");
    assert_eq!(back.get("security.auto-lock").unwrap(), "15");
    assert_eq!(back.values.get("future.setting").map(String::as_str), Some("x"));
}

#[test]
fn a_damaged_file_is_an_error_not_silent_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(&path, b"{ not json").unwrap();
    assert!(matches!(SettingsStore::new(&path).load(), Err(CoreError::Invalid(_))));
}

#[test]
fn auto_lock_is_due_after_the_chosen_idle_time() {
    assert!(!settings::auto_lock_due("off", u64::MAX));
    assert!(!settings::auto_lock_due("5", 299));
    assert!(settings::auto_lock_due("5", 300));
    assert!(settings::auto_lock_due("60", 3600));
    assert!(!settings::auto_lock_due("garbage", 10_000));
}

#[test]
fn screen_lock_and_touch_id_settings_have_safe_defaults() {
    let s = Settings::default();
    assert_eq!(s.get("security.lock-on-screen-lock").unwrap(), "true", "locking on screen lock is on by default");
    assert_eq!(s.get("security.confirm-vault-open").unwrap(), "false");
    let mut s = s;
    assert!(s.set("security.confirm-vault-open", "maybe").is_err());
    s.set("security.lock-on-screen-lock", "false").unwrap();
    let links = [ALL_LINKS, &["vault-open-confirm"]].concat();
    let ids = |q: &str| settings::search(q, &links).into_iter().map(|d| d.id).collect::<Vec<_>>();
    assert!(ids(if cfg!(windows) { "windows hello" } else { "touch id" }).contains(&"security.confirm-vault-open"));
    assert!(ids("screen saver").contains(&"security.lock-on-screen-lock"));
}

#[test]
fn terminal_font_bell_copy_and_close_settings_need_their_capability() {
    let ids = |links: &[&str]| settings::visible(links).into_iter().map(|d| d.id).collect::<Vec<_>>();
    let new = ["terminal.font-family", "terminal.bell", "terminal.copy-on-select", "terminal.confirm-close"];
    assert!(new.iter().all(|id| !ids(&[]).contains(id)), "hidden from frontends that do not honour them");
    let shown = ids(&["terminal-font-family", "terminal-bell", "terminal-copy-on-select", "terminal-confirm-close"]);
    assert!(new.iter().all(|id| shown.contains(id)));
    let bell = settings::definition("terminal.bell").unwrap();
    assert_eq!(bell.default, "visual");
    assert!(bell.validate("sound").is_ok() && bell.validate("loud").is_err());
    assert_eq!(settings::definition("terminal.font-family").unwrap().default, "bundled");
    assert_eq!(settings::definition("terminal.confirm-close").unwrap().default, "true");
}

/// TM-03: a managed inactivity limit applies whatever the user's own auto-lock choice.
#[test]
fn managed_inactivity_limit_locks_credentials_even_when_off() {
    let p = bastion_core::policy::Policy { inactivity_lock_secs: Some(60), ..Default::default() };
    assert!(settings::auto_lock_due_under("off", 60, &p));
    assert!(!settings::auto_lock_due_under("off", 59, &p));
    assert!(settings::auto_lock_due_under("1", 60, &bastion_core::policy::Policy { inactivity_lock_secs: None, ..Default::default() }));
}

/// A3-S1: how long a copied password stays on the clipboard is a setting (30, 45 or 60 s,
/// default 60), shown only by frontends that honour it.
#[test]
fn secret_clipboard_lifetime_is_a_choice_of_30_45_60_defaulting_to_60() {
    let id = settings::SECRET_CLIPBOARD_SETTING;
    let def = settings::definition(id).unwrap();
    assert_eq!(def.category, Category::Security);
    assert_eq!(def.default, "60");
    let options: Vec<_> = settings::SECRET_CLIPBOARD_SECONDS.iter().map(|(id, _)| *id).collect();
    assert_eq!(options, ["30", "45", "60"]);
    assert!(def.validate("30").is_ok() && def.validate("45").is_ok() && def.validate("60").is_ok());
    for bad in ["0", "29", "61", "120", "off", "", "-30"] {
        assert!(def.validate(bad).is_err(), "`{bad}` must be rejected");
    }
    assert!(settings::visible(&[]).iter().all(|d| d.id != id), "hidden from frontends that do not honour it");
    assert!(settings::visible(&["secret-clipboard-lifetime"]).iter().any(|d| d.id == id));
    let found: Vec<_> = settings::search("clipboard password", &["secret-clipboard-lifetime"]).into_iter().map(|d| d.id).collect();
    assert!(found.contains(&id));

    let mut s = Settings::default();
    assert_eq!(s.get(id).unwrap(), "60");
    s.set(id, "30").unwrap();
    assert_eq!(s.get(id).unwrap(), "30");
    assert!(matches!(s.set(id, "600"), Err(CoreError::Invalid(_))));
    assert_eq!(s.get(id).unwrap(), "30", "a rejected value changes nothing");
}

/// A3-S1: the lifetime never exceeds 60 s. A value that cannot be read, or is not one of the
/// choices, gives the shortest lifetime rather than a longer or endless one.
#[test]
fn secret_clipboard_seconds_falls_back_to_the_shortest_lifetime() {
    assert_eq!(settings::secret_clipboard_seconds(Some("30")), 30);
    assert_eq!(settings::secret_clipboard_seconds(Some("45")), 45);
    assert_eq!(settings::secret_clipboard_seconds(Some("60")), 60);
    for bad in [None, Some(""), Some("0"), Some("off"), Some("61"), Some("3600"), Some("-1"), Some("60 "), Some("never")] {
        assert_eq!(settings::secret_clipboard_seconds(bad), 30, "{bad:?}");
    }
    // A stored value that is no longer valid reads as the default through `Settings::get`.
    let mut s = Settings::default();
    s.values.insert(settings::SECRET_CLIPBOARD_SETTING.into(), "600".into());
    assert_eq!(settings::secret_clipboard_seconds(Some(&s.get(settings::SECRET_CLIPBOARD_SETTING).unwrap())), 60);
}

/// A1-CORE-02: the user's reuse time for a remembered login is a setting: whole minutes,
/// default 0 (until Lock or quit), shown only by frontends that honour it. It round-trips
/// through `settings.json` and feeds the session-login policy value.
#[test]
fn session_login_reuse_policy_setting_round_trips() {
    use bastion_core::policy::effective_session_login_reuse_minutes;
    let id = settings::SESSION_LOGIN_REUSE_SETTING;
    assert_eq!(id, "security.session-login-reuse-minutes");
    let def = settings::definition(id).unwrap();
    assert_eq!(def.default, "0");
    assert!(matches!(def.kind, settings::Kind::Integer { min: 0, max: 1440, .. }));
    assert!(def.help.chars().count() <= 120, "one short sentence");
    for bad in ["-1", "1441", "five", "", "1.5"] {
        assert!(def.validate(bad).is_err(), "{bad}");
    }
    let ids = |links: &[&str]| settings::visible(links).into_iter().map(|d| d.id).collect::<Vec<_>>();
    assert!(!ids(&[]).contains(&id), "hidden from frontends that do not honour it yet");
    assert!(ids(&["session-login-reuse"]).contains(&id));

    let dir = tempfile::tempdir().unwrap();
    let store = settings::SettingsStore::new(dir.path().join("settings.json"));
    let mut s = store.load().unwrap();
    assert_eq!(s.get(id).unwrap(), "0");
    s.set(id, "30").unwrap();
    assert!(s.set(id, "2000").is_err());
    store.save(&s).unwrap();
    let back = store.load().unwrap();
    assert_eq!(back.get(id).unwrap(), "30");
    assert_eq!(settings::session_login_reuse_user_minutes(&back.get(id).unwrap()), 30);
    assert_eq!(effective_session_login_reuse_minutes(settings::session_login_reuse_user_minutes(&back.get(id).unwrap()), 10), 10);
    // A value that is not a number in range reads as 0, which never relaxes a managed maximum.
    for odd in ["", "off", "-5", "99999999999"] {
        assert_eq!(settings::session_login_reuse_user_minutes(odd), 0, "{odd}");
    }
    let mut s = back;
    s.set(id, "0").unwrap();
    assert!(s.is_default(id));
}

// SETTINGS-PLATFORM-GATE: the biometric rows show only where the frontend implements them, and name
// the platform's own feature (Touch ID on the Mac, Windows Hello on Windows).
#[test]
fn biometric_settings_hide_unless_the_frontend_implements_them() {
    let ids = |caps: &[&str]| settings::visible(caps).into_iter().map(|d| d.id).collect::<Vec<_>>();
    let none = ids(&[]);
    assert!(!none.contains(&"security.confirm-vault-open"));
    assert!(!none.contains(&"security.touch-id-unlock"));
    // Native Windows: the Windows Hello vault gate only; the library has no biometric unlock there.
    let windows = ids(&["vault-open-confirm"]);
    assert!(windows.contains(&"security.confirm-vault-open"));
    assert!(!windows.contains(&"security.touch-id-unlock"));
    let mac = ids(&["vault-open-confirm", "touch-id-library-unlock"]);
    assert!(mac.contains(&"security.confirm-vault-open") && mac.contains(&"security.touch-id-unlock"));
}

#[test]
fn vault_open_confirm_names_the_platform_feature() {
    let d = settings::definition("security.confirm-vault-open").unwrap();
    let (own, other) = if cfg!(windows) { ("Windows Hello", "Touch ID") } else { ("Touch ID", "Windows Hello") };
    assert!(d.label.contains(own), "{}", d.label);
    assert!(!d.label.contains(other) && !d.help.contains(other), "{} / {}", d.label, d.help);
}

#[test]
fn window_at_launch_defaults_to_remember_and_shows_only_where_handled() {
    let s = settings::Settings::default();
    assert_eq!(s.get("window.launch").unwrap(), "remember");
    assert_eq!(s.get("window.launch-width").unwrap(), "1280");
    assert_eq!(s.get("window.launch-height").unwrap(), "800");
    let mut s = settings::Settings::default();
    for v in ["fixed", "maximized", "full-screen", "remember"] { s.set("window.launch", v).unwrap(); }
    assert!(s.set("window.launch", "huge").is_err());
    assert!(s.set("window.launch-width", "100").is_err(), "below the minimum");
    let none = settings::visible(&[]);
    assert!(none.iter().all(|d| !d.id.starts_with("window.")));
    let both = settings::visible(&["window-launch", "window-current-size"]);
    assert_eq!(both.iter().filter(|d| d.id.starts_with("window.")).count(), 4);
}
