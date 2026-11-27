//! Bundled terminal themes, user themes and the per-connection override.
use bastion_core::model::{Connection, Document, Protocol};
use bastion_core::properties;
use bastion_core::settings::Settings;
use bastion_core::termthemes::{self, ThemeStore, BUNDLED};

#[test]
fn bundled_themes_cover_the_requested_families_with_licences() {
    for id in ["catppuccin-mocha", "dracula", "tokyo-night", "nord", "gruvbox-dark", "solarized-dark", "solarized-light", "one-dark", "monokai"] {
        let b = termthemes::bundled(id).unwrap_or_else(|| panic!("{id} missing"));
        assert!(!b.license.is_empty() && !b.source.is_empty());
        // Published palettes are kept as published; the editor flags anything under 4.5:1 (Solarized is ~4.1).
        assert!(termthemes::contrast(b.theme.foreground, b.theme.background) >= 3.0, "{id} body text is readable");
    }
    assert!(termthemes::contrast(termthemes::bundled("solarized-light").unwrap().theme.foreground, 0xfdf6e3) < 4.5);
    let mut ids: Vec<_> = BUNDLED.iter().map(|b| b.id).collect();
    ids.dedup();
    assert_eq!(ids.len(), BUNDLED.len());
}

#[test]
fn contrast_matches_wcag_reference_values() {
    assert!((termthemes::contrast(0xffffff, 0x000000) - 21.0).abs() < 0.01);
    assert!((termthemes::contrast(0x777777, 0x777777) - 1.0).abs() < 0.001);
}

#[test]
fn custom_themes_duplicate_edit_persist_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let path = ThemeStore::file(dir.path());
    let mut store = ThemeStore::open(path.clone()).unwrap();
    let mut t = store.duplicate("nord").unwrap();
    assert_eq!(t.name, "Nord copy");
    assert_eq!(store.duplicate("nord").unwrap().name, "Nord copy 2");
    t.name = "Acme prod".into();
    t.background = 0x3a0000;
    store.put(t.clone()).unwrap();
    let back = ThemeStore::open(path.clone()).unwrap();
    assert_eq!(back.resolve(&t.id).unwrap().background, 0x3a0000);
    assert_eq!(back.resolve("dracula").unwrap().background, 0x282a36);
    let mut dup = t.clone();
    dup.id = back.custom().iter().find(|c| c.id != t.id).unwrap().id.clone();
    assert!(store.put(dup).is_err(), "names are unique");
    let mut bad = t.clone();
    bad.foreground = 0x1000000;
    assert!(store.put(bad).is_err());
    let mut bundled_name = t.clone();
    bundled_name.name = "dracula".into();
    assert!(store.put(bundled_name).is_err(), "cannot shadow a bundled name");
    assert!(store.remove("nord").is_err(), "bundled themes stay");
    store.remove(&t.id).unwrap();
    assert!(ThemeStore::open(path).unwrap().resolve(&t.id).is_none());
}

#[test]
fn damaged_theme_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = ThemeStore::file(dir.path());
    std::fs::write(&path, b"[{\"id\":\"custom-zz\"}]").unwrap();
    assert!(ThemeStore::open(path).is_err());
}

#[test]
fn terminal_theme_defaults_to_match_app_and_keeps_a_saved_choice() {
    let s = Settings::default();
    assert_eq!(s.get("terminal.theme").unwrap(), termthemes::MATCH_APP, "users who never picked follow the app");
    assert_eq!(termthemes::app_theme_id(termthemes::MATCH_APP, false), "bastion-light");
    assert_eq!(termthemes::app_theme_id(termthemes::MATCH_APP, true), "bastion-dark");
    let mut s = Settings::default();
    s.set("terminal.theme", "dracula").unwrap();
    assert_eq!(s.get("terminal.theme").unwrap(), "dracula");
    assert_eq!(termthemes::app_theme_id("dracula", false), "dracula", "a light app may keep a dark terminal");
}

#[test]
fn app_setting_accepts_bundled_and_custom_ids() {
    let mut s = Settings::default();
    s.set("terminal.theme", "tokyo-night").unwrap();
    s.set("terminal.theme", "custom-0a1b2c3d").unwrap();
    assert!(s.set("terminal.theme", "custom-../../x").is_err());
    assert!(s.set("terminal.theme", "nope").is_err());
}

#[test]
fn connection_and_folder_theme_overrides_inherit() {
    let mut doc = Document::new("t");
    let c = Connection::new("db", Protocol::Ssh, "10.0.0.2");
    let id = c.id;
    doc.insert(None, bastion_core::model::Node::Connection(c)).unwrap();
    assert!(properties::schema(Protocol::Ssh).iter().any(|d| d.key == "terminal_theme"));
    properties::set_type_value(&mut doc, Protocol::Ssh, "terminal_theme", Some("gruvbox-dark")).unwrap();
    assert_eq!(doc.resolve(id).unwrap().effective.terminal_theme.as_deref(), Some("gruvbox-dark"));
    properties::set_value(&mut doc, id, "terminal_theme", Some("custom-0a1b2c3d")).unwrap();
    assert_eq!(doc.resolve(id).unwrap().effective.terminal_theme.as_deref(), Some("custom-0a1b2c3d"));
    assert!(properties::set_value(&mut doc, id, "terminal_theme", Some("no-such")).is_err());
}
