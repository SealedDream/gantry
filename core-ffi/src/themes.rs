//! Bridge for terminal themes (`bastion_core::termthemes`): the bundled set, the user's themes
//! and the per-connection override.
use std::sync::{Arc, Mutex};

use bastion_core::terminal::TerminalTheme;
use bastion_core::termthemes::{self, CustomTheme, ThemeStore, BUNDLED};

use crate::{parse_id, FfiError, FfiResult, Library, Terminal};

#[derive(uniffi::Record, Clone)]
pub struct TerminalThemeView {
    pub id: String,
    pub name: String,
    pub bundled: bool,
    /// Where a bundled palette comes from, and its licence; empty for the user's themes.
    pub source: String,
    pub license: String,
    pub foreground: u32,
    pub background: u32,
    /// 16 colours: black, red, green, yellow, blue, magenta, cyan, white, then the bright set.
    pub ansi: Vec<u32>,
    /// WCAG contrast of foreground on background; under 4.5 is hard to read.
    pub contrast: f64,
}

fn view(id: &str, name: &str, bundled: bool, source: &str, license: &str, t: &TerminalTheme) -> TerminalThemeView {
    TerminalThemeView {
        id: id.into(),
        name: name.into(),
        bundled,
        source: source.into(),
        license: license.into(),
        foreground: t.foreground,
        background: t.background,
        ansi: t.ansi.to_vec(),
        contrast: termthemes::contrast(t.foreground, t.background),
    }
}

#[derive(uniffi::Object)]
pub struct ThemeLibrary {
    store: Mutex<ThemeStore>,
}

#[uniffi::export]
impl ThemeLibrary {
    /// `terminal-themes.json` in `data_dir`; a damaged file is an error.
    #[uniffi::constructor]
    pub fn open(data_dir: String) -> FfiResult<Arc<Self>> {
        let store = ThemeStore::open(ThemeStore::file(std::path::Path::new(&data_dir)))?;
        Ok(Arc::new(ThemeLibrary { store: Mutex::new(store) }))
    }

    /// Bundled themes first, then the user's by name.
    pub fn list(&self) -> Vec<TerminalThemeView> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let mut custom: Vec<_> = store.custom().iter().map(|c| view(&c.id, &c.name, false, "", "", &c.theme())).collect();
        custom.sort_by_key(|v| v.name.to_lowercase());
        BUNDLED.iter().map(|b| view(b.id, b.name, true, b.source, b.license, &b.theme)).chain(custom).collect()
    }

    pub fn get(&self, id: String) -> Option<TerminalThemeView> {
        self.list().into_iter().find(|v| v.id == id)
    }

    /// Copy any theme into a new editable one.
    pub fn duplicate(&self, id: String) -> FfiResult<TerminalThemeView> {
        let t = self.store.lock().unwrap_or_else(|e| e.into_inner()).duplicate(&id)?;
        Ok(view(&t.id, &t.name, false, "", "", &t.theme()))
    }

    /// Save an edited user theme (bundled themes are read-only).
    pub fn save(&self, theme: TerminalThemeView) -> FfiResult<()> {
        let ansi: [u32; 16] = theme.ansi.try_into().map_err(|_| FfiError::failed("a theme has exactly 16 ANSI colours".into()))?;
        let t = CustomTheme { id: theme.id, name: theme.name, foreground: theme.foreground, background: theme.background, ansi };
        Ok(self.store.lock().unwrap_or_else(|e| e.into_inner()).put(t)?)
    }

    pub fn remove(&self, id: String) -> FfiResult<()> {
        Ok(self.store.lock().unwrap_or_else(|e| e.into_inner()).remove(&id)?)
    }

    /// Apply theme `id` to `terminal`; an unknown id (a deleted theme) falls back to Bastion Dark.
    pub fn apply(&self, id: String, terminal: Arc<Terminal>) {
        let theme = self.store.lock().unwrap_or_else(|e| e.into_inner()).resolve(&id).unwrap_or_default();
        terminal.apply_theme(theme);
    }
}

#[uniffi::export]
impl Library {
    /// The connection's own or inherited terminal theme, if any (else the app's applies).
    pub fn terminal_theme(&self, connection_id: String) -> FfiResult<Option<String>> {
        Ok(self.resolve(parse_id(&connection_id)?)?.settings.terminal_theme)
    }
}

/// Window colours derived from a terminal theme (UI-06), as `0xRRGGBB`.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct WindowTonesView {
    pub active_tab: u32,
    pub tab_strip: u32,
    pub toolbar: u32,
    pub sidebar: u32,
    pub separator: u32,
    pub text: u32,
    pub secondary_text: u32,
    pub is_dark: bool,
}

/// Sidebar, tab strip and toolbar tones for a theme's background and foreground; text keeps 4.5:1 (7:1 with
/// `increased_contrast`).
#[uniffi::export]
pub fn window_tones(background: u32, foreground: u32, increased_contrast: bool) -> WindowTonesView {
    let t = bastion_core::windowtones::window_tones(background, foreground, increased_contrast);
    WindowTonesView {
        active_tab: t.active_tab,
        tab_strip: t.tab_strip,
        toolbar: t.toolbar,
        sidebar: t.sidebar,
        separator: t.separator,
        text: t.text,
        secondary_text: t.secondary_text,
        is_dark: t.is_dark,
    }
}

/// True when the accent reaches 3:1 on every derived surface; otherwise draw selection with the tones' text colour.
#[uniffi::export]
pub fn window_tones_accent_usable(accent: u32, tones: WindowTonesView) -> bool {
    let t = bastion_core::windowtones::WindowTones {
        active_tab: tones.active_tab, tab_strip: tones.tab_strip, toolbar: tones.toolbar, sidebar: tones.sidebar,
        separator: tones.separator, text: tones.text, secondary_text: tones.secondary_text, is_dark: tones.is_dark,
    };
    bastion_core::windowtones::accent_usable(accent, &t)
}
