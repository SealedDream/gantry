//! Terminal colour themes: the bundled set (each with its source and licence) plus the user's own
//! themes in `terminal-themes.json` next to `settings.json`. A theme is chosen app-wide
//! (`terminal.theme`) and may be overridden per connection or folder (`Settings::terminal_theme`),
//! so a customer's servers can look different from everything else.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::terminal::TerminalTheme;

/// One bundled theme. Colour values are taken from each project's published palette.
pub struct Bundled {
    pub id: &'static str,
    pub name: &'static str,
    pub source: &'static str,
    pub license: &'static str,
    pub theme: TerminalTheme,
}

const fn t(foreground: u32, background: u32, ansi: [u32; 16]) -> TerminalTheme {
    TerminalTheme { foreground, background, ansi }
}

/// Bundled themes in display order. Every licence here allows redistribution with attribution.
pub const BUNDLED: &[Bundled] = &[
    Bundled { id: "bastion-dark", name: "Gantry Dark", source: "Gantry", license: "Apache-2.0", theme: TerminalTheme::BASTION_DARK },
    Bundled { id: "bastion-light", name: "Gantry Light", source: "Gantry", license: "Apache-2.0", theme: TerminalTheme::BASTION_LIGHT },
    Bundled { id: "high-contrast", name: "High Contrast", source: "Gantry", license: "Apache-2.0", theme: TerminalTheme::HIGH_CONTRAST },
    Bundled { id: "catppuccin-mocha", name: "Catppuccin Mocha", source: "github.com/catppuccin/catppuccin", license: "MIT",
        theme: t(0xcdd6f4, 0x1e1e2e, [0x45475a, 0xf38ba8, 0xa6e3a1, 0xf9e2af, 0x89b4fa, 0xf5c2e7, 0x94e2d5, 0xbac2de, 0x585b70, 0xf38ba8, 0xa6e3a1, 0xf9e2af, 0x89b4fa, 0xf5c2e7, 0x94e2d5, 0xa6adc8]) },
    Bundled { id: "catppuccin-latte", name: "Catppuccin Latte", source: "github.com/catppuccin/catppuccin", license: "MIT",
        theme: t(0x4c4f69, 0xeff1f5, [0x5c5f77, 0xd20f39, 0x40a02b, 0xdf8e1d, 0x1e66f5, 0xea76cb, 0x179299, 0xacb0be, 0x6c6f85, 0xd20f39, 0x40a02b, 0xdf8e1d, 0x1e66f5, 0xea76cb, 0x179299, 0xbcc0cc]) },
    Bundled { id: "dracula", name: "Dracula", source: "draculatheme.com", license: "MIT",
        theme: t(0xf8f8f2, 0x282a36, [0x21222c, 0xff5555, 0x50fa7b, 0xf1fa8c, 0xbd93f9, 0xff79c6, 0x8be9fd, 0xf8f8f2, 0x6272a4, 0xff6e6e, 0x69ff94, 0xffffa5, 0xd6acff, 0xff92df, 0xa4ffff, 0xffffff]) },
    Bundled { id: "tokyo-night", name: "Tokyo Night", source: "github.com/enkia/tokyo-night-vscode-theme", license: "MIT",
        theme: t(0xc0caf5, 0x1a1b26, [0x15161e, 0xf7768e, 0x9ece6a, 0xe0af68, 0x7aa2f7, 0xbb9af7, 0x7dcfff, 0xa9b1d6, 0x414868, 0xf7768e, 0x9ece6a, 0xe0af68, 0x7aa2f7, 0xbb9af7, 0x7dcfff, 0xc0caf5]) },
    Bundled { id: "nord", name: "Nord", source: "nordtheme.com", license: "MIT",
        theme: t(0xd8dee9, 0x2e3440, [0x3b4252, 0xbf616a, 0xa3be8c, 0xebcb8b, 0x81a1c1, 0xb48ead, 0x88c0d0, 0xe5e9f0, 0x4c566a, 0xbf616a, 0xa3be8c, 0xebcb8b, 0x81a1c1, 0xb48ead, 0x8fbcbb, 0xeceff4]) },
    Bundled { id: "gruvbox-dark", name: "Gruvbox Dark", source: "github.com/morhetz/gruvbox", license: "MIT",
        theme: t(0xebdbb2, 0x282828, [0x282828, 0xcc241d, 0x98971a, 0xd79921, 0x458588, 0xb16286, 0x689d6a, 0xa89984, 0x928374, 0xfb4934, 0xb8bb26, 0xfabd2f, 0x83a598, 0xd3869b, 0x8ec07c, 0xebdbb2]) },
    Bundled { id: "solarized-dark", name: "Solarized Dark", source: "ethanschoonover.com/solarized", license: "MIT", theme: TerminalTheme::SOLARIZED_DARK },
    Bundled { id: "solarized-light", name: "Solarized Light", source: "ethanschoonover.com/solarized", license: "MIT",
        theme: t(0x657b83, 0xfdf6e3, [0x073642, 0xdc322f, 0x859900, 0xb58900, 0x268bd2, 0xd33682, 0x2aa198, 0xeee8d5, 0x002b36, 0xcb4b16, 0x586e75, 0x657b83, 0x839496, 0x6c71c4, 0x93a1a1, 0xfdf6e3]) },
    Bundled { id: "one-dark", name: "One Dark", source: "github.com/atom/atom (one-dark-syntax)", license: "MIT",
        theme: t(0xabb2bf, 0x282c34, [0x282c34, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xabb2bf, 0x5c6370, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xffffff]) },
    Bundled { id: "monokai", name: "Monokai", source: "base16 Monokai scheme (after Wimer Hazenberg), github.com/chriskempson/base16", license: "MIT",
        theme: t(0xf8f8f2, 0x272822, [0x272822, 0xf92672, 0xa6e22e, 0xf4bf75, 0x66d9ef, 0xae81ff, 0xa1efe4, 0xf8f8f2, 0x75715e, 0xf92672, 0xa6e22e, 0xf4bf75, 0x66d9ef, 0xae81ff, 0xa1efe4, 0xf9f8f5]) },
];

pub fn bundled(id: &str) -> Option<&'static Bundled> {
    BUNDLED.iter().find(|b| b.id == id)
}

/// A theme the user made (usually by duplicating a bundled one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomTheme {
    /// `custom-<8 hex>`, never the id of a bundled theme.
    pub id: String,
    pub name: String,
    pub foreground: u32,
    pub background: u32,
    pub ansi: [u32; 16],
}

impl CustomTheme {
    pub fn theme(&self) -> TerminalTheme {
        TerminalTheme { foreground: self.foreground, background: self.background, ansi: self.ansi }
    }
}

const MAX_NAME: usize = 64;
pub const MAX_CUSTOM: usize = 200;
const MAX_FILE: u64 = 1024 * 1024;

/// Ids a setting may hold: a bundled id, or a well-formed custom id.
/// The `terminal.theme` value that follows the app's light or dark appearance (the default, owner 2026-11-15).
pub const MATCH_APP: &str = "match-app";

/// The theme id a `terminal.theme` value stands for: `match-app` is Bastion Light in a light app and Bastion Dark in a
/// dark one (high contrast counts as dark); any other value is itself.
pub fn app_theme_id(value: &str, app_is_dark: bool) -> &str {
    match value {
        MATCH_APP if app_is_dark => "bastion-dark",
        MATCH_APP => "bastion-light",
        other => other,
    }
}

pub fn is_theme_id(id: &str) -> bool {
    bundled(id).is_some() || is_custom_id(id)
}

fn is_custom_id(id: &str) -> bool {
    id.strip_prefix("custom-").is_some_and(|h| h.len() == 8 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// WCAG relative-luminance contrast ratio of two colours (1.0 to 21.0).
pub fn contrast(a: u32, b: u32) -> f64 {
    fn lum(c: u32) -> f64 {
        let ch = |v: u32| {
            let s = v as f64 / 255.0;
            if s <= 0.03928 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * ch(c >> 16 & 0xff) + 0.7152 * ch(c >> 8 & 0xff) + 0.0722 * ch(c & 0xff)
    }
    let (x, y) = (lum(a), lum(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// The user's themes, saved atomically (owner-only) to `terminal-themes.json`.
pub struct ThemeStore {
    path: PathBuf,
    themes: Vec<CustomTheme>,
}

impl ThemeStore {
    pub fn file(dir: &Path) -> PathBuf {
        dir.join("terminal-themes.json")
    }

    /// A missing file is an empty store; a damaged one is an error, never silently replaced.
    pub fn open(path: PathBuf) -> Result<ThemeStore> {
        let themes = match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
            Ok(m) if m.len() > MAX_FILE => return Err(CoreError::Invalid("terminal-themes.json is too large".into())),
            Ok(_) => {
                let list: Vec<CustomTheme> = serde_json::from_slice(&std::fs::read(&path)?).map_err(|e| CoreError::Corrupt(format!("terminal-themes.json: {e}")))?;
                for t in &list {
                    validate(t)?;
                }
                list
            }
        };
        Ok(ThemeStore { path, themes })
    }

    pub fn custom(&self) -> &[CustomTheme] {
        &self.themes
    }

    pub fn resolve(&self, id: &str) -> Option<TerminalTheme> {
        bundled(id).map(|b| b.theme).or_else(|| self.themes.iter().find(|t| t.id == id).map(CustomTheme::theme))
    }

    /// A new custom theme with `source`'s colours, named "<name> copy" (numbered when taken).
    pub fn duplicate(&mut self, source: &str) -> Result<CustomTheme> {
        let (name, theme) = match bundled(source) {
            Some(b) => (b.name.to_string(), b.theme),
            None => self.themes.iter().find(|t| t.id == source).map(|t| (t.name.clone(), t.theme())).ok_or_else(|| CoreError::NotFound(format!("theme {source}")))?,
        };
        let base = format!("{name} copy");
        let mut candidate = base.clone();
        let mut n = 2;
        while self.name_taken(&candidate, None) {
            candidate = format!("{base} {n}");
            n += 1;
        }
        let id = loop {
            let id = format!("custom-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            if !self.themes.iter().any(|t| t.id == id) {
                break id;
            }
        };
        let t = CustomTheme { id, name: candidate.chars().take(MAX_NAME).collect(), foreground: theme.foreground, background: theme.background, ansi: theme.ansi };
        self.put(t.clone())?;
        Ok(t)
    }

    /// Add or replace a custom theme (by id) and save.
    pub fn put(&mut self, theme: CustomTheme) -> Result<()> {
        validate(&theme)?;
        if self.name_taken(&theme.name, Some(&theme.id)) {
            return Err(CoreError::Invalid(format!("A theme named {} already exists.", theme.name.trim())));
        }
        let mut next = self.themes.clone();
        match next.iter_mut().find(|t| t.id == theme.id) {
            Some(slot) => *slot = theme,
            None => {
                if next.len() >= MAX_CUSTOM {
                    return Err(CoreError::Invalid(format!("At most {MAX_CUSTOM} custom themes.")));
                }
                next.push(theme)
            }
        }
        self.save(next)
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        if bundled(id).is_some() {
            return Err(CoreError::Invalid("Bundled themes cannot be deleted.".into()));
        }
        let next: Vec<CustomTheme> = self.themes.iter().filter(|t| t.id != id).cloned().collect();
        if next.len() == self.themes.len() {
            return Err(CoreError::NotFound(format!("theme {id}")));
        }
        self.save(next)
    }

    fn name_taken(&self, name: &str, except: Option<&str>) -> bool {
        let name = name.trim();
        BUNDLED.iter().any(|b| b.name.eq_ignore_ascii_case(name)) || self.themes.iter().any(|t| Some(t.id.as_str()) != except && t.name.trim().eq_ignore_ascii_case(name))
    }

    fn save(&mut self, next: Vec<CustomTheme>) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&next).map_err(|e| CoreError::Corrupt(e.to_string()))?;
        crate::store::write_atomic(&self.path, &bytes)?;
        self.themes = next;
        Ok(())
    }
}

fn validate(t: &CustomTheme) -> Result<()> {
    if !is_custom_id(&t.id) {
        return Err(CoreError::Invalid(format!("`{}` is not a custom theme id", t.id)));
    }
    let name = t.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        return Err(CoreError::Invalid(format!("Theme name must be 1 to {MAX_NAME} characters.")));
    }
    if [t.foreground, t.background].iter().chain(t.ansi.iter()).any(|c| *c > 0xffffff) {
        return Err(CoreError::Invalid("Colours must be 24-bit RGB.".into()));
    }
    Ok(())
}
