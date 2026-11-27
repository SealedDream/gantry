//! Terminal fonts shared by the frontends: the bundled Nerd Font, the families offered in the
//! font pickers (Settings › Terminal, a folder's or connection's Terminal properties), the
//! effective font of a session, and how each cell's glyph should be drawn so Starship-style
//! prompts (Powerline separators, Nerd Font icons, box drawing) line up on the grid.
//!
//! The bundled font is JetBrains Mono Nerd Font Mono (SIL Open Font License 1.1, see
//! `assets/fonts/OFL.txt`). Frontends ship the files from `assets/fonts` and register them at
//! launch, then fall back to it for any glyph the chosen family lacks.

/// Family name of the bundled font, as the font files declare it.
pub const BUNDLED_FAMILY: &str = "JetBrainsMono Nerd Font Mono";
/// Files in `assets/fonts` that make up the bundled font.
pub const BUNDLED_FILES: &[&str] = &["JetBrainsMonoNerdFontMono-Regular.ttf", "JetBrainsMonoNerdFontMono-Bold.ttf"];
/// Licence file shipped next to the font files.
pub const BUNDLED_LICENCE: &str = "OFL.txt";

pub const DEFAULT_SIZE: u32 = 13;
pub const MIN_SIZE: u32 = 9;
pub const MAX_SIZE: u32 = 24;
/// Longest family name accepted; real names are far shorter.
const MAX_FAMILY_LEN: usize = 64;

/// Families every picker lists first: the bundled one, then monospaced families macOS and
/// Windows ship. Frontends add the other monospaced families installed on the machine.
pub const SUGGESTED_FAMILIES: &[(&str, &str)] = &[
    (BUNDLED_FAMILY, "JetBrains Mono Nerd Font (bundled)"),
    ("SF Mono", "SF Mono"),
    ("Menlo", "Menlo"),
    ("Monaco", "Monaco"),
    ("Cascadia Mono", "Cascadia Mono"),
    ("Consolas", "Consolas"),
    ("Courier New", "Courier New"),
];

/// Whether `family` can be stored as a font family: any installed family is allowed, so only
/// the shape is checked (non-empty, short, no control characters).
pub fn is_family(family: &str) -> bool {
    let f = family.trim();
    !f.is_empty() && f.len() <= MAX_FAMILY_LEN && f == family && !f.chars().any(char::is_control)
}

/// The font a terminal uses, after a connection's own or inherited choice over the app's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FontSpec {
    pub family: String,
    pub size: u32,
    pub ligatures: bool,
}

/// Effective font: each part of the connection's own or inherited setting wins over the app's;
/// invalid stored values fall back to the app's (and the app's to the bundled defaults).
pub fn effective(app: &FontSpec, family: Option<&str>, size: Option<u32>, ligatures: Option<bool>) -> FontSpec {
    let app_family = if is_family(&app.family) { app.family.clone() } else { BUNDLED_FAMILY.to_string() };
    let app_size = if (MIN_SIZE..=MAX_SIZE).contains(&app.size) { app.size } else { DEFAULT_SIZE };
    FontSpec {
        family: family.filter(|f| is_family(f)).map(str::to_string).unwrap_or(app_family),
        size: size.filter(|s| (MIN_SIZE..=MAX_SIZE).contains(s)).unwrap_or(app_size),
        ligatures: ligatures.unwrap_or(app.ligatures),
    }
}

/// How a frontend draws one cell's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlyphClass {
    /// Ordinary text through the font (with fallback).
    Text,
    /// U+2500–U+257F: drawn as lines that meet the cell edges, so boxes have no gaps whatever
    /// the font's line height.
    BoxDrawing,
    /// U+2580–U+259F: block elements and shades, filled to the cell edges.
    Block,
    /// Powerline separators (U+E0B0–U+E0BF): drawn as shapes filling the full cell height.
    Powerline,
    /// Private-use icons (Nerd Font, U+E000–U+F8FF and planes 15–16): through the font, with the
    /// bundled Nerd Font as fallback, scaled to fit their cells.
    Icon,
}

/// Classify a cell's text by its first character.
pub fn glyph_class(text: &str) -> GlyphClass {
    let Some(c) = text.chars().next() else { return GlyphClass::Text };
    match c as u32 {
        0x2500..=0x257f => GlyphClass::BoxDrawing,
        0x2580..=0x259f => GlyphClass::Block,
        0xe0b0..=0xe0bf => GlyphClass::Powerline,
        0xe000..=0xf8ff | 0xf0000..=0x10ffff => GlyphClass::Icon,
        _ => GlyphClass::Text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> FontSpec {
        FontSpec { family: "Menlo".into(), size: 13, ligatures: true }
    }

    #[test]
    fn classifies_prompt_glyphs() {
        assert_eq!(glyph_class("─"), GlyphClass::BoxDrawing);
        assert_eq!(glyph_class("╭"), GlyphClass::BoxDrawing);
        assert_eq!(glyph_class("█"), GlyphClass::Block);
        assert_eq!(glyph_class("\u{e0b0}"), GlyphClass::Powerline);
        assert_eq!(glyph_class("\u{e0b6}"), GlyphClass::Powerline);
        assert_eq!(glyph_class("\u{f115}"), GlyphClass::Icon);
        assert_eq!(glyph_class("\u{f0001}"), GlyphClass::Icon);
        assert_eq!(glyph_class("a"), GlyphClass::Text);
        assert_eq!(glyph_class("界"), GlyphClass::Text);
        assert_eq!(glyph_class(""), GlyphClass::Text);
    }

    #[test]
    fn connection_font_overrides_app_font_part_by_part() {
        let f = effective(&app(), Some("SF Mono"), None, Some(false));
        assert_eq!(f, FontSpec { family: "SF Mono".into(), size: 13, ligatures: false });
        assert_eq!(effective(&app(), None, Some(18), None), FontSpec { family: "Menlo".into(), size: 18, ligatures: true });
    }

    #[test]
    fn invalid_values_fall_back() {
        assert_eq!(effective(&app(), Some(""), Some(99), None), app());
        let bad = FontSpec { family: " ".into(), size: 3, ligatures: false };
        assert_eq!(effective(&bad, None, None, None), FontSpec { family: BUNDLED_FAMILY.into(), size: DEFAULT_SIZE, ligatures: false });
    }

    #[test]
    fn family_shape() {
        assert!(is_family(BUNDLED_FAMILY));
        assert!(!is_family(""));
        assert!(!is_family(" Menlo"));
        assert!(!is_family("Me\nnlo"));
        assert!(!is_family(&"x".repeat(65)));
    }

    #[test]
    fn bundled_font_files_and_licence_are_in_the_repo() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets/fonts");
        for f in BUNDLED_FILES.iter().chain([&BUNDLED_LICENCE]) {
            assert!(dir.join(f).is_file(), "missing assets/fonts/{f}");
        }
        let licence = std::fs::read_to_string(dir.join(BUNDLED_LICENCE)).unwrap();
        assert!(licence.contains("SIL Open Font License"));
    }
}
