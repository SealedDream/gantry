//! Bridge for terminal fonts (`bastion_core::termfonts`): the bundled Nerd Font, the families the
//! pickers list first, the per-connection override and how each cell's glyph is drawn.
use bastion_core::termfonts::{self, FontSpec, GlyphClass};

use crate::{parse_id, FfiResult, Library};

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TerminalFontView {
    pub family: String,
    pub size: u32,
    pub ligatures: bool,
}

#[derive(uniffi::Record, Clone)]
pub struct TerminalFontFamily {
    pub family: String,
    pub label: String,
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlyphClassView {
    Text,
    BoxDrawing,
    Block,
    Powerline,
    Icon,
}

impl From<GlyphClass> for GlyphClassView {
    fn from(c: GlyphClass) -> Self {
        match c {
            GlyphClass::Text => GlyphClassView::Text,
            GlyphClass::BoxDrawing => GlyphClassView::BoxDrawing,
            GlyphClass::Block => GlyphClassView::Block,
            GlyphClass::Powerline => GlyphClassView::Powerline,
            GlyphClass::Icon => GlyphClassView::Icon,
        }
    }
}

/// Family name of the bundled Nerd Font.
#[uniffi::export]
pub fn bundled_terminal_font() -> String {
    termfonts::BUNDLED_FAMILY.into()
}

/// Font files (in `assets/fonts`, or the app bundle's Fonts folder) that make up the bundled font.
#[uniffi::export]
pub fn bundled_terminal_font_files() -> Vec<String> {
    termfonts::BUNDLED_FILES.iter().map(|f| f.to_string()).collect()
}

/// Families every font picker lists first; frontends add other installed monospaced families.
#[uniffi::export]
pub fn suggested_terminal_fonts() -> Vec<TerminalFontFamily> {
    termfonts::SUGGESTED_FAMILIES.iter().map(|(f, l)| TerminalFontFamily { family: f.to_string(), label: l.to_string() }).collect()
}

#[uniffi::export]
pub fn is_terminal_font_family(family: String) -> bool {
    termfonts::is_family(&family)
}

/// How to draw a cell's text (see `termfonts::GlyphClass`).
#[uniffi::export]
pub fn terminal_glyph_class(text: String) -> GlyphClassView {
    termfonts::glyph_class(&text).into()
}

/// The app font when no connection applies (a local shell), cleaned of invalid values.
#[uniffi::export]
pub fn effective_terminal_font(app: TerminalFontView) -> TerminalFontView {
    view(termfonts::effective(&spec(app), None, None, None))
}

fn spec(v: TerminalFontView) -> FontSpec {
    FontSpec { family: v.family, size: v.size, ligatures: v.ligatures }
}

fn view(f: FontSpec) -> TerminalFontView {
    TerminalFontView { family: f.family, size: f.size, ligatures: f.ligatures }
}

#[uniffi::export]
impl Library {
    /// The connection's own or inherited font over the app's, part by part.
    pub fn terminal_font(&self, connection_id: String, app: TerminalFontView) -> FfiResult<TerminalFontView> {
        let s = self.resolve(parse_id(&connection_id)?)?.settings;
        Ok(view(termfonts::effective(&spec(app), s.terminal_font_family.as_deref(), s.terminal_font_size, s.terminal_ligatures)))
    }
}
