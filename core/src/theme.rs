//! Design tokens shared by the frontends: icon tints, status colours, spacing and density
//! metrics. Surfaces and text colours stay native on each platform (system materials on macOS,
//! theme resources on Windows); the tokens carry what must look the same everywhere.
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ColorToken {
    pub name: &'static str,
    /// `#RRGGBB`.
    pub hex: &'static str,
}

const fn c(name: &'static str, hex: &'static str) -> ColorToken {
    ColorToken { name, hex }
}

/// Colour tokens for the dark or light appearance. Every `icons::Tint` has an `icon.*` entry.
pub fn colors(dark: bool) -> Vec<ColorToken> {
    if dark {
        vec![
            c("icon.terminal", "#3DD68C"),
            c("icon.desktop", "#5B9DFF"),
            c("icon.vnc", "#B194FA"),
            c("icon.web", "#F5A04A"),
            c("icon.files", "#2DD4BF"),
            c("icon.legacy", "#9CA3AF"),
            c("icon.infrastructure", "#7DC4F5"),
            c("icon.folder", "#8FA6C4"),
            c("icon.neutral", "#A1A7B0"),
            c("icon.running", "#3DD68C"),
            c("icon.stopped", "#8B919B"),
            c("icon.suspended", "#F2B84B"),
            c("status.connected", "#3DD68C"),
            c("status.connecting", "#F2B84B"),
            c("status.failed", "#F87171"),
            c("favorite", "#F2C94C"),
        ]
    } else {
        vec![
            c("icon.terminal", "#11904A"),
            c("icon.desktop", "#2563EB"),
            c("icon.vnc", "#7C3AED"),
            c("icon.web", "#C2620A"),
            c("icon.files", "#0F8A7E"),
            c("icon.legacy", "#6B7280"),
            c("icon.infrastructure", "#0277B5"),
            c("icon.folder", "#5A779E"),
            c("icon.neutral", "#666C76"),
            c("icon.running", "#11904A"),
            c("icon.stopped", "#6B7280"),
            c("icon.suspended", "#B7791F"),
            c("status.connected", "#11904A"),
            c("status.connecting", "#B7791F"),
            c("status.failed", "#DC2626"),
            c("favorite", "#C99A06"),
        ]
    }
}

/// The `appearance.accent` choices (same ids as `settings::ACCENTS`) as `#RRGGBB`: selections, primary buttons and
/// focus rings. One palette for every app; each derives its own lighter and darker shades for its toolkit.
pub const ACCENTS: &[(&str, &str)] = &[
    ("electric", "#2E6BFF"),
    ("cyan", "#00A8D1"),
    ("violet", "#7D5CFF"),
    ("emerald", "#0FA673"),
    ("amber", "#E6940A"),
    ("rose", "#ED405E"),
];

/// Hex colour of an accent id, or `None` for an unknown id.
pub fn accent(id: &str) -> Option<&'static str> {
    ACCENTS.iter().find(|(a, _)| *a == id).map(|(_, hex)| *hex)
}

/// 4-point spacing scale (xxs … xl).
pub const SPACING: [f64; 6] = [4.0, 8.0, 12.0, 16.0, 24.0, 32.0];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Density {
    Compact,
    Comfortable,
    Spacious,
}

/// Size metrics for one density.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Metrics {
    /// Navigation tree row height in points (DIPs on Windows).
    pub tree_row: f64,
    /// Icon size in tree rows.
    pub tree_icon: f64,
    /// Indentation per tree level.
    pub tree_indent: f64,
    /// Inspector label/value row height.
    pub inspector_row: f64,
}

pub fn metrics(d: Density) -> Metrics {
    match d {
        Density::Compact => Metrics { tree_row: 22.0, tree_icon: 14.0, tree_indent: 14.0, inspector_row: 20.0 },
        Density::Comfortable => Metrics { tree_row: 26.0, tree_icon: 16.0, tree_indent: 16.0, inspector_row: 24.0 },
        Density::Spacious => Metrics { tree_row: 30.0, tree_icon: 17.0, tree_indent: 18.0, inspector_row: 28.0 },
    }
}

/// Inspector width limits: wide enough for label/value rows without truncating common values.
pub const INSPECTOR_MIN: f64 = 260.0;
pub const INSPECTOR_IDEAL: f64 = 300.0;
pub const INSPECTOR_MAX: f64 = 460.0;
