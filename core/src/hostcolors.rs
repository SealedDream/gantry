//! Per-host colours: a `#rrggbb` accent set on a connection or inherited from a folder
//! (`Settings::host_color`), so a customer's or production servers stand out. The UIs paint the
//! tab, the terminal border and the tree badge from [`HostColor`]; the core picks the readable
//! text colour so every UI agrees on contrast.
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::Document;

/// Ready-made accents offered next to the free hex field, `(hex, label)`.
pub const PRESETS: &[(&str, &str)] = &[
    ("#d64545", "Red"),
    ("#e8833a", "Orange"),
    ("#d9b72b", "Yellow"),
    ("#3fa34d", "Green"),
    ("#2b9bb3", "Teal"),
    ("#3b6fd6", "Blue"),
    ("#8a55d6", "Purple"),
    ("#d64598", "Pink"),
    ("#7a7a7a", "Grey"),
];

/// Opacity of the tinted tab/terminal background, so the accent never fights the theme.
const TINT_ALPHA: f64 = 0.18;
/// Luminance above which black text reads better than white (WCAG midpoint).
const DARK_TEXT_ABOVE: f64 = 0.179;

/// Colours a UI paints for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostColor {
    /// The accent, `#rrggbb` lower-case.
    pub accent: String,
    /// `#000000` or `#ffffff`: text drawn on the accent.
    pub text: String,
    /// `#rrggbbaa`: the accent at low opacity for a tab or terminal background.
    pub tint: String,
    /// Label of the nearest preset (`Red`), for a UI that keeps its own swatch per name.
    pub named: String,
    /// The connection is marked privileged (UI-01: the session strip says so).
    pub privileged: bool,
    /// Text-safe tones (`#rrggbb`) for coloured names: 4.5:1 or better on the app's surfaces and on
    /// `bg_*`. `fg_light` / `bg_light` for the light theme, `fg_dark` / `bg_dark` for dark.
    pub fg_light: String,
    pub bg_light: String,
    pub fg_dark: String,
    pub bg_dark: String,
}

/// Worst-case window surfaces the tones are checked against (sidebar grey, not white).
pub const SURFACE_LIGHT: &str = "#e8e8e8";
pub const SURFACE_DARK: &str = "#2c2c2c";
/// Minimum contrast for coloured text (WCAG AA body text).
pub const MIN_CONTRAST: f64 = 4.5;
/// Default for a privileged connection with no colour of its own or from a folder.
pub const PRIVILEGED_DEFAULT: &str = "#d64545";

/// Normalise `#rgb` / `#rrggbb` (with or without `#`, any case) to `#rrggbb`, or name a preset
/// (`Red`). Anything else is refused.
pub fn normalize(value: &str) -> Result<String> {
    let v = value.trim();
    if let Some((hex, _)) = PRESETS.iter().find(|(_, label)| label.eq_ignore_ascii_case(v)) {
        return Ok((*hex).to_string());
    }
    let h = v.strip_prefix('#').unwrap_or(v);
    if h.is_empty() || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(value));
    }
    let full: String = match h.len() {
        3 => h.chars().flat_map(|c| [c, c]).collect(),
        6 => h.to_string(),
        _ => return Err(invalid(value)),
    };
    Ok(format!("#{}", full.to_ascii_lowercase()))
}

fn invalid(value: &str) -> CoreError {
    CoreError::Invalid(format!("Host colour: `{value}` is not a colour (use #rrggbb or a preset name)."))
}

fn rgb(hex: &str) -> (u8, u8, u8) {
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0);
    (byte(1), byte(3), byte(5))
}

/// WCAG relative luminance of a normalised colour.
fn luminance(hex: &str) -> f64 {
    let lin = |c: u8| {
        let s = f64::from(c) / 255.0;
        if s <= 0.03928 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    };
    let (r, g, b) = rgb(hex);
    0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

/// WCAG contrast ratio of two normalised colours.
pub fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

fn hex((r, g, b): (u8, u8, u8)) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

/// `a` mixed toward `b` by `t` (0 = a, 1 = b).
fn mix(a: &str, b: &str, t: f64) -> String {
    let ((ar, ag, ab), (br, bg, bb)) = (rgb(a), rgb(b));
    let m = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round() as u8;
    hex((m(ar, br), m(ag, bg), m(ab, bb)))
}

/// The accent moved toward `toward` (black or white) in small steps until it reads at
/// `MIN_CONTRAST` on every surface in `on`.
fn readable(accent: &str, toward: &str, on: &[&str]) -> String {
    (0..=50)
        .map(|i| mix(accent, toward, f64::from(i) / 50.0))
        .find(|c| on.iter().all(|s| contrast(c, s) >= MIN_CONTRAST))
        .unwrap_or_else(|| toward.to_string())
}

/// Accent, text and tint for a colour value (normalised first).
pub fn derive(value: &str) -> Result<HostColor> {
    let accent = normalize(value)?;
    let text = if luminance(&accent) > DARK_TEXT_ABOVE { "#000000" } else { "#ffffff" }.to_string();
    let alpha = (TINT_ALPHA * 255.0).round() as u8;
    let tint = format!("{accent}{alpha:02x}");
    let named = nearest_preset(&accent).to_string();
    let bg_light = mix(SURFACE_LIGHT, &accent, TINT_ALPHA);
    let bg_dark = mix(SURFACE_DARK, &accent, TINT_ALPHA);
    let fg_light = readable(&accent, "#000000", &["#ffffff", SURFACE_LIGHT, &bg_light]);
    let fg_dark = readable(&accent, "#ffffff", &["#1e1e1e", SURFACE_DARK, &bg_dark]);
    Ok(HostColor { accent, text, tint, named, privileged: false, fg_light, bg_light, fg_dark, bg_dark })
}

/// Label of the preset closest to `accent` (custom hex values map to a named colour).
pub fn nearest_preset(accent: &str) -> &'static str {
    let (r, g, b) = rgb(accent);
    let dist = |h: &str| {
        let (pr, pg, pb) = rgb(h);
        let d = |x: u8, y: u8| (i32::from(x) - i32::from(y)).pow(2);
        d(r, pr) + d(g, pg) + d(b, pb)
    };
    PRESETS.iter().min_by_key(|(h, _)| dist(h)).map_or("Grey", |(_, l)| l)
}

/// Colour for a resolved connection: its effective value, else red when it is privileged.
fn resolved_color(r: &crate::model::ResolvedConnection) -> Option<HostColor> {
    let privileged = r.connection.classification.privileged_infrastructure;
    let value = r.effective.host_color.as_deref().filter(|v| derive(v).is_ok());
    let value = value.or(if privileged { Some(PRIVILEGED_DEFAULT) } else { None })?;
    derive(value).ok().map(|c| HostColor { privileged, ..c })
}

/// The effective colour of a connection (own value, else nearest folder's, else red when it is
/// privileged), or `None`. A stored value that no longer parses (hand-edited file) counts as unset.
pub fn for_connection(doc: &Document, id: Uuid) -> Result<Option<HostColor>> {
    Ok(resolved_color(&doc.resolve(id)?))
}

/// Every connection's colour, in one pass over the tree (`for_connection` resolves one connection
/// with a walk of the whole tree; asking for each of 5,000 connections was quadratic: ~120 ms per
/// library edit on the Mac, 2026-11-15). Connections without a colour are left out.
///
/// Folders are included too (UI-01: the tree tints a folder's icon): a folder's own colour, else
/// the nearest parent folder's. The root is left out.
pub fn all(doc: &Document) -> Vec<(Uuid, HostColor)> {
    let mut out: Vec<(Uuid, HostColor)> =
        doc.connections().into_iter().filter_map(|r| Some((r.connection.id, resolved_color(&r)?))).collect();
    fn walk(f: &crate::model::Folder, inherited: Option<&str>, out: &mut Vec<(Uuid, HostColor)>) {
        for child in &f.children {
            if let crate::model::Node::Folder(sub) = child {
                let own = sub.defaults.host_color.as_deref().filter(|v| derive(v).is_ok()).or(inherited);
                if let Some(c) = own.and_then(|v| derive(v).ok()) {
                    out.push((sub.id, c));
                }
                walk(sub, own, out);
            }
        }
    }
    let root = doc.root.defaults.host_color.as_deref().filter(|v| derive(v).is_ok());
    walk(&doc.root, root, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Connection, Node, Protocol};

    #[test]
    fn all_matches_for_connection_and_skips_uncoloured() {
        let mut doc = Document::new("t");
        let mut red = Connection::new("red", Protocol::Ssh, "a");
        red.settings.host_color = Some("#d64545".into());
        let plain = Connection::new("plain", Protocol::Ssh, "b");
        let (red_id, plain_id) = (red.id, plain.id);
        doc.insert(None, Node::Connection(red)).unwrap();
        doc.insert(None, Node::Connection(plain)).unwrap();
        let all = all(&doc);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, red_id);
        assert_eq!(Some(all[0].1.clone()), for_connection(&doc, red_id).unwrap());
        assert_eq!(for_connection(&doc, plain_id).unwrap(), None);
    }

    #[test]
    fn normalises_short_long_and_preset_forms() {
        assert_eq!(normalize("#ABC").unwrap(), "#aabbcc");
        assert_eq!(normalize(" 3B6FD6 ").unwrap(), "#3b6fd6");
        assert_eq!(normalize("red").unwrap(), "#d64545");
    }

    #[test]
    fn refuses_non_colours() {
        for bad in ["", "#", "#12", "#12345g", "blurple", "#1234567"] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn picks_readable_text() {
        assert_eq!(derive("#ffffff").unwrap().text, "#000000");
        assert_eq!(derive("#d9b72b").unwrap().text, "#000000");
        assert_eq!(derive("#3b6fd6").unwrap().text, "#ffffff");
        assert_eq!(derive("#000").unwrap().text, "#ffffff");
    }

    #[test]
    fn tint_is_accent_with_low_alpha() {
        assert_eq!(derive("#3b6fd6").unwrap().tint, "#3b6fd62e");
    }

    #[test]
    fn tones_pass_contrast_in_light_and_dark() {
        let mut samples: Vec<String> = PRESETS.iter().map(|(h, _)| (*h).to_string()).collect();
        samples.extend(["#ffff00", "#00ffff", "#000080", "#ffffff", "#000000", "#123456"].map(String::from));
        for s in samples {
            let c = derive(&s).unwrap();
            for surface in ["#ffffff", SURFACE_LIGHT, &c.bg_light] {
                assert!(contrast(&c.fg_light, surface) >= MIN_CONTRAST, "{s} light on {surface}: {}", contrast(&c.fg_light, surface));
            }
            for surface in ["#1e1e1e", SURFACE_DARK, &c.bg_dark] {
                assert!(contrast(&c.fg_dark, surface) >= MIN_CONTRAST, "{s} dark on {surface}: {}", contrast(&c.fg_dark, surface));
            }
        }
    }

    #[test]
    fn custom_hex_maps_to_nearest_preset() {
        assert_eq!(derive("#e04040").unwrap().named, "Red");
        assert_eq!(derive("#3070e0").unwrap().named, "Blue");
    }

    #[test]
    fn privileged_without_colour_is_red_and_own_colour_wins() {
        let mut doc = Document::new("t");
        let mut p = Connection::new("dc", Protocol::Rdp, "a");
        p.classification.privileged_infrastructure = true;
        let mut q = p.clone();
        q.id = Uuid::new_v4();
        q.settings.host_color = Some("#3b6fd6".into());
        let (pid, qid) = (p.id, q.id);
        doc.insert(None, Node::Connection(p)).unwrap();
        doc.insert(None, Node::Connection(q)).unwrap();
        let pc = for_connection(&doc, pid).unwrap().unwrap();
        assert_eq!((pc.accent.as_str(), pc.privileged), (PRIVILEGED_DEFAULT, true));
        assert_eq!(for_connection(&doc, qid).unwrap().unwrap().named, "Blue");
        assert_eq!(all(&doc).len(), 2);
    }

    #[test]
    fn folders_carry_own_or_inherited_colour() {
        use crate::model::{Extra, Folder, Settings};
        let folder = |n: &str| Folder { id: Uuid::new_v4(), name: n.into(), color: None, defaults: Settings::default(), children: vec![], dynamic_task_id: None, extra: Extra::new() };
        let mut doc = Document::new("t");
        let mut red = folder("red");
        red.defaults.host_color = Some("Red".into());
        let inner = folder("inner");
        let (red_id, inner_id) = (red.id, inner.id);
        doc.insert(None, Node::Folder(red)).unwrap();
        doc.insert(Some(red_id), Node::Folder(inner)).unwrap();
        let all = all(&doc);
        assert!(all.iter().any(|(id, c)| *id == red_id && c.named == "Red"));
        assert!(all.iter().any(|(id, c)| *id == inner_id && c.named == "Red"));
    }

    #[test]
    fn every_preset_is_normalised() {
        for (hex, _) in PRESETS {
            assert_eq!(normalize(hex).unwrap(), *hex);
        }
    }
}
