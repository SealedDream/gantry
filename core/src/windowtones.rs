//! Window colours derived from a terminal theme (UI-06, decision D13): the sidebar, tab strip and toolbar
//! take two fixed lightness steps from the active tab's terminal background, with text that keeps at least
//! 4.5:1 contrast on every surface. Pure colour maths, shared by every app so all four look the same.
use crate::termthemes::contrast;

/// Minimum WCAG contrast for every text colour on every derived surface.
pub const MIN_TEXT_CONTRAST: f64 = 4.5;
/// OKLab lightness change per step.
const STEP: f64 = 0.04;
/// Chroma cap, so saturated themes give quiet chrome.
const MAX_CHROMA: f64 = 0.04;
/// Text floor with Increase Contrast on, and its larger step.
pub const MIN_TEXT_CONTRAST_HIGH: f64 = 7.0;
const STEP_HIGH: f64 = 0.06;
/// Non-text floor for the accent (selection, focus ring).
pub const MIN_ACCENT_CONTRAST: f64 = 3.0;
const LIGHT_TEXT: u32 = 0xF2F2F2;
const DARK_TEXT: u32 = 0x1A1A1A;

/// Colours as `0xRRGGBB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowTones {
    pub active_tab: u32,
    pub tab_strip: u32,
    pub toolbar: u32,
    pub sidebar: u32,
    pub separator: u32,
    pub text: u32,
    pub secondary_text: u32,
    pub is_dark: bool,
}

/// Tones for a theme with this background and foreground. `increased_contrast` (macOS Increase Contrast) raises the
/// text floor to 7:1 and the step to 0.06 L.
pub fn window_tones(background: u32, foreground: u32, increased_contrast: bool) -> WindowTones {
    let (floor, step_l) = if increased_contrast { (MIN_TEXT_CONTRAST_HIGH, STEP_HIGH) } else { (MIN_TEXT_CONTRAST, STEP) };
    let start = Lab::from_rgb(background & 0xFF_FFFF).cap_chroma(MAX_CHROMA);
    let is_dark = start.l < 0.5;
    let dir = if is_dark { 1.0 } else { -1.0 };
    let foreground = foreground & 0xFF_FFFF;
    // A mid-tone base can't carry readable text on all three steps: move it away from mid-grey until it can.
    let mut base = start;
    loop {
        let t = derive(base, dir, step_l, foreground, floor, is_dark);
        let surfaces = [t.active_tab, t.tab_strip, t.sidebar];
        let ok = surfaces.iter().all(|s| contrast(t.text, *s) >= floor);
        let edge = if is_dark { base.l <= 0.0 } else { base.l >= 1.0 };
        if ok || edge {
            return t;
        }
        base = base.with_l(base.l - dir * 0.01);
    }
}

/// True when the accent reaches 3:1 (non-text floor) on every surface; otherwise apps draw selection with `text`.
pub fn accent_usable(accent: u32, tones: &WindowTones) -> bool {
    [tones.active_tab, tones.tab_strip, tones.sidebar].iter().all(|s| contrast(accent & 0xFF_FFFF, *s) >= MIN_ACCENT_CONTRAST)
}

fn derive(base: Lab, dir: f64, step_l: f64, foreground: u32, floor: f64, is_dark: bool) -> WindowTones {
    let step = |n: f64| base.with_l(base.l + dir * step_l * n).to_rgb();
    let (active_tab, strip, sidebar) = (step(0.0), step(1.0), step(2.0));
    let surfaces = [active_tab, strip, sidebar];
    let min_on = |c: u32| surfaces.iter().map(|s| contrast(c, *s)).fold(f64::MAX, f64::min);
    let text = if min_on(foreground) >= floor {
        foreground
    } else if min_on(LIGHT_TEXT) >= min_on(DARK_TEXT) {
        LIGHT_TEXT
    } else {
        DARK_TEXT
    };
    WindowTones {
        active_tab,
        tab_strip: strip,
        toolbar: strip,
        sidebar,
        separator: step(3.0),
        text,
        secondary_text: secondary(text, sidebar, floor, &min_on),
        is_dark,
    }
}

/// `text` blended toward `surface` as far as possible while staying at or above the contrast floor.
/// When `text` is already at the floor, no blend passes and `text` itself is returned.
fn secondary(text: u32, surface: u32, floor: f64, min_on: &dyn Fn(u32) -> f64) -> u32 {
    let mut best = text;
    for i in 1..=10 {
        let c = mix(text, surface, i as f64 * 0.05);
        if min_on(c) < floor {
            break;
        }
        best = c;
    }
    best
}

fn mix(a: u32, b: u32, t: f64) -> u32 {
    let ch = |s: u32| {
        let (x, y) = ((a >> s & 0xff) as f64, (b >> s & 0xff) as f64);
        ((x + (y - x) * t).round() as u32) << s
    };
    ch(16) | ch(8) | ch(0)
}

#[derive(Clone, Copy)]
struct Lab {
    l: f64,
    a: f64,
    b: f64,
}

fn to_linear(v: u32) -> f64 {
    let s = v as f64 / 255.0;
    if s <= 0.04045 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
}

/// Out-of-gamut results are clipped per channel in linear sRGB; with chroma capped at 0.04 the shift is tiny, and
/// contrast is always checked on the clipped colour that is actually returned.
fn to_srgb(v: f64) -> u32 {
    let v = v.clamp(0.0, 1.0);
    let s = if v <= 0.003_130_8 { v * 12.92 } else { 1.055 * v.powf(1.0 / 2.4) - 0.055 };
    (s * 255.0).round().clamp(0.0, 255.0) as u32
}

impl Lab {
    fn from_rgb(c: u32) -> Lab {
        let (r, g, b) = (to_linear(c >> 16 & 0xff), to_linear(c >> 8 & 0xff), to_linear(c & 0xff));
        let l = (0.412_221_470_8 * r + 0.536_332_536_3 * g + 0.051_445_992_9 * b).cbrt();
        let m = (0.211_903_498_2 * r + 0.680_699_545_1 * g + 0.107_396_956_6 * b).cbrt();
        let s = (0.088_302_461_9 * r + 0.281_718_837_6 * g + 0.629_978_700_5 * b).cbrt();
        Lab {
            l: 0.210_454_255_3 * l + 0.793_617_785 * m - 0.004_072_046_8 * s,
            a: 1.977_998_495_1 * l - 2.428_592_205 * m + 0.450_593_709_9 * s,
            b: 0.025_904_037_1 * l + 0.782_771_766_2 * m - 0.808_675_766 * s,
        }
    }

    fn to_rgb(self) -> u32 {
        let l = (self.l + 0.396_337_777_4 * self.a + 0.215_803_757_3 * self.b).powi(3);
        let m = (self.l - 0.105_561_345_8 * self.a - 0.063_854_172_8 * self.b).powi(3);
        let s = (self.l - 0.089_484_177_5 * self.a - 1.291_485_548 * self.b).powi(3);
        let r = 4.076_741_662_1 * l - 3.307_711_591_3 * m + 0.230_969_929_2 * s;
        let g = -1.268_438_004_6 * l + 2.609_757_401_1 * m - 0.341_319_396_5 * s;
        let b = -0.004_196_086_3 * l - 0.703_418_614_7 * m + 1.707_614_701 * s;
        to_srgb(r) << 16 | to_srgb(g) << 8 | to_srgb(b)
    }

    fn cap_chroma(self, max: f64) -> Lab {
        let c = self.a.hypot(self.b);
        if c <= max { self } else { Lab { a: self.a * max / c, b: self.b * max / c, ..self } }
    }

    fn with_l(self, l: f64) -> Lab {
        Lab { l: l.clamp(0.0, 1.0), ..self }
    }
}
