use bastion_core::termthemes::{contrast, BUNDLED};
use bastion_core::windowtones::{accent_usable, window_tones, MIN_TEXT_CONTRAST, MIN_TEXT_CONTRAST_HIGH};

fn assert_readable(name: &str, bg: u32, fg: u32) {
    assert_floor(name, bg, fg, false, MIN_TEXT_CONTRAST);
    assert_floor(name, bg, fg, true, MIN_TEXT_CONTRAST_HIGH);
}

fn assert_floor(name: &str, bg: u32, fg: u32, high: bool, floor: f64) {
    let t = window_tones(bg, fg, high);
    for (what, s) in [("active tab", t.active_tab), ("tab strip", t.tab_strip), ("toolbar", t.toolbar), ("sidebar", t.sidebar)] {
        for (kind, c) in [("text", t.text), ("secondary", t.secondary_text)] {
            let r = contrast(c, s);
            assert!(r >= floor, "{name} {bg:06x} high={high}: {kind} on {what} is {r:.2}");
        }
    }
}

#[test]
fn every_bundled_theme_keeps_text_readable_on_every_surface() {
    for b in BUNDLED {
        assert_readable(b.id, b.theme.background, b.theme.foreground);
    }
}

#[test]
fn extremes_and_saturated_backgrounds_stay_readable() {
    for bg in [0x000000, 0xFFFFFF, 0xFF0000, 0x00FF00, 0x0000FF, 0x808080, 0x777777] {
        assert_readable(&format!("{bg:06x}"), bg, 0x808080);
    }
}

#[test]
fn dark_background_steps_lighter_and_light_steps_darker() {
    let lum = |c: u32| contrast(c, 0);
    let d = window_tones(0x1E1E2E, 0xCDD6F4, false);
    assert!(d.is_dark && lum(d.sidebar) > lum(d.tab_strip) && lum(d.tab_strip) > lum(d.active_tab));
    let l = window_tones(0xFAFAFA, 0x202020, false);
    assert!(!l.is_dark && lum(l.sidebar) < lum(l.tab_strip) && lum(l.tab_strip) < lum(l.active_tab));
}

#[test]
fn readable_theme_foreground_is_kept_and_toolbar_matches_tab_strip() {
    let t = window_tones(0x101010, 0xE0E0E0, false);
    assert_eq!(t.text, 0xE0E0E0);
    assert_eq!(t.toolbar, t.tab_strip);
}

#[test]
fn saturated_background_gives_quiet_chrome() {
    let t = window_tones(0xFF0000, 0xFFFFFF, false);
    let (r, g, b) = (t.sidebar >> 16 & 0xff, t.sidebar >> 8 & 0xff, t.sidebar & 0xff);
    assert!(r.max(g).max(b) - r.min(g).min(b) < 60, "sidebar {:06x} too saturated", t.sidebar);
}

#[test]
fn deterministic_and_ignores_alpha_byte() {
    assert_eq!(window_tones(0xFF282A36, 0xF8F8F2, false), window_tones(0x282A36, 0xF8F8F2, false));
}

#[test]
fn sweep_of_greys_and_hues_stays_readable() {
    for v in (0..=255u32).step_by(5) {
        assert_readable("grey", v << 16 | v << 8 | v, 0x808080);
        for (r, g, b) in [(v, 0, 0), (0, v, 0), (0, 0, v), (v, v, 0), (0, v, v), (v, 0, v), (255, v, 0), (0, 255, v)] {
            assert_readable("hue", r << 16 | g << 8 | b, 0x808080);
        }
    }
}

/// OKLab (L, a, b) to sRGB 0xRRGGBB with per-channel clipping; test-side copy so the sweep is independent.
fn oklab(l: f64, a: f64, b: f64) -> u32 {
    let l_ = (l + 0.3963377774 * a + 0.2158037573 * b).powi(3);
    let m_ = (l - 0.1055613458 * a - 0.0638541728 * b).powi(3);
    let s_ = (l - 0.0894841775 * a - 1.2914855480 * b).powi(3);
    let lin = [
        4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
        -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
        -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_,
    ];
    let c = |v: f64| {
        let v = v.clamp(0.0, 1.0);
        let s = if v <= 0.0031308 { v * 12.92 } else { 1.055 * v.powf(1.0 / 2.4) - 0.055 };
        (s * 255.0).round() as u32
    };
    c(lin[0]) << 16 | c(lin[1]) << 8 | c(lin[2])
}

#[test]
fn sweep_lightness_hue_and_chroma() {
    for li in 0..=100 {
        let l = li as f64 / 100.0;
        for chroma in [0.0, 0.03, 0.08, 0.15] {
            for h in 0..12 {
                let ang = h as f64 * std::f64::consts::PI / 6.0;
                assert_readable("oklab", oklab(l, chroma * ang.cos(), chroma * ang.sin()), 0x808080);
            }
        }
    }
}

#[test]
fn increased_contrast_uses_larger_steps() {
    let lum = |c: u32| contrast(c, 0);
    let n = window_tones(0x1E1E2E, 0xCDD6F4, false);
    let h = window_tones(0x1E1E2E, 0xCDD6F4, true);
    assert!(lum(h.sidebar) > lum(n.sidebar));
}

#[test]
fn accent_fallback_at_three_to_one() {
    let dark = window_tones(0x101010, 0xE0E0E0, false);
    assert!(accent_usable(0x2E6BFF, &window_tones(0xFAFAFA, 0x202020, false)));
    assert!(!accent_usable(0x202020, &dark));
    assert!(accent_usable(0xFFFFFF, &dark));
}
