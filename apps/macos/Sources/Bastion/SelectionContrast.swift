import Foundation

/// WCAG 2 contrast for selection fills. Pure maths on sRGB components (0…1), so the rules are
/// unit-tested without AppKit (tests/selection-contrast).
///
/// A selected tree row is filled with the accent and carries white text (AppKit's emphasized
/// style). Several palette accents (cyan, emerald, amber, rose) are too light for white text, so
/// the fill is the accent darkened just enough for white text to reach `minimumRatio`.
enum SelectionContrast {
    /// WCAG AA for body text.
    static let requiredRatio = 4.5
    /// The fill aims a little above AA so rounding and antialiasing never land under it.
    static let minimumRatio = 4.6
    /// Darkening step towards black while searching for a readable fill.
    static let darkenStep = 0.01

    struct RGB: Equatable {
        var r: Double, g: Double, b: Double
        static let white = RGB(r: 1, g: 1, b: 1)
        static let black = RGB(r: 0, g: 0, b: 0)

        func mixed(with other: RGB, _ t: Double) -> RGB {
            RGB(r: r + (other.r - r) * t, g: g + (other.g - g) * t, b: b + (other.b - b) * t)
        }
    }

    /// Relative luminance (WCAG 2).
    static func luminance(_ c: RGB) -> Double {
        func lin(_ v: Double) -> Double { v <= 0.04045 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4) }
        return 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b)
    }

    /// Contrast ratio, 1…21.
    static func ratio(_ a: RGB, _ b: RGB) -> Double {
        let la = luminance(a), lb = luminance(b)
        return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
    }

    /// The accent, darkened only as far as white text on it needs to reach `minimumRatio`.
    static func readableFill(for accent: RGB) -> RGB {
        var t = 0.0
        var fill = accent
        while ratio(.white, fill) < minimumRatio, t < 1 {
            t += darkenStep
            fill = accent.mixed(with: .black, t)
        }
        return fill
    }
}
