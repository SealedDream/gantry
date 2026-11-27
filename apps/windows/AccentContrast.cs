namespace Bastion.Shell;

/// <summary>
/// WCAG 2 contrast for accent fills that carry text (owner 2026-11-15: selected connection names were hard to read
/// with some accents). Pure maths on sRGB bytes, so tests\accent-contrast-console checks it without a window.
/// In the light theme an accent fill carries white text (Fluent's TextOnAccentFillColorPrimary); cyan, emerald and
/// amber at Fluent's Dark1 shade were under 4.5:1. <see cref="ReadableFill"/> darkens the accent until white text
/// reaches <see cref="MinimumRatio"/> on the solid and hover fills (<see cref="HoverOpacity"/>).
/// </summary>
public static class AccentContrast
{
    /// <summary>WCAG AA for body text.</summary>
    public const double RequiredRatio = 4.5;
    /// <summary>A little above AA so rounding and antialiasing never land under it.</summary>
    public const double MinimumRatio = 4.6;
    /// <summary>Accent.xaml's secondary (hover) fill opacity. The pressed fill (0.8) shows only while the button is held.</summary>
    public const double HoverOpacity = 0.9;
    /// <summary>Fluent's Dark1 shade: the fill is never lighter than this.</summary>
    public const double MinimumDarken = 0.15;
    private const double Step = 0.01;

    public readonly record struct Rgb(byte R, byte G, byte B)
    {
        public static readonly Rgb White = new(255, 255, 255);
        public static readonly Rgb Black = new(0, 0, 0);

        public Rgb Mix(Rgb to, double t) => new(Lerp(R, to.R, t), Lerp(G, to.G, t), Lerp(B, to.B, t));
        private static byte Lerp(byte a, byte b, double t) => (byte)Math.Round(a + (b - a) * t);
        public override string ToString() => $"#{R:X2}{G:X2}{B:X2}";
    }

    /// <summary>Relative luminance (WCAG 2).</summary>
    public static double Luminance(Rgb c)
    {
        static double Lin(byte v) { var s = v / 255.0; return s <= 0.04045 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4); }
        return 0.2126 * Lin(c.R) + 0.7152 * Lin(c.G) + 0.0722 * Lin(c.B);
    }

    /// <summary>Contrast ratio, 1 to 21.</summary>
    public static double Ratio(Rgb a, Rgb b)
    {
        double la = Luminance(a), lb = Luminance(b);
        return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
    }

    /// <summary>The fill as seen over a white surface at the given opacity.</summary>
    public static Rgb OverWhite(Rgb fill, double opacity) => Rgb.White.Mix(fill, opacity);

    /// <summary>How far (0 to 1) the accent is mixed towards black for the light-theme fill: Fluent's Dark1 or further,
    /// until white text passes on the solid and the hover fill.</summary>
    public static double ReadableDarken(Rgb accent)
    {
        for (var t = MinimumDarken; t < 1; t += Step)
            if (Ratio(Rgb.White, OverWhite(accent.Mix(Rgb.Black, t), HoverOpacity)) >= MinimumRatio) return t;
        return 1;
    }

    /// <summary>The light-theme accent fill (<see cref="ReadableDarken"/>).</summary>
    public static Rgb ReadableFill(Rgb accent) => accent.Mix(Rgb.Black, ReadableDarken(accent));
}
