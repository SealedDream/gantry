using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// Access to the design tokens (Themes/*.xaml) from code. Code-built UI (tabs, inspector rows, dialog forms) uses
/// these instead of literals, like the XAML does.
/// </summary>
internal static class Ui
{
    private static readonly Windows.UI.ViewManagement.AccessibilitySettings Accessibility = new();

    private static object Res(string key) => Application.Current.Resources[key];

    public static double Double(string key) => (double)Res(key);
    public static string String(string key) => (string)Res(key);
    public static Thickness Thickness(string key) => (Thickness)Res(key);
    public static CornerRadius Radius(string key) => (CornerRadius)Res(key);
    public static GridLength Length(string key) => (GridLength)Res(key);
    public static Style Style(string key) => (Style)Res(key);

    /// <summary>
    /// Whether a high-contrast theme is on. Read once and then kept current by the settings' change event: each live read
    /// is a WinRT call (3-4 ms per UI stall while library rows are built, WIN-SPEED-ROOTCAUSE), and every row icon asks.
    /// </summary>
    public static bool HighContrast => _highContrast ??= WatchHighContrast();

    private static bool? _highContrast;

    private static bool WatchHighContrast()
    {
        try
        {
            Accessibility.HighContrastChanged += (s, _) => { try { _highContrast = s.HighContrast; } catch { _highContrast = false; } };
            return Accessibility.HighContrast;
        }
        catch { return false; }
    }

    /// <summary>
    /// A colour token for the theme <paramref name="scope"/> is actually drawn in. Application.Current.Resources
    /// would answer for the app's theme instead, which is wrong for an element with its own RequestedTheme (the
    /// snapshot renderer switches the root between Light and Dark), so this reads the theme dictionaries directly.
    /// </summary>
    public static Brush Brush(FrameworkElement scope, string key)
    {
        var theme = HighContrast ? "HighContrast" : scope.ActualTheme == ElementTheme.Light ? "Light" : "Dark";
        foreach (var dictionary in Application.Current.Resources.MergedDictionaries)
        {
            if (dictionary.ThemeDictionaries.TryGetValue(theme, out var themed)
                && themed is ResourceDictionary rd && rd.TryGetValue(key, out var value) && value is Brush brush)
                return brush;
        }
        return (Brush)Res(key);
    }

    /// <summary>A Color or SolidColorBrush token from one theme dictionary ("Light", "Dark"), or null if absent.</summary>
    public static Windows.UI.Color? ThemeColor(string theme, string key)
    {
        foreach (var dictionary in Application.Current.Resources.MergedDictionaries)
        {
            if (!dictionary.ThemeDictionaries.TryGetValue(theme, out var themed) || themed is not ResourceDictionary rd || !rd.TryGetValue(key, out var value)) continue;
            if (value is Windows.UI.Color color) return color;
            if (value is SolidColorBrush brush) return brush.Color;
        }
        return null;
    }

    /// <summary>A symbol-font icon (Segoe Fluent Icons, falling back to Segoe MDL2 Assets on Windows 10).</summary>
    public static FontIcon Icon(string glyphKey, string sizeKey = "IconSize") => new()
    {
        Glyph = (string)Res(glyphKey),
        FontFamily = (FontFamily)Res("SymbolFontFamily"),
        FontSize = Double(sizeKey),
    };

    /// <summary>Turn a text button into a quiet icon button with a tooltip (button restyle). The text becomes its automation name
    /// unless one is already set, so tests and screen readers still find it.</summary>
    public static Button Quiet(this Button b, string glyph, string tip)
    {
        if (b.Content is string text && string.IsNullOrEmpty(AutomationProperties.GetName(b))) AutomationProperties.SetName(b, text);
        b.Content = Icon(glyph);
        b.Style = Style("SubtleButtonStyle");
        ToolTipService.SetToolTip(b, tip);
        return b;
    }

    /// <summary>A text block in one of the type-ramp styles (Themes/Tokens.xaml).</summary>
    public static TextBlock Text(string text, string styleKey) => new() { Text = text, Style = Style(styleKey) };

    /// <summary>Icon followed by a label, the content of toolbar-style buttons.</summary>
    public static StackPanel IconLabel(IconElement icon, string label) => new()
    {
        Orientation = Orientation.Horizontal,
        Spacing = Double("Space8"),
        Children = { icon, new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center } },
    };
}
