using Bastion.Shell.Interop;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Bastion.Shell;

// Settings › Appearance and Terminal on Windows, from the same settings.json and core values as macOS:
// - appearance.accent: the core's palette colour replaces the Windows accent: Themes/Accent.xaml's brushes (which Fluent's
//   accent keys and Colors.xaml alias) are recoloured in place, so selections, primary buttons and accent text follow it.
// - appearance.density: the core's metrics (core/src/theme.rs) size tree rows and icons and space the inspector's rows.
// - terminal.font-size: every open terminal pane re-measures its cells and tells its program the new grid size.
public sealed partial class MainWindow
{
    /// <summary>A tree row draws its selection 1 px inside the row above and below (LibraryRow), so a row is the core's height plus 2.</summary>
    private const double TreeRowInset = 2;
    /// <summary>The inspector's text line; the rest of the core's inspector row is spacing between rows.</summary>
    private const double InspectorLineHeight = 16;

    /// <summary>Accent.xaml's brushes with the shade each takes in the Light and the Dark theme (Fluent's mapping).</summary>
    private static readonly (string Key, string Light, string Dark)[] AccentBrushes =
    [
        ("AccentFillColorDefaultBrush", "Dark1", "Light2"), ("AccentFillColorSecondaryBrush", "Dark1", "Light2"),
        ("AccentFillColorTertiaryBrush", "Dark1", "Light2"), ("AccentTextFillColorPrimaryBrush", "Dark2", "Light3"),
        ("AccentTextFillColorSecondaryBrush", "Dark3", "Light3"), ("AccentTextFillColorTertiaryBrush", "Dark1", "Light2"),
    ];

    private Dictionary<string, string>? _accents;
    /// <summary>The item the inspector shows (set by UpdateInspector).</summary>
    private string? _inspectedId;
    private ThemeMetricsDto _metrics = new(26, 16, 16, 24);

    private double TerminalFontSize => double.TryParse(SettingValue("terminal.font-size"), out var v) ? v : TerminalView.DefaultFontSize;

    private double TreeRowHeight => _metrics.TreeRow + TreeRowInset;

    private double InspectorRowSpacing => Math.Max(0, _metrics.InspectorRow - InspectorLineHeight);

    /// <summary>Accent and density at startup, before the first tree load (the terminal font size is read as each terminal opens).</summary>
    private void ApplyAppearance()
    {
        // The header style first: an error in the steps below must not leave the XAML's Classic controls showing.
        ApplyHeader();
        ApplyAccent(SettingValue("appearance.accent"));
        ApplyDensity(SettingValue("appearance.density"), reload: false);
        ApplyTabOrientation(SettingValue("tabs.vertical") == "true");
    }

    private void ApplyAccent(string id)
    {
        try { _accents ??= LibraryClient.ThemeAccents(); }
        catch (BastionException) { return; }
        if (!_accents.TryGetValue(id, out var hex) && !_accents.TryGetValue("electric", out hex)) return;
        var accent = ParseHex(hex);
        // Fluent's shades: darker ones carry the accent on light backgrounds, lighter ones on dark backgrounds.
        var d1 = AccentContrast.ReadableDarken(new AccentContrast.Rgb(accent.R, accent.G, accent.B));
        var shade = new Dictionary<string, Color>
        {
            ["Light1"] = Mix(accent, Colors.White, 0.25), ["Light2"] = Mix(accent, Colors.White, 0.45), ["Light3"] = Mix(accent, Colors.White, 0.65),
            // Dark1 is the fill behind white text: Fluent's 15 % or darker where white text would be under 4.5:1
            // (AccentContrast); the text shades stay 15 and 30 points darker than it.
            ["Dark1"] = Mix(accent, Colors.Black, d1), ["Dark2"] = Mix(accent, Colors.Black, Math.Max(0.30, d1 + 0.15)),
            ["Dark3"] = Mix(accent, Colors.Black, Math.Max(0.45, d1 + 0.30)),
        };
        // Recolour Accent.xaml's brush objects in place: everything drawn with them follows at once, in both themes.
        var accentFile = Application.Current.Resources.MergedDictionaries.FirstOrDefault(d => d.Source?.AbsolutePath.EndsWith("/Themes/Accent.xaml", StringComparison.OrdinalIgnoreCase) == true);
        if (accentFile is null) return;
        foreach (var (theme, pick) in new[] { ("Light", 0), ("Default", 1) })
        {
            if (!accentFile.ThemeDictionaries.TryGetValue(theme, out var found) || found is not ResourceDictionary d) continue;
            foreach (var (key, light, dark) in AccentBrushes)
                if (d.TryGetValue(key, out var value) && value is SolidColorBrush brush) brush.Color = shade[pick == 0 ? light : dark];
        }
    }

    private void ApplyDensity(string id, bool reload = true)
    {
        try { _metrics = LibraryClient.ThemeMetrics(id); }
        catch (BastionException) { return; }
        // WIN-FLAT-TREE: the rows take the core's height (plus the 1 px fill inset above and below) directly.
        Tree.RowHeight = TreeRowHeight;
        // New rows take the new height and the inspector is rebuilt with the new spacing. The inspected item stands in for a
        // selection that is still being applied (SelectItem sets it after layout).
        if (reload) Reload(CurrentSelectionId);
    }

    private void ApplyTerminalFontSize(double size)
    {
        // A zoomed tab keeps its offset from the new size.
        foreach (var tab in _tabs) foreach (var pane in tab.AllPanes) pane.SetFontSize((pane.FontOverride.Size ?? size) + tab.Zoom);
    }

    /// <summary>Icon size of a realised tree row (density); called as rows are created or recycled.</summary>
    private void ApplyRowDensity(LibraryRow container)
    {
        if (container.Content is StackPanel { Children.Count: > 0 } row && row.Children[0] is Grid icon)
        {
            icon.Width = icon.Height = _metrics.TreeIcon;
            foreach (var glyph in icon.Children.OfType<FontIcon>()) glyph.FontSize = _metrics.TreeIcon;
        }
    }

    private static Color ParseHex(string hex) =>
        Color.FromArgb(0xFF, Convert.ToByte(hex[1..3], 16), Convert.ToByte(hex[3..5], 16), Convert.ToByte(hex[5..7], 16));

    private static Color Mix(Color from, Color to, double amount) => Color.FromArgb(0xFF,
        (byte)Math.Round(from.R + (to.R - from.R) * amount),
        (byte)Math.Round(from.G + (to.G - from.G) * amount),
        (byte)Math.Round(from.B + (to.B - from.B) * amount));

    // ---- Snapshot hooks (BASTION_SNAPSHOT_SETTINGS) ----

    /// <summary>Snapshot only: change an appearance setting as its control would.</summary>
    internal void SetAppearanceForSnapshot(string id, string value) => SetSetting(id, value);

    /// <summary>Snapshot only: the colour the primary button and the theme dictionaries' accent brush resolve to.</summary>
    internal string AccentProbeForSnapshot()
    {
        static string Hex(Brush? b) => b is SolidColorBrush s ? $"#{s.Color.R:X2}{s.Color.G:X2}{s.Color.B:X2}" : b?.GetType().Name ?? "null";
        var app = Application.Current.Resources;
        var accentFile = app.MergedDictionaries.FirstOrDefault(d => d.Source?.AbsolutePath.EndsWith("/Themes/Accent.xaml", StringComparison.OrdinalIgnoreCase) == true);
        string Dict(string theme) => accentFile is not null && accentFile.ThemeDictionaries.TryGetValue(theme, out var d) && d is ResourceDictionary rd && rd.TryGetValue("AccentFillColorDefaultBrush", out var b) ? Hex(b as Brush) : "missing";
        return $"theme {RootGrid.ActualTheme} (app {Application.Current.RequestedTheme}): primary button {Hex(_inspectorView?.InspectorPrimaryButton.Background)}, " +
               $"Light dict {Dict("Light")}, Default dict {Dict("Default")}, lookup {Hex(RootGrid.Resources.TryGetValue("AccentFillColorDefaultBrush", out var r) ? r as Brush : null)}";
    }
}
