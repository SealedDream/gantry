using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

// UI-06: with appearance.window-follows-terminal on, the navigation pane, title bar (tab strip and toolbar), vertical tab
// list and caption buttons take tones from the active terminal tab's theme. The core derives them (ABI 143), so all apps
// match. Off in Windows high contrast: system colours win. Per window: each MainWindow follows its own active tab.
// Applied on tab switch, theme apply and setting change only; never from SizeChanged (LayoutCycle).
public sealed partial class MainWindow
{
    private const string WindowTonesSetting = "appearance.window-follows-terminal";

    /// <summary>The tones in effect for this window; null = stock colours.</summary>
    private WindowTonesDto? _tones;
    private string? _tonesKey;
    /// <summary>Theme foregrounds by "id#background", so a tab switch does not re-read the theme store.</summary>
    private static readonly Dictionary<string, uint> ThemeForegrounds = [];
    private readonly Dictionary<(DependencyObject, DependencyProperty), object> _stockValues = [];

    /// <summary>Automation reads it (UI driver): the tones applied, or "off".</summary>
    internal string WindowTonesReport => _tones is { } t
        ? $"sidebar={t.Sidebar} tabStrip={t.TabStrip} toolbar={t.Toolbar} activeTab={t.ActiveTab} text={t.Text} secondary={t.SecondaryText} dark={t.IsDark} accentUsable={t.AccentUsable}"
        : "off";

    private void SyncWindowTones(TerminalView? pane)
    {
        SyncTornOffTones();
        WindowTonesDto? tones = null;
        string? key = null;
        if (pane is { ThemeId: { } id } && !(Ui.HighContrast || TestHooks.WindowTonesHighContrast) && Settings.Get(WindowTonesSetting) == "true")
        {
            var accent = Ui.Brush(RootGrid, "AccentFillColorDefaultBrush") is SolidColorBrush b ? Rgb(b.Color) : 0x2E6BFFu;
            key = $"{id}#{pane.BackgroundColor:x6}#{accent:x6}";
            if (key == _tonesKey) return;
            try { tones = TermThemes.WindowTones(pane.BackgroundColor, Foreground(id, pane.BackgroundColor), accent); }
            catch (BastionException) { tones = null; } // stock colours; the terminal itself is unaffected
        }
        if (key == _tonesKey && tones is null && _tones is null) return;
        _tonesKey = tones is null ? null : key;
        _tones = tones;
        ApplyWindowTones();
    }

    private static uint Foreground(string id, uint background)
    {
        var key = $"{id}#{background:x6}";
        if (ThemeForegrounds.TryGetValue(key, out var fg)) return fg;
        var theme = TermThemes.List().FirstOrDefault(t => t.Id == id);
        fg = theme is null ? 0xE6E6E6u : Parse(theme.Foreground);
        ThemeForegrounds[key] = fg;
        return fg;
    }

    private void ApplyWindowTones()
    {
        var t = _tones;
        var theme = t is null ? ElementTheme.Default : t.IsDark ? ElementTheme.Dark : ElementTheme.Light;
        Paint(NavPane, Microsoft.UI.Xaml.Controls.Panel.BackgroundProperty, t?.Sidebar);
        NavPane.RequestedTheme = theme;
        if (_titleBar is { } bar)
        {
            Paint(bar, Microsoft.UI.Xaml.Controls.Panel.BackgroundProperty, t?.Toolbar);
            bar.RequestedTheme = theme;
        }
        // Accent under 3:1 on the sidebar tone: the selection bar takes the tones' text colour.
        Tree.SelectionBarOverride = t is { AccentUsable: false } ? new SolidColorBrush(ColorOf(t.Text)) : null;
        Paint(VerticalTabScroller, Microsoft.UI.Xaml.Controls.Control.BackgroundProperty, t?.TabStrip);
        VerticalTabScroller.RequestedTheme = theme;
        // Automation (window-tones-ui-test.ps1) reads the tones in effect from the pane's item status.
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetItemStatus(NavPane, WindowTonesReport);
        _titleBarTheme = null;
        ApplyTitleBarTheme();
        foreach (var tab in _tabs) PaintTab(tab);
    }

    /// <summary>Sets a tone, keeping the stock value (local or style) to put back when the tones go off.</summary>
    private void Paint(DependencyObject target, DependencyProperty property, string? hex)
    {
        var slot = (target, property);
        if (hex is null)
        {
            if (!_stockValues.Remove(slot, out var stock)) return;
            if (stock == DependencyProperty.UnsetValue) target.ClearValue(property);
            else target.SetValue(property, stock);
            return;
        }
        if (!_stockValues.ContainsKey(slot)) _stockValues[slot] = target.ReadLocalValue(property);
        target.SetValue(property, new SolidColorBrush(ColorOf(hex)));
    }

    /// <summary>A tone brush for tab painting, or null when tones are off.</summary>
    private SolidColorBrush? ToneBrush(Func<WindowTonesDto, string> pick) => _tones is { } t ? new SolidColorBrush(ColorOf(pick(t))) : null;

    /// <summary>Caption buttons (minimise, maximise, close) take the toolbar tone and the tones' text colour.</summary>
    private void ApplyTitleBarTones(WindowTonesDto t)
    {
        try
        {
            var bar = AppWindow.TitleBar;
            bar.PreferredTheme = t.IsDark ? Microsoft.UI.Windowing.TitleBarTheme.Dark : Microsoft.UI.Windowing.TitleBarTheme.Light;
            if (!Microsoft.UI.Windowing.AppWindowTitleBar.IsCustomizationSupported()) return;
            var background = ColorOf(t.Toolbar);
            var text = ColorOf(t.Text);
            bar.BackgroundColor = bar.InactiveBackgroundColor = background;
            bar.ButtonBackgroundColor = bar.ButtonInactiveBackgroundColor = background;
            bar.ForegroundColor = bar.ButtonForegroundColor = bar.ButtonHoverForegroundColor = bar.ButtonPressedForegroundColor = text;
            bar.InactiveForegroundColor = bar.ButtonInactiveForegroundColor = ColorOf(t.SecondaryText);
            bar.ButtonHoverBackgroundColor = ColorOf(t.Separator);
            bar.ButtonPressedBackgroundColor = ColorOf(t.Sidebar);
        }
        catch
        {
            // Cosmetic: the default caption buttons stay.
        }
    }

    private static uint Rgb(Windows.UI.Color c) => (uint)(c.R << 16 | c.G << 8 | c.B);
    private static uint Parse(string hex) => Convert.ToUInt32(hex.TrimStart('#'), 16);
    internal static Windows.UI.Color ToneColor(string hex) => ColorOf(hex);

    /// <summary>Each torn-off window takes the tones of its own tab, apart from this window's active tab.</summary>
    private void SyncTornOffTones()
    {
        foreach (var tab in _tabs)
        {
            if (tab.Window is not { } window) continue;
            WindowTonesDto? tones = null;
            if (tab.AllPanes.FirstOrDefault() is { ThemeId: { } id } pane && !(Ui.HighContrast || TestHooks.WindowTonesHighContrast) && Settings.Get(WindowTonesSetting) == "true")
            {
                var accent = Ui.Brush(RootGrid, "AccentFillColorDefaultBrush") is SolidColorBrush b ? Rgb(b.Color) : 0x2E6BFFu;
                try { tones = TermThemes.WindowTones(pane.BackgroundColor, Foreground(id, pane.BackgroundColor), accent); }
                catch (BastionException) { tones = null; }
            }
            window.ApplyTones(tones);
        }
    }

    private static Windows.UI.Color ColorOf(string hex)
    {
        var v = Parse(hex);
        return Windows.UI.Color.FromArgb(255, (byte)(v >> 16), (byte)(v >> 8), (byte)v);
    }
}
