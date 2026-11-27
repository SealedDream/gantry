using Microsoft.UI.Xaml;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

// Per-connection terminal theme (property terminal_theme, own or inherited from a folder). New tabs take it in
// NewTerminalView; this repaints open tabs after a Properties change, so a session never needs reopening to show it.
public sealed partial class MainWindow
{
    /// <summary>Light app chrome (not dark, not high contrast).</summary>
    private bool LightChrome => !Ui.HighContrast && RootGrid.ActualTheme == ElementTheme.Light;

    /// <summary>The app's terminal colours: the user's scheme, or with Match app theme (the default) Bastion Light in the
    /// light theme and Bastion Dark otherwise, as on the Mac. A light app may keep a dark terminal.</summary>
    private string EffectiveTerminalTheme => AppearanceSettings.TerminalThemeId(_appearance.TerminalTheme, LightChrome);

    /// <summary>Paint every open pane that has no connection theme of its own in the app's terminal colours.</summary>
    private void RepaintAppTerminalTheme()
    {
        var id = EffectiveTerminalTheme;
        foreach (var tab in _tabs)
            foreach (var pane in tab.AllPanes)
            {
                try { if (!pane.OwnTheme) pane.ApplyTheme(id); } catch (BastionException) { /* an exited session keeps its last colours */ }
            }
    }

    /// <summary>After a tree build: give each open connection tab its connection's theme, or the app theme when it has none.</summary>
    private void RepaintConnectionThemes()
    {
        foreach (var tab in _tabs)
        {
            if (tab.ConnectionId is not { } connectionId) continue;
            var own = ConnectionTheme(connectionId);
            foreach (var pane in tab.AllPanes)
            {
                if (own is null && !pane.OwnTheme) continue;
                try { pane.ApplyTheme(own ?? EffectiveTerminalTheme); pane.OwnTheme = own is not null; }
                catch (BastionException) { /* an exited session keeps its last colours */ }
            }
        }
    }

    /// <summary>
    /// The session surface (SessionHost and its padding) takes the active terminal's own background, whatever the app
    /// theme or terminal theme, so no frame of another colour rings the terminal. Other tabs keep the theme's surface.
    /// </summary>
    private void SyncSessionSurface()
    {
        var pane = _active is { Window: null } tab ? tab.AllPanes.FirstOrDefault() : null;
        if (pane is null)
        {
            SyncWindowTones(null);
            SessionHost.Background = Ui.Brush(RootGrid, "SessionBackgroundBrush");
            SessionHost.Padding = (Thickness)Application.Current.Resources["SessionPadding"];
            return;
        }
        // UI-03: a terminal draws its own padding, scaled with its text, so the host adds none.
        SessionHost.Padding = new Thickness(0);
        var bg = pane.BackgroundColor;
        // UI-06: Home and a connection page hide the terminal, so the window takes the stock colours while they show.
        SyncWindowTones(SessionHost.Visibility == Visibility.Visible ? pane : null);
        SessionHost.Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(
            Windows.UI.Color.FromArgb(255, (byte)(bg >> 16), (byte)(bg >> 8), (byte)bg));
    }
}
