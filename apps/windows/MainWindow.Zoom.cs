using System;
using System.Globalization;
using System.Linq;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.System;

namespace Bastion.Shell;

// Window zoom (appearance.zoom, core/src/settings.rs) scales the whole window and is set only in Settings > Appearance
// (owner point 13). Every zoom key (Ctrl+= / - / 0, the keypad, Ctrl+Shift+= / - / 0) sizes the terminal text only.
//
// How: RootGrid is laid out at the window's size divided by the zoom and then scaled by it, so panels reflow to the
// smaller logical size instead of being clipped, and text is rasterised at the final scale (it stays sharp). The system
// display scale is never touched. Menus and tooltips are popups outside RootGrid and keep the system size.
public sealed partial class MainWindow
{
    private const int ActualSizePercent = 100;

    /// <summary>The zoom steps in percent, from the setting's choices; 100 alone when the core offers none.</summary>
    private static int[] ZoomSteps
    {
        get
        {
            var steps = SettingsClient.Definitions().FirstOrDefault(d => d.Id == "appearance.zoom")?.Options
                .Select(o => int.TryParse(o.Id, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0)
                .Where(v => v > 0).OrderBy(v => v).ToArray();
            return steps is { Length: > 0 } ? steps : [ActualSizePercent];
        }
    }

    /// <summary>The saved zoom in percent (100 when unset or unreadable).</summary>
    private int ZoomPercent =>
        int.TryParse(SettingValue("appearance.zoom"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v > 0 ? v : ActualSizePercent;

    private void InitZoom()
    {
        SizeChanged += (_, _) => ApplyZoom();
        ApplyZoom();
    }

    /// <summary>One step in (+1) or out (-1), or back to 100% (0); saved at once, so it survives a restart.</summary>
    private bool StepZoom(int step)
    {
        var steps = ZoomSteps;
        var now = ZoomPercent;
        var next = step switch
        {
            0 => ActualSizePercent,
            > 0 => steps.FirstOrDefault(s => s > now, steps[^1]),
            _ => steps.LastOrDefault(s => s < now, steps[0]),
        };
        if (next != now)
        {
            try { Settings.Set("appearance.zoom", next.ToString(CultureInfo.InvariantCulture)); }
            catch (BastionException ex)
            {
                Announce("Zoom not saved: " + ex.Message);
                return true;
            }
            ApplyZoom();
        }
        Announce($"Zoom {next}%");
        return true;
    }

    /// <summary>Scale RootGrid, and the Settings window, to the saved zoom.</summary>
    private void ApplyZoom()
    {
        var z = ZoomPercent / (double)ActualSizePercent;
        _zoomFactor = z;
        GrowToMinimum();
        ScaleToZoom(RootGrid, Bounds, z);
        _settingsWindow?.SetZoom(z);
    }

    /// <summary>The applied zoom as a factor (1 = 100%); the minimum window size scales with it (MainWindow.MinSize.cs).</summary>
    private double _zoomFactor = 1;

    /// <summary>A zoom raised in Settings can leave the window under the new minimum: grow it to the minimum.</summary>
    private void GrowToMinimum()
    {
        if (_fullScreen || AppWindow.Presenter is Microsoft.UI.Windowing.OverlappedPresenter { State: Microsoft.UI.Windowing.OverlappedPresenterState.Maximized }) return;
        var (w, h) = MinimumWindowSize(Hwnd);
        var size = AppWindow.Size;
        if (size.Width >= w && size.Height >= h) return;
        AppWindow.Resize(new Windows.Graphics.SizeInt32(Math.Max(size.Width, w), Math.Max(size.Height, h)));
    }

    /// <summary>
    /// Lay a window's root out at the window size divided by the zoom and scale it by the zoom, so it reflows instead of
    /// being clipped. Shared by the main window and the Settings window so both follow appearance.zoom.
    /// </summary>
    internal static void ScaleToZoom(FrameworkElement root, Windows.Foundation.Rect bounds, double z)
    {
        if (Math.Abs(z - 1) < 0.001)
        {
            root.RenderTransform = null;
            root.ClearValue(FrameworkElement.WidthProperty);
            root.ClearValue(FrameworkElement.HeightProperty);
            return;
        }
        if (bounds.Width <= 0 || bounds.Height <= 0) return;
        root.HorizontalAlignment = HorizontalAlignment.Left;
        root.VerticalAlignment = VerticalAlignment.Top;
        root.Width = bounds.Width / z;
        root.Height = bounds.Height / z;
        root.RenderTransform = new ScaleTransform { ScaleX = z, ScaleY = z };
    }

    /// <summary>
    /// Ctrl with the keypad +, - or 0 zooms the window too. The main-row Ctrl++ is Ctrl+Shift+= on most layouts, which is
    /// terminal text zoom, so the keypad keys are the other window-zoom keys.
    /// </summary>
    private bool ZoomKeypadKey(VirtualKey key, bool ctrl, bool alt, bool shift)
    {
        if (!ctrl || alt || shift) return false;
        return key switch
        {
            VirtualKey.Add => Zoom(+1),
            VirtualKey.Subtract => Zoom(-1),
            VirtualKey.NumberPad0 => Zoom(0),
            _ => false,
        };
    }

    // Menu items size the terminal text, like their shortcuts (owner point 13).
    private void ZoomIn_Click(object sender, RoutedEventArgs e) => Zoom(+1);

    private void ZoomOut_Click(object sender, RoutedEventArgs e) => Zoom(-1);

    private void ZoomReset_Click(object sender, RoutedEventArgs e) => Zoom(0);

    /// <summary>Snapshot mode: the window's zoom in percent.</summary>
    internal int ZoomForSnapshot => ZoomPercent;
}
