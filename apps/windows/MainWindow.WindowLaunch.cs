using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.UI.Windowing;

namespace Bastion.Shell;

// Settings › General › Window at launch (owner 2026-11-15): remember the last size and position (the default), a fixed
// size, maximised or full screen. The size is fitted to the screen the window opens on (WindowLaunch.cs); a saved
// monitor that is gone falls back to the main screen. The last frame is kept in window.json beside settings.json.
public sealed partial class MainWindow
{
    internal sealed record SavedWindowFrame(int X, int Y, int Width, int Height, bool Maximized);

    [JsonSerializable(typeof(SavedWindowFrame))]
    internal sealed partial class SavedWindowFrameJson : JsonSerializerContext { }

    /// <summary>The last restored (not maximised, not full screen) frame, kept in memory and written on close.</summary>
    private PixelRect? _lastNormalFrame;

    private string WindowFramePath => Path.Combine(ConfigDir, "window.json");

    private SavedWindowFrame? LoadWindowFrame()
    {
        try
        {
            var f = JsonSerializer.Deserialize(File.ReadAllText(WindowFramePath), SavedWindowFrameJson.Default.SavedWindowFrame);
            return f is { Width: > 0, Height: > 0 } ? f : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    /// <summary>Where the window opens and whether it then maximises or goes full screen (applied after the first frame).</summary>
    private PixelRect LaunchFrame(double scale, PixelRect primaryWork, out bool maximize, out bool fullScreen)
    {
        maximize = fullScreen = false;
        var standard = WindowLaunch.Centred((int)(Ui.Double("WindowDefaultWidth") * scale), (int)(Ui.Double("WindowDefaultHeight") * scale), primaryWork);
        if (_demo) return standard; // snapshot and demo runs always open the same way
        var saved = LoadWindowFrame();
        var savedRect = saved is { } s ? new PixelRect(s.X, s.Y, s.Width, s.Height) : (PixelRect?)null;
        var work = savedRect is { } r ? WindowLaunch.WorkAreaFor(r, WorkAreas(), primaryWork) : primaryWork;
        var remembered = savedRect is { } sr ? WindowLaunch.Clamp(sr, work) : standard;
        switch (SettingValue(WindowLaunch.SettingId))
        {
            case WindowLaunch.Fixed:
                var w = int.TryParse(SettingValue(WindowLaunch.WidthId), out var wv) ? wv : 1280;
                var h = int.TryParse(SettingValue(WindowLaunch.HeightId), out var hv) ? hv : 800;
                return WindowLaunch.Centred((int)(w * scale), (int)(h * scale), work);
            case WindowLaunch.Maximized:
                maximize = true;
                return remembered;
            case WindowLaunch.FullScreen:
                fullScreen = true;
                return remembered;
            default:
                maximize = saved?.Maximized == true;
                return remembered;
        }
    }

    /// <summary>Every monitor's work area. Indexed, not enumerated: enumerating DisplayArea.FindAll() can fail in WinAppSDK.</summary>
    private static List<PixelRect> WorkAreas()
    {
        var list = new List<PixelRect>();
        var all = DisplayArea.FindAll();
        for (var i = 0; i < all.Count; i++) { var a = all[i].WorkArea; list.Add(new PixelRect(a.X, a.Y, a.Width, a.Height)); }
        return list;
    }

    private void ApplyLaunchState(bool maximize, bool fullScreen)
    {
        AppWindow.Changed += (_, e) => { if (e.DidPositionChange || e.DidSizeChange) NoteNormalFrame(); };
        NoteNormalFrame();
        if (!maximize && !fullScreen) return;
        Startup.AfterFirstFrame(this, () =>
        {
            if (_windowClosed) return;
            if (fullScreen) { if (!_fullScreen) ToggleFullScreen(); }
            else if (AppWindow.Presenter is OverlappedPresenter p) p.Maximize();
        });
    }

    private void NoteNormalFrame()
    {
        if (_fullScreen || AppWindow.Presenter is not OverlappedPresenter { State: OverlappedPresenterState.Restored }) return;
        _lastNormalFrame = new PixelRect(AppWindow.Position.X, AppWindow.Position.Y, AppWindow.Size.Width, AppWindow.Size.Height);
    }

    /// <summary>On close: write the last restored frame and whether the window was maximised (best effort).</summary>
    private void SaveWindowFrame()
    {
        if (_demo || _lastNormalFrame is not { } f) return;
        var maximized = AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Maximized };
        try { File.WriteAllText(WindowFramePath, JsonSerializer.Serialize(new SavedWindowFrame(f.X, f.Y, f.Width, f.Height, maximized), SavedWindowFrameJson.Default.SavedWindowFrame)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { System.Diagnostics.Debug.WriteLine($"Gantry: window frame not saved: {e.Message}"); }
    }

    /// <summary>Settings › General › Use current size: the window's size in effective pixels becomes the fixed launch size.</summary>
    private void UseCurrentWindowSize()
    {
        var scale = Math.Max(96u, GetDpiForWindow(Hwnd)) / 96.0;
        var f = _lastNormalFrame ?? new PixelRect(0, 0, AppWindow.Size.Width, AppWindow.Size.Height);
        SetSetting(WindowLaunch.WidthId, ((int)Math.Round(f.Width / scale)).ToString(System.Globalization.CultureInfo.InvariantCulture));
        SetSetting(WindowLaunch.HeightId, ((int)Math.Round(f.Height / scale)).ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (_pageKind == "settings") ShowSettingsPage(); // the two fields show the new numbers
    }
}
