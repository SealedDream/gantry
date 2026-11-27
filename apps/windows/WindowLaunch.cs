namespace Bastion.Shell;

/// <summary>A window rectangle in screen pixels (no WinUI types, so tests/window-launch-unit builds it alone).</summary>
public readonly record struct PixelRect(int X, int Y, int Width, int Height)
{
    public int Right => X + Width;
    public int Bottom => Y + Height;
    public bool Intersects(PixelRect o) => X < o.Right && o.X < Right && Y < o.Bottom && o.Y < Bottom;
}

/// <summary>
/// Settings › General › Window at launch (core settings <c>window.launch</c>, <c>window.launch-width</c>,
/// <c>window.launch-height</c>; owner 2026-11-15): how the main window opens, and the size rules shared with the Mac
/// (apps/macos/Sources/Bastion/WindowLaunch.swift).
/// </summary>
public static class WindowLaunch
{
    public const string SettingId = "window.launch";
    public const string WidthId = "window.launch-width";
    public const string HeightId = "window.launch-height";
    public const string Remember = "remember", Fixed = "fixed", Maximized = "maximized", FullScreen = "full-screen";

    /// <summary>A size never larger than the work area, centred in it.</summary>
    public static PixelRect Centred(int width, int height, PixelRect work)
    {
        var w = Math.Clamp(width, 1, Math.Max(1, work.Width));
        var h = Math.Clamp(height, 1, Math.Max(1, work.Height));
        return new PixelRect(work.X + (work.Width - w) / 2, work.Y + (work.Height - h) / 2, w, h);
    }

    /// <summary>A remembered frame fitted to the work area: shrunk to fit, then moved inside it.</summary>
    public static PixelRect Clamp(PixelRect frame, PixelRect work)
    {
        var w = Math.Clamp(frame.Width, 1, Math.Max(1, work.Width));
        var h = Math.Clamp(frame.Height, 1, Math.Max(1, work.Height));
        var x = Math.Clamp(frame.X, work.X, work.Right - w);
        var y = Math.Clamp(frame.Y, work.Y, work.Bottom - h);
        return new PixelRect(x, y, w, h);
    }

    /// <summary>The work area a saved frame belongs to: the one it overlaps most, else the main screen's (its monitor is gone).</summary>
    public static PixelRect WorkAreaFor(PixelRect frame, IReadOnlyList<PixelRect> workAreas, PixelRect main)
    {
        PixelRect? best = null;
        long bestArea = 0;
        foreach (var a in workAreas)
        {
            if (!a.Intersects(frame)) continue;
            long area = (long)(Math.Min(a.Right, frame.Right) - Math.Max(a.X, frame.X)) * (Math.Min(a.Bottom, frame.Bottom) - Math.Max(a.Y, frame.Y));
            if (area > bestArea) { bestArea = area; best = a; }
        }
        return best ?? main;
    }
}
