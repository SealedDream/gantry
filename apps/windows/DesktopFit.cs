namespace Bastion.Shell;

/// <summary>How a remote desktop meets its tab (connection property <c>display.fit</c>, RDP and VNC), as Mac DesktopFit.</summary>
public enum DesktopFit
{
    /// <summary>The server's desktop follows the tab's size; a server that refuses is scaled to fit.</summary>
    Fit,
    /// <summary>The desktop at its own size, one desktop pixel per screen pixel, centred; larger desktops are clipped.</summary>
    Fixed,
    /// <summary>The desktop at its own size, scaled to the tab, keeping its shape.</summary>
    Scale,
}

/// <summary>Pure rules for <see cref="DesktopFit"/> (no UI, so the unit test compiles this file alone).</summary>
public static class DesktopFitRules
{
    public const string PropertyKey = "display.fit";
    public const string ResolutionKey = "rdp.resolution";
    /// <summary>Used before any desktop tab has been laid out.</summary>
    public const int FallbackWidth = 1280, FallbackHeight = 800;
    /// <summary>The smallest and largest size asked of a server (MS-RDPEDISP limits; VNC uses the same).</summary>
    public const int MinSide = 200, MaxSide = 8192;
    /// <summary>A resize is sent once the tab has kept its size this long (as Mac resizeSettle).</summary>
    public static readonly TimeSpan ResizeSettle = TimeSpan.FromMilliseconds(300);

    /// <summary>"fit" (default, also empty or unknown), "fixed" or "scale".</summary>
    public static DesktopFit Parse(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "fixed" => DesktopFit.Fixed,
        "scale" => DesktopFit.Scale,
        _ => DesktopFit.Fit,
    };

    /// <summary>"1920x1080" → (1920, 1080); "window", empty or malformed → null.</summary>
    public static (int Width, int Height)? ParseResolution(string? value) =>
        value?.Split('x') is [var w, var h] && int.TryParse(w, out var pw) && int.TryParse(h, out var ph) && pw > 0 && ph > 0 ? (pw, ph) : null;

    /// <summary>A tab's size in device pixels, clamped to what a server accepts; a tab not laid out yet gives the fallback.</summary>
    public static (int Width, int Height) TabPixels(double width, double height, double rasterScale)
    {
        if (width < 1 || height < 1) return (FallbackWidth, FallbackHeight);
        var scale = rasterScale > 0 ? rasterScale : 1.0;
        return (Math.Clamp((int)Math.Round(width * scale), MinSide, MaxSide), Math.Clamp((int)Math.Round(height * scale), MinSide, MaxSide));
    }

    /// <summary>The size an RDP connect asks for: the tab's for Fit to tab (or Desktop size Window), else the connection's Desktop size.</summary>
    public static (int Width, int Height) ConnectSize(DesktopFit fit, string? resolution, (int Width, int Height) tab) =>
        fit != DesktopFit.Fit && ParseResolution(resolution) is { } r ? r : tab;

    /// <summary>
    /// Where the desktop is drawn in a view of <paramref name="viewW"/> x <paramref name="viewH"/> (view units), and the
    /// scale from desktop pixels to view units: as large as fits for Fit and Scale (never stretched), one desktop pixel per
    /// device pixel for Fixed. Always centred.
    /// </summary>
    public static (double X, double Y, double Scale) Placement(DesktopFit fit, int desktopW, int desktopH, double viewW, double viewH, double rasterScale)
    {
        if (desktopW <= 0 || desktopH <= 0 || viewW <= 0 || viewH <= 0) return (0, 0, 1);
        var scale = fit == DesktopFit.Fixed ? 1.0 / (rasterScale > 0 ? rasterScale : 1.0) : Math.Min(viewW / desktopW, viewH / desktopH);
        return ((viewW - desktopW * scale) / 2, (viewH - desktopH * scale) / 2, scale);
    }

    /// <summary>A view position (view units) in desktop pixels; null outside the picture.</summary>
    public static (int X, int Y)? ToDesktop(DesktopFit fit, int desktopW, int desktopH, double viewW, double viewH, double rasterScale, double px, double py)
    {
        if (desktopW <= 0 || desktopH <= 0) return null;
        var (ox, oy, scale) = Placement(fit, desktopW, desktopH, viewW, viewH, rasterScale);
        var x = (int)Math.Floor((px - ox) / scale);
        var y = (int)Math.Floor((py - oy) / scale);
        return x < 0 || y < 0 || x >= desktopW || y >= desktopH ? null : (x, y);
    }
}
