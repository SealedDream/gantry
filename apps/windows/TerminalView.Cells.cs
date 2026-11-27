using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// WIN-STALL-USER: cell metrics per font, and the grid a terminal gets in an area. Measuring a cell lays out a TextBlock
/// in the terminal font, and the first time that loads the font (the bundled font file and the fallback list) inside the
/// frame of the first new terminal ('Ctrl+Shift+T new local shell', q-stall-ab). The metrics are kept per family list and
/// size for the life of the process, so later views with the same font measure nothing, and <see cref="Warm"/> lets the
/// window measure the default font once while it is idle. UI thread only (XAML).
/// </summary>
public sealed partial class TerminalView
{
    private static readonly Dictionary<(string Family, double Size), (double W, double H)> CellCache = new();

    private static (double W, double H) CellOf(FontFamily family, double size)
    {
        var key = (family.Source, size);
        if (CellCache.TryGetValue(key, out var cell)) return cell;
        var probe = new TextBlock { Text = new string('M', 10), FontFamily = family, FontSize = size, IsTextScaleFactorEnabled = false };
        probe.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        cell = (Math.Max(1, probe.DesiredSize.Width / 10), Math.Max(1, Math.Ceiling(probe.DesiredSize.Height)));
        CellCache[key] = cell;
        return cell;
    }

    /// <summary>Idle warm-up: measure (and so load) the font that a new terminal with these settings uses.</summary>
    public static void Warm(double fontSize, string? fontId) => _ = CellOf(FontFor(fontId), fontSize);

    /// <summary>The grid a terminal with this font gets in <paramref name="area"/>, as <see cref="ResizeToFit"/> sizes it;
    /// null when the area is smaller than one cell.</summary>
    public static (int Cols, int Rows)? GridFor(Windows.Foundation.Size area, double fontSize, string? fontId)
    {
        var (w, h) = CellOf(FontFor(fontId), fontSize);
        return Fit(area, w, h, fontSize);
    }

    /// <summary>Inner padding around the grid (UI-03, as the Mac): 8 left and right, 4 top and bottom at the default
    /// 13 pt, scaled with the text size. Painted in the theme background; clicks there hit the edge cell.</summary>
    private const double PadFontSize = 13, PadX = 8, PadY = 4;
    internal static (double X, double Y) InsetFor(double fontSize) =>
        (Math.Round(PadX * fontSize / PadFontSize), Math.Round(PadY * fontSize / PadFontSize));

    private static (int Cols, int Rows)? Fit(Windows.Foundation.Size area, double cellW, double cellH, double fontSize)
    {
        var (x, y) = InsetFor(fontSize);
        double w = area.Width - 2 * x, h = area.Height - 2 * y;
        return w < cellW || h < cellH ? null
            : (Math.Clamp((int)(w / cellW), 2, 1000), Math.Clamp((int)(h / cellH), 1, 1000));
    }

    /// <summary>The session was started at this grid (a new tab whose PTY started off the UI thread at the tab's size):
    /// the first fit to the same grid then resizes nothing.</summary>
    public void StartedAt(int cols, int rows)
    {
        _sizedCols = cols;
        _sizedRows = rows;
    }
}
