using System;
using System.Globalization;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Bastion.Shell;

/// <summary>Brushes for the core's per-host colours (<c>#rrggbb</c> accent, <c>#rrggbbaa</c> tint). The core has already
/// normalised and validated the value, so a malformed string here only means "no colour".</summary>
internal static class HostColors
{
    public static SolidColorBrush? Brush(string hex) => Parse(hex) is { } c ? new SolidColorBrush(c) : null;

    public static Color? Parse(string hex)
    {
        var h = hex.StartsWith('#') ? hex[1..] : hex;
        if (h.Length is not (6 or 8) || !uint.TryParse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v)) return null;
        return h.Length == 6
            ? Color.FromArgb(0xff, (byte)(v >> 16), (byte)(v >> 8), (byte)v)
            : Color.FromArgb((byte)v, (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8));
    }
}
