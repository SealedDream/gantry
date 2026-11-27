using System.Collections.Generic;
using System.Globalization;

namespace Bastion.Shell;

/// <summary>
/// A connection's own terminal font, from the inherited <c>terminal_font_family</c>, <c>terminal_font_size</c> and
/// <c>terminal_ligatures</c> properties (core/src/properties.rs). A null field follows the app setting
/// (<c>terminal.font-family</c>, <c>terminal.font-size</c>, <c>terminal.ligatures</c>), so Settings changes still reach it.
/// </summary>
public sealed record TerminalFontOverride(string? Family, double? Size, bool? Ligatures)
{
    public const string FamilyKey = "terminal_font_family";
    public const string SizeKey = "terminal_font_size";
    public const string LigaturesKey = "terminal_ligatures";

    public static readonly TerminalFontOverride None = new(null, null, null);

    /// <summary>Read the effective (own or inherited) values; empty or unparsable ones follow the app.</summary>
    public static TerminalFontOverride From(IReadOnlyDictionary<string, string?> effective)
    {
        string? Get(string key) => effective.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;
        double? size = double.TryParse(Get(SizeKey), NumberStyles.Float, CultureInfo.InvariantCulture, out var s) && s > 0 ? s : null;
        bool? ligatures = Get(LigaturesKey) switch { "true" => true, "false" => false, _ => null };
        return new TerminalFontOverride(Get(FamilyKey), size, ligatures);
    }
}
