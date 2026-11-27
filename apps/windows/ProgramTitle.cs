using System.Text;

namespace Bastion.Shell;

/// <summary>A program's window title (OSC 0/2) made safe to show as a tab name. It comes from the remote side.</summary>
internal static class ProgramTitle
{
    /// <summary>Longest tab name taken from a program title, in characters.</summary>
    public const int Max = 60;

    /// <summary>
    /// Control characters and bidirectional marks and overrides removed (they could hide or reorder text), white space
    /// collapsed, at most <see cref="Max"/> characters with an ellipsis. Null when nothing is left, so the tab falls back
    /// to its default name.
    /// </summary>
    public static string? Clean(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return null;
        var sb = new StringBuilder(Math.Min(raw.Length, Max + 1));
        var space = false;
        foreach (var ch in raw)
        {
            if (char.IsControl(ch) || IsBidiControl(ch)) continue;
            if (char.IsWhiteSpace(ch)) { space = sb.Length > 0; continue; }
            if (space) { sb.Append(' '); space = false; }
            sb.Append(ch);
            if (sb.Length > Max) break;
        }
        if (sb.Length == 0) return null;
        if (sb.Length <= Max) return sb.ToString();
        var cut = Max - 1;
        if (char.IsHighSurrogate(sb[cut - 1])) cut--; // never split a surrogate pair
        return sb.ToString(0, cut) + "\u2026";
    }

    /// <summary>SEC-7: marks a name a terminal program set, so it never passes as a Bastion label.</summary>
    public const string Mark = "\u203A ";

    /// <summary>A program title as a tab shows it: cleaned, leading symbols (a fake bell, dot or mark) dropped, then
    /// <see cref="Mark"/> in front. Null when nothing readable is left.</summary>
    public static string? Marked(string? raw)
    {
        var clean = Clean(raw);
        if (clean is null) return null;
        var i = 0;
        while (i < clean.Length && (char.IsWhiteSpace(clean[i]) || IsLeadSymbol(clean, i))) i += char.IsSurrogatePair(clean, i) ? 2 : 1;
        return i >= clean.Length ? null : Mark + clean[i..];
    }

    /// <summary>SEC-7: heading and body of a program (OSC 9/777) notification. The heading always names the tab's own
    /// source (connection or shell) and says it came from the terminal.</summary>
    public static (string Title, string Body) Notice(string source, string? title, string? body)
    {
        var t = Clean(title) ?? "";
        var b = Clean(body) ?? "";
        var text = t.Length == 0 ? b : (b.Length == 0 || b == t ? t : t + ": " + b);
        return (source + " \u00B7 terminal", text);
    }

    private static bool IsLeadSymbol(string s, int i)
    {
        if (s[i] is '\u203A' or '\uFE0F') return true;
        return System.Globalization.CharUnicodeInfo.GetUnicodeCategory(s, i) is
            System.Globalization.UnicodeCategory.OtherSymbol or System.Globalization.UnicodeCategory.MathSymbol or
            System.Globalization.UnicodeCategory.ModifierSymbol or System.Globalization.UnicodeCategory.InitialQuotePunctuation or
            System.Globalization.UnicodeCategory.FinalQuotePunctuation;
    }

    private static bool IsBidiControl(char ch) =>
        ch is '\u200E' or '\u200F' or '\u061C' or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069');
}
