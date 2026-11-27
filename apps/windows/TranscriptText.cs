using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Bastion.Shell;

// Transcript viewer (LOG-NATIVE-01 item 4, Native Windows; the Mac's TranscriptText.swift): reads a session log in pages,
// splits it into lines, strips terminal control sequences, finds the time column and searches. No WinUI, so the
// activity console test compiles it as it is. Read-only: nothing here writes the file.

/// <summary>One line of a transcript. <see cref="Time"/> is the leading timestamp when the line has one.</summary>
public sealed record TranscriptLine(int Number, string? Time, string Text)
{
    /// <summary>The line as shown: with or without its time column.</summary>
    public string Display(bool showTimes) => showTimes && Time is not null ? Time + "  " + Text : Text;
}

public static partial class TranscriptText
{
    /// <summary>Bytes read per page: a 60 MB log arrives in 60 pages and the window stays responsive between them.</summary>
    public const int PageBytes = 1 << 20;
    /// <summary>Only the first lines decide whether the log has a time column worth a toggle.</summary>
    private const int TimeProbeLines = 200;
    /// <summary>A timestamp sits in the first characters of a line.</summary>
    private const int TimeProbeChars = 48;

    /// <summary>The page title: "&lt;connection&gt; — &lt;started&gt;".</summary>
    public static string Title(string connection, DateTimeOffset started) =>
        $"{connection} — {started.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)}";

    /// <summary>Reads <paramref name="path"/> page by page, calling <paramref name="page"/> with each page's lines. Stops when
    /// <paramref name="page"/> returns false (the viewer closed) or <paramref name="cancel"/> fires. Opens the file for
    /// reading with read/write sharing, so a log still being written is never locked. Throws on I/O errors.</summary>
    public static void Read(string path, Func<IReadOnlyList<TranscriptLine>, bool> page, int pageBytes = PageBytes, CancellationToken cancel = default)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024);
        var buffer = new byte[pageBytes];
        var carry = new List<byte>();
        var next = 0;
        while (!cancel.IsCancellationRequested)
        {
            var n = stream.Read(buffer, 0, buffer.Length);
            var atEnd = n == 0;
            carry.AddRange(new ArraySegment<byte>(buffer, 0, n));
            byte[] body;
            if (atEnd)
            {
                body = carry.ToArray();
                carry.Clear();
            }
            else
            {
                var cut = carry.LastIndexOf((byte)'\n');
                if (cut < 0) continue; // no full line yet
                body = carry.GetRange(0, cut + 1).ToArray();
                carry.RemoveRange(0, cut + 1);
            }
            var lines = Split(body, next);
            next += lines.Count;
            if (lines.Count > 0 && !page(lines)) return;
            if (atEnd) return;
        }
    }

    /// <summary>Splits bytes into lines; invalid UTF-8 is replaced, not dropped.</summary>
    public static IReadOnlyList<TranscriptLine> Split(byte[] data, int firstNumber)
    {
        var parts = Encoding.UTF8.GetString(data).Split('\n');
        var count = parts.Length > 0 && parts[^1].Length == 0 ? parts.Length - 1 : parts.Length;
        var lines = new List<TranscriptLine>(count);
        for (var i = 0; i < count; i++)
        {
            var (time, rest) = SplitTime(Strip(parts[i]));
            lines.Add(new TranscriptLine(firstNumber + i, time, rest));
        }
        return lines;
    }

    /// <summary>Removes terminal control sequences (CSI, OSC, other ESC pairs), carriage returns and other control
    /// characters except tab.</summary>
    public static string Strip(string s)
    {
        if (!s.Any(c => c < 0x20 || c == 0x7F)) return s;
        var sb = new StringBuilder(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '\u001B')
            {
                if (++i >= s.Length) break;
                if (s[i] == '[') // CSI: parameters, then a final byte 0x40–0x7E
                {
                    while (++i < s.Length && s[i] is not (>= '@' and <= '~')) { }
                }
                else if (s[i] == ']') // OSC: ends with BEL or ESC \
                {
                    while (++i < s.Length)
                    {
                        if (s[i] == '\u0007') break;
                        if (s[i] == '\u001B') { i++; break; }
                    }
                } // other ESC x pairs: both dropped
                continue;
            }
            if (c == '\t' || (c >= 0x20 && c != 0x7F)) sb.Append(c);
        }
        return sb.ToString();
    }

    [GeneratedRegex(@"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\]?[ \t]", RegexOptions.CultureInvariant)]
    private static partial Regex TimePattern();

    /// <summary>A leading ISO 8601 or [hh:mm:ss] timestamp and the rest of the line.</summary>
    public static (string? Time, string Body) SplitTime(string line)
    {
        var m = TimePattern().Match(line.Length > TimeProbeChars ? line[..TimeProbeChars] : line);
        return m.Success ? (m.Groups[1].Value, line[m.Length..]) : (null, line);
    }

    /// <summary>Whether the transcript has a time column worth a toggle.</summary>
    public static bool HasTimes(IEnumerable<TranscriptLine> lines) => lines.Take(TimeProbeLines).Any(l => l.Time is not null);

    /// <summary>Line numbers containing <paramref name="query"/> (case-insensitive), in order.</summary>
    public static IReadOnlyList<int> Find(string query, IEnumerable<TranscriptLine> lines)
    {
        var q = query.Trim();
        if (q.Length == 0) return [];
        return lines.Where(l => l.Text.Contains(q, StringComparison.CurrentCultureIgnoreCase) || (l.Time?.Contains(q, StringComparison.Ordinal) ?? false))
            .Select(l => l.Number).ToList();
    }

    /// <summary>Where Find Next (or Previous) lands from <paramref name="current"/>, wrapping round.</summary>
    public static int? Step(IReadOnlyList<int> hits, int? current, bool forward)
    {
        if (hits.Count == 0) return null;
        if (current is not { } at) return forward ? hits[0] : hits[^1];
        return forward ? hits.FirstOrDefault(h => h > at, hits[0]) : hits.LastOrDefault(h => h < at, hits[^1]);
    }

    /// <summary>Text for Copy: the chosen lines, or all lines when none are chosen.</summary>
    public static string CopyText(IEnumerable<TranscriptLine> lines, IReadOnlySet<int> selected, bool showTimes)
    {
        var picked = selected.Count == 0 ? lines : lines.Where(l => selected.Contains(l.Number));
        return string.Join("\r\n", picked.Select(l => l.Display(showTimes)));
    }
}
