using System.Globalization;

namespace Bastion.Shell;

// Results grid for Tasks (design A, Native Mac TaskGridModel.swift ported 1:1): one row per host, rows with the same
// output folded into a group, a line diff of two rows and a labelled copy. No WinUI here, so the console test builds it.

public enum GridStatus { Waiting, Running, Ok, Failed }

/// <summary>One host. <see cref="State"/> is the core's: waiting, starting, running, done, failed, timed_out or cancelled.</summary>
public sealed record TaskGridRow(string Id, string Host, string State, int? Exit = null, string Stdout = "", string Stderr = "",
    string? Error = null, long Millis = 0)
{
    public GridStatus Status => State switch
    {
        "waiting" or "starting" => GridStatus.Waiting,
        "running" => GridStatus.Running,
        "done" => Exit == 0 ? GridStatus.Ok : GridStatus.Failed,
        _ => GridStatus.Failed,
    };

    public bool IsFinished => Status is GridStatus.Ok or GridStatus.Failed;

    /// <summary>Everything the host printed, stderr after stdout, then the error.</summary>
    public string Output => string.Join("\n", new[] { Stdout, Stderr, Error ?? "" }.Where(s => s.Length > 0)
        .Select(s => s.EndsWith('\n') ? s[..^1] : s));

    /// <summary>The line shown in the grid: the last non-empty line, or the first one of an error.</summary>
    public string Summary =>
        Error is { Length: > 0 } e ? TaskGrid.FirstLine(e)
        : Status == GridStatus.Failed && Stdout.Length == 0 && Stderr.Length > 0 ? TaskGrid.FirstLine(Stderr)
        : TaskGrid.LastLine(Output);

    public bool IsTruncated => Output.Contains(TaskGrid.TruncatedMarker, StringComparison.Ordinal);
}

/// <summary>Rows whose finished output is the same.</summary>
public sealed record GridGroup(IReadOnlyList<TaskGridRow> Rows)
{
    public string Id => string.Join(",", Rows.Select(r => r.Id));
    public TaskGridRow First => Rows[0];
    public bool IsGroup => Rows.Count > 1;
    public string Title => IsGroup ? $"{Rows.Count} hosts" : First.Host;
}

public enum DiffKind { Same, Left, Right }

public readonly record struct DiffLine(DiffKind Kind, string Text);

public static class TaskGrid
{
    /// <summary>What the core appends when it cut a host's output (<c>multiexec::capture</c>).</summary>
    public const string TruncatedMarker = "[output truncated by Gantry]";
    /// <summary>Lines per side compared at most; beyond that the rest is shown as changed.</summary>
    public const int MaxDiffLines = 2000;
    /// <summary>Overtime is never shorter than this, whatever the task's own limit.</summary>
    public const int MinOvertimeSecs = 30;

    private static readonly char[] NewLines = ['\n', '\r'];

    public static string FirstLine(string s) =>
        s.Split(NewLines, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "";

    public static string LastLine(string s) =>
        s.Split(NewLines, StringSplitOptions.RemoveEmptyEntries).LastOrDefault(l => !string.IsNullOrWhiteSpace(l))?.Trim() ?? "";

    /// <summary>Finished rows with the same status, exit code and output share a group; rows still running stay alone.
    /// Order follows the first row of each group.</summary>
    public static List<GridGroup> Groups(IEnumerable<TaskGridRow> rows)
    {
        var order = new List<string>();
        var byKey = new Dictionary<string, List<TaskGridRow>>();
        foreach (var r in rows)
        {
            var key = r.IsFinished ? $"{r.Status}|{r.Exit?.ToString(CultureInfo.InvariantCulture) ?? "-"}|{r.Output}" : $"live|{r.Id}";
            if (!byKey.TryGetValue(key, out var list)) { list = []; byKey[key] = list; order.Add(key); }
            list.Add(r);
        }
        return order.Select(k => new GridGroup(byKey[k])).ToList();
    }

    /// <summary>Line diff (longest common subsequence) of two outputs, each side capped at <see cref="MaxDiffLines"/>.</summary>
    public static List<DiffLine> Diff(string a, string b)
    {
        var l = Lines(a);
        var r = Lines(b);
        var lc = l.Take(MaxDiffLines).ToArray();
        var rc = r.Take(MaxDiffLines).ToArray();
        int n = lc.Length, m = rc.Length;
        var t = new int[n + 1, m + 1];
        for (var i = n - 1; i >= 0; i--)
            for (var j = m - 1; j >= 0; j--)
                t[i, j] = lc[i] == rc[j] ? t[i + 1, j + 1] + 1 : Math.Max(t[i + 1, j], t[i, j + 1]);
        var output = new List<DiffLine>();
        int x = 0, y = 0;
        while (x < n && y < m)
        {
            if (lc[x] == rc[y]) { output.Add(new(DiffKind.Same, lc[x])); x++; y++; }
            else if (t[x + 1, y] >= t[x, y + 1]) { output.Add(new(DiffKind.Left, lc[x])); x++; }
            else { output.Add(new(DiffKind.Right, rc[y])); y++; }
        }
        output.AddRange(lc[x..].Select(s => new DiffLine(DiffKind.Left, s)));
        output.AddRange(rc[y..].Select(s => new DiffLine(DiffKind.Right, s)));
        output.AddRange(l.Skip(MaxDiffLines).Select(s => new DiffLine(DiffKind.Left, s)));
        output.AddRange(r.Skip(MaxDiffLines).Select(s => new DiffLine(DiffKind.Right, s)));
        return output;
    }

    private static List<string> Lines(string s)
    {
        var ls = s.Split('\n').ToList();
        if (ls[^1].Length == 0) ls.RemoveAt(ls.Count - 1);
        return ls;
    }

    /// <summary>Every host's output under a header line, for the clipboard.</summary>
    public static string Labelled(IEnumerable<TaskGridRow> rows) =>
        string.Join("\n\n", rows.Select(r => $"== {r.Host} ({(r.Exit is { } e ? $"exit {e}" : r.State)}, {Duration(r.Millis)}) ==\n{r.Output}"));

    public static string Duration(long millis) =>
        millis < 1000 ? $"{millis} ms"
        : millis < 60_000 ? (millis / 1000.0).ToString("0.0", CultureInfo.InvariantCulture) + " s"
        : $"{millis / 60_000} m {millis / 1000 % 60} s";

    /// <summary>A row still running after <paramref name="limitSecs"/>: offer the terminal instead of waiting on it.</summary>
    public static bool IsOvertime(TaskGridRow row, double runningForSecs, double limitSecs) => !row.IsFinished && runningForSecs >= limitSecs;

    /// <summary>The overtime limit for a task: its own time limit, never below <see cref="MinOvertimeSecs"/>.</summary>
    public static int OvertimeLimit(int taskTimeoutSecs) => Math.Max(taskTimeoutSecs, MinOvertimeSecs);

    /// <summary>"3 ok · 1 failed", for a task card's last result.</summary>
    public static string Tally(IReadOnlyCollection<TaskGridRow> rows)
    {
        var ok = rows.Count(r => r.Status == GridStatus.Ok);
        var failed = rows.Count(r => r.Status == GridStatus.Failed);
        var busy = rows.Count - ok - failed;
        return string.Join(" · ", new[] { ok > 0 ? $"{ok} ok" : null, failed > 0 ? $"{failed} failed" : null, busy > 0 ? $"{busy} running" : null }
            .OfType<string>());
    }
}
