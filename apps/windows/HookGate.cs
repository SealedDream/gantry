namespace Bastion.Shell;

/// <summary>
/// B5 before-connect gate (Native Mac HookGate.swift): what the connect does once a before-connect hook's task has
/// ended. Only "done" with exit 0 lets it connect (the core's own success rule); a failure, a timeout or Cancel stops
/// it and the user is told why, with the tail of the output. No WinUI, so tests/hook-gate-console checks it.
/// </summary>
public static class HookGate
{
    /// <summary>The longest output tail the refusal quotes; the full output stays in the task's log.</summary>
    public const int QuotedOutputLimit = 400;

    /// <summary>Null to connect, else the message that says why the connect stopped.</summary>
    public static string? StopReason(string task, string connection, string state, int? exit, string stdout, string stderr, string? error)
    {
        if (state == "done" && exit == 0) return null;
        if (state == "cancelled") return $"Not connected to {connection}: “{task}” was cancelled before connect.";
        var why = state == "timed_out" ? "timed out" : exit is { } e ? $"exited with {e}" : "failed";
        var text = $"Not connected to {connection}: before-connect task “{task}” {why}.";
        var output = new[] { error ?? "", stderr, stdout }.Select(s => s.Trim()).FirstOrDefault(s => s.Length > 0);
        if (output is not null) text += "\n\n" + (output.Length > QuotedOutputLimit ? output[^QuotedOutputLimit..] : output);
        return text;
    }
}

/// <summary>One Connect All run: a multi-host hook set on a folder runs once for the run, not once per host.</summary>
public sealed class HookBatch
{
    private readonly HashSet<string> _fired = [];

    /// <summary>True the first time this hook (folder, task, moment) asks to run in this batch.</summary>
    public bool Claim(string ownerId, string taskId, string when) => _fired.Add($"{ownerId}|{taskId}|{when}");
}
