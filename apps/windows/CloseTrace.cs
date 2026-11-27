using System.Diagnostics;
using System.Globalization;

namespace Bastion.Shell;

/// <summary>
/// BASTION_CLOSE_TRACE=&lt;file&gt;: time each step of the window's close path and the process exit, one line per step
/// ("&lt;ms since close began&gt; &lt;step&gt; &lt;step ms&gt;"), appended and flushed at once so a hang shows its last step.
/// Off otherwise.
/// </summary>
public static class CloseTrace
{
    public const string EnvVar = "BASTION_CLOSE_TRACE";
    private static readonly string? TracePath = Environment.GetEnvironmentVariable(EnvVar);
    private static readonly Stopwatch Since = new();

    public static bool Active => !string.IsNullOrWhiteSpace(TracePath);

    /// <summary>Start timing (the close request) and log the process exit once it comes.</summary>
    public static void Begin(string what)
    {
        if (!Active) return;
        if (!Since.IsRunning)
        {
            Since.Start();
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Write("process-exit", 0);
        }
        Write(what, 0);
    }

    /// <summary>Run one close step, timed.</summary>
    public static void Step(string name, Action step)
    {
        if (!Active) { step(); return; }
        var t0 = Since.Elapsed.TotalMilliseconds;
        try { step(); }
        finally { Write(name, Since.Elapsed.TotalMilliseconds - t0); }
    }

    private static void Write(string step, double ms)
    {
        try
        {
            File.AppendAllText(TracePath!, string.Create(CultureInfo.InvariantCulture,
                $"{Since.Elapsed.TotalMilliseconds:F0} {step} {ms:F0}{Environment.NewLine}"));
        }
        catch (IOException e) { Debug.WriteLine("close trace: " + e.Message); }
    }
}
