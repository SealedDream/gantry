using System.Diagnostics;
using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// BASTION_STARTUP_PROBE=&lt;file&gt;: once the window has painted two frames with the tree loaded, write the
/// milliseconds since process start to the file and exit. Used by tests\startup-budget.ps1; off otherwise.
/// </summary>
public static class StartupProbe
{
    public const string EnvVar = "BASTION_STARTUP_PROBE";
    private const int FramesToWait = Startup.FramesBeforeDeferredWork;
    private static readonly string? ProbePath = Environment.GetEnvironmentVariable(EnvVar);
    private static readonly List<string> Marks = [];

    public static bool Active => !string.IsNullOrWhiteSpace(ProbePath);

    private static double SinceStart => (DateTime.Now - Process.GetCurrentProcess().StartTime).TotalMilliseconds;

    /// <summary>Note how far start-up has got; written next to the result as &lt;file&gt;.marks.</summary>
    public static void Mark(string what)
    {
        // Locked: the core image scan marks from a worker thread (ColdPrefetch.WarmCoreImage).
        if (Active) lock (Marks) Marks.Add(what + " " + SinceStart.ToString("F0", CultureInfo.InvariantCulture));
    }

    /// <summary>Record why start-up failed, as &lt;file&gt;.err, so the budget script can show it.</summary>
    public static void Fail(Exception e)
    {
        if (!Active) return;
        try { File.WriteAllText(ProbePath + ".err", e.ToString()); }
        catch (IOException io) { Debug.WriteLine("startup probe: " + io.Message); }
    }

    public static void Arm(Window window)
    {
        if (!Active) return;
        var path = ProbePath!;
        var frames = 0;
        EventHandler<object>? onFrame = null;
        onFrame = (_, _) =>
        {
            Mark("frame" + (frames + 1).ToString(CultureInfo.InvariantCulture));
            if (++frames < FramesToWait) return;
            CompositionTarget.Rendering -= onFrame;
            var ms = SinceStart;
            try
            {
                string[] marks;
                lock (Marks) marks = [.. Marks];
                File.WriteAllLines(path + ".marks", marks);
                File.WriteAllText(path, ms.ToString("F0", CultureInfo.InvariantCulture));
            }
            catch (IOException e) { Debug.WriteLine("startup probe: " + e.Message); }
            // Never close inside the Rendering callback: the close handler then tears down a large tree inside a
            // frame (re-entrant layout), which overflowed the stack (0xc00000fd) on a 5,000-connection library.
            // Close on the next dispatcher turn, as a user's close does.
            if (!window.DispatcherQueue.TryEnqueue(window.Close)) window.Close();
        };
        CompositionTarget.Rendering += onFrame;
    }
}
