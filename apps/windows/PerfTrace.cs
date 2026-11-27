using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.UI.Dispatching;

namespace Bastion.Shell;

/// <summary>
/// Speed marks for the Windows speed suite (tests\speed-suite.ps1). Test builds only: with BASTION_PERF_TRACE set
/// to a file path, each mark appends one line "PERF &lt;metric&gt; &lt;value&gt; ms", the format the Mac runner prints
/// (apps/macos/uitests/budgets.py), so both apps share one set of metric names. In an owner build
/// <see cref="Enabled"/> is a constant false and every mark returns at once.
/// </summary>
internal static class PerfTrace
{
#if BASTION_TEST_HOOKS
    private static readonly string? TracePath = Environment.GetEnvironmentVariable("BASTION_PERF_TRACE") is { Length: > 0 } p ? p : null;
    public static bool Enabled => TracePath is not null;
#else
    private const string? TracePath = null;
    public static bool Enabled => false;
#endif

    private const int HeartbeatMs = 10;
    private const int StallReportMs = 5000;
    /// <summary>A heartbeat this late is written as its own STALL line (the suite attributes it to a step).</summary>
    private const int StallLineMs = 20;

    private static readonly object Gate = new();
    private static readonly ConcurrentDictionary<string, long> Spans = new();
    private static DispatcherQueueTimer? _heartbeat;

    public static long Now() => Stopwatch.GetTimestamp();

    public static double Ms(long from) => Stopwatch.GetElapsedTime(from).TotalMilliseconds;

    /// <summary>Append one line. Never throws: a trace failure must not change what the app does.</summary>
    public static void Write(string metric, double value, string unit = "ms")
    {
        if (!Enabled) return;
        Enqueue(FormattableString.Invariant($"PERF {metric} {value:0.0} {unit}{Environment.NewLine}"));
    }

    /// <summary>Append a raw line (not a PERF mark: the suite's metrics ignore it). Never throws.</summary>
    public static void Line(string text)
    {
        if (Enabled) Enqueue(text + Environment.NewLine);
    }

    // The marks are written by a background thread in batches. Writing each one on the calling thread opened, wrote and
    // closed the file on the UI thread (one per tree row prepared while filtering): the WPR trace q-trace-1 shows that
    // file I/O inside the UI stalls, so the speed suite was measuring its own trace writes.
    private const int FlushMs = 25;
    private static readonly ConcurrentQueue<string> Pending = new();
    private static readonly AutoResetEvent Wake = new(false);
    private static Thread? _writer;

    private static void Enqueue(string line)
    {
        Pending.Enqueue(line);
        if (_writer is not null) return;
        lock (Gate)
        {
            if (_writer is not null) return;
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Flush();
            _writer = new Thread(() => { while (true) { Wake.WaitOne(FlushMs); Flush(); } }) { IsBackground = true, Name = "perf-trace" };
            _writer.Start();
        }
    }

    /// <summary>Write what is queued, in order. Never throws.</summary>
    private static void Flush()
    {
        if (Pending.IsEmpty) return;
        var batch = new System.Text.StringBuilder();
        lock (Gate)
        {
            while (Pending.TryDequeue(out var line)) batch.Append(line);
            // The suite appends to the same file and retries while the app holds it: a short open per batch.
            for (var attempt = 0; attempt < 20; attempt++)
            {
                try { File.AppendAllText(TracePath!, batch.ToString()); return; }
                catch (IOException) { Thread.Sleep(5); }
                catch (UnauthorizedAccessException) { return; }
            }
        }
    }

    /// <summary>Open a span that a later <see cref="End"/> with the same key closes.</summary>
    public static void Begin(string key)
    {
        if (Enabled) Spans[key] = Now();
    }

    /// <summary>Close span <paramref name="key"/> if open and write its length as <paramref name="metric"/>.</summary>
    public static bool End(string key, string metric)
    {
        if (!Enabled || !Spans.TryRemove(key, out var t0)) return false;
        Write(metric, Ms(t0));
        return true;
    }

    /// <summary>Write the time from <paramref name="t0"/> until the UI thread is idle again: a Low-priority callback
    /// runs only after the input, layout and render work queued before it.</summary>
    public static void AfterLayout(DispatcherQueue queue, string metric, long t0)
    {
        if (!Enabled) return;
        var id = PerfEvents.Begin(metric);
        queue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            PerfEvents.End(metric, id);
            Write(metric, Ms(t0));
        });
        AfterFrame(metric + "-frame", t0);
    }

    /// <summary>Write the time from <paramref name="t0"/> to the first frame rendered after the call: what the user
    /// sees. A Low-priority callback (<see cref="AfterLayout"/>) can also wait for input to go idle, for example a held
    /// key, so both are written and compared on the speed VM before either is the gate. UI thread only.</summary>
    public static void AfterFrame(string metric, long t0)
    {
        if (!Enabled) return;
        EventHandler<Microsoft.UI.Xaml.Media.RenderedEventArgs>? onFrame = null;
        onFrame = (_, _) =>
        {
            Microsoft.UI.Xaml.Media.CompositionTarget.Rendered -= onFrame;
            Write(metric, Ms(t0));
        };
        Microsoft.UI.Xaml.Media.CompositionTarget.Rendered += onFrame;
    }

    /// <summary>A 10 ms heartbeat on the UI thread; a late tick is a stall. Every 5 s writes the worst lateness as
    /// "ui-stall-max"; the suite takes the max over the window it cares about. Every stall of 20 ms or more is also
    /// written as "STALL &lt;ms&gt; &lt;unix ms at its end&gt;".</summary>
    public static void StartStallWatch(DispatcherQueue queue)
    {
        if (!Enabled || _heartbeat is not null) return;
        var last = Now();
        var window = Now();
        var worst = 0.0;
        _heartbeat = queue.CreateTimer();
        _heartbeat.Interval = TimeSpan.FromMilliseconds(HeartbeatMs);
        _heartbeat.Tick += (_, _) =>
        {
            var late = Ms(last) - HeartbeatMs;
            // Each stall on its own, with the wall clock at its end, so the suite can name the step it fell in.
            if (late >= StallLineMs) Line(FormattableString.Invariant($"STALL {late:0.0} {DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}"));
            worst = Math.Max(worst, late);
            last = Now();
            if (Ms(window) < StallReportMs) return;
            Write("ui-stall-max", Math.Max(0, worst));
            worst = 0;
            window = Now();
        };
        _heartbeat.Start();
    }
}
