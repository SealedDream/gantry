using Microsoft.UI.Dispatching;

namespace Bastion.Shell;

/// <summary>
/// Speed suite only (PerfTrace on): what one tab switch ran, to explain its slow switches. Per switch one line
/// "DETAIL &lt;mark&gt; total=.. sync=.. gc=g0/g1/g2 resizes=.. renders=.. render-ms=.. render-max=..", written once the
/// UI thread is idle again. The suite reads only PERF lines, so these lines change no metric. UI thread only.
/// </summary>
internal static class TabSwitchProbe
{
    private static int _resizes;
    private static int _renders;
    private static double _renderMs;
    private static double _renderMax;

    private static string _resizeFromTo = "";

    public static void Resized(int fromCols, int fromRows, int cols, int rows)
    {
        if (!PerfTrace.Enabled) return;
        _resizes++;
        _resizeFromTo += FormattableString.Invariant($" {fromCols}x{fromRows}->{cols}x{rows}");
    }

    public static void Rendered(double ms)
    {
        if (!PerfTrace.Enabled) return;
        _renders++;
        _renderMs += ms;
        if (ms > _renderMax) _renderMax = ms;
    }

    /// <summary>Start of a switch: counters reset, GC counts taken. Returns the start time, or 0 when tracing is off.</summary>
    private static string _mark = "tab-switch";

    public static (long T0, int G0, int G1, int G2) Begin(string mark)
    {
        if (!PerfTrace.Enabled) return default;
        _mark = mark;
        _resizes = 0; _resizeFromTo = ""; _renders = 0; _renderMs = 0; _renderMax = 0;
        var t0 = PerfTrace.Now();
        if (mark == "tab-open") BeginOpenPhases(t0);
        return (t0, GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2));
    }

    /// <summary>Start of the last tab open (0 = none yet): the new terminal's first layout, load and render are written
    /// against it, so a slow 'tab-open' says which step it waited for.</summary>
    private static long _openT0;
    private const double OpenPhaseWindowMs = 5000;

    private static void BeginOpenPhases(long t0)
    {
        _openT0 = t0;
        EventHandler<Microsoft.UI.Xaml.Media.RenderedEventArgs>? onFrame = null;
        onFrame = (_, _) =>
        {
            Microsoft.UI.Xaml.Media.CompositionTarget.Rendered -= onFrame;
            if (_openT0 == t0) Phase("frame");
        };
        Microsoft.UI.Xaml.Media.CompositionTarget.Rendered += onFrame;
    }

    /// <summary>One step of the last tab open, as "DETAIL tab-open phase &lt;name&gt; at=&lt;ms after the open&gt;". A new
    /// terminal calls it once per step (its first measure, size, load, render); views that already existed never do.</summary>
    public static void Phase(string name)
    {
        if (!PerfTrace.Enabled || _openT0 == 0) return;
        // A view made later (a split pane, a restored tab) is not part of that open.
        if (PerfTrace.Ms(_openT0) > OpenPhaseWindowMs) return;
        PerfTrace.Line(FormattableString.Invariant($"DETAIL tab-open phase {name} at={PerfTrace.Ms(_openT0):0.0}"));
    }

    /// <summary>After the switch's own code ran: its time, and the rest once the queued layout and renders are done.</summary>
    public static void End(DispatcherQueue queue, (long T0, int G0, int G1, int G2) start)
    {
        if (!PerfTrace.Enabled || start.T0 == 0) return;
        var sync = PerfTrace.Ms(start.T0);
        var mark = _mark;
        queue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            var line = FormattableString.Invariant(
                $"DETAIL {mark} total={PerfTrace.Ms(start.T0):0.0} sync={sync:0.0} gc={GC.CollectionCount(0) - start.G0}/{GC.CollectionCount(1) - start.G1}/{GC.CollectionCount(2) - start.G2} resizes={_resizes}{_resizeFromTo} renders={_renders} render-ms={_renderMs:0.0} render-max={_renderMax:0.0}");
            PerfTrace.Line(line);
        });
    }
}
