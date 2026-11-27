using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

// WIN-STALL-USER round 3. The folder dashboard's first show ('Escape' after the tree search) made the page's controls,
// applied their templates and laid them out in the frame of the key, then the rows in a later frame (q-stall-ab2: 23.7
// and 34.8 ms in B2, one 68.7 ms stall in B1). At idle after start-up the page is made in one short item, laid out in
// another and given its first list item in a third, so its first show lays out controls that have their templates.
public sealed partial class MainWindow
{
    /// <summary>After the terminal font warm-up (TerminalWarmDelay), so the two never share an idle moment.</summary>
    private static readonly TimeSpan DashboardWarmDelay = TimeSpan.FromSeconds(3);

    /// <summary>Between making the page and laying it out: each is its own idle item.</summary>
    private static readonly TimeSpan DashboardLayoutDelay = TimeSpan.FromMilliseconds(250);

    private DispatcherQueueTimer? _dashWarmTimer;
    private int _dashWarmStep;

    /// <summary>One placeholder row: the list makes its first item (the ListViewItem style and template load once per
    /// process; the library tree is an ItemsRepeater and makes none) at idle, not in a page's first rows frame.</summary>
    private static readonly string[] DashWarmRow = [""];

    /// <summary>Called once, when the first tree row is prepared (the window has painted).</summary>
    private void PrewarmDashboard()
    {
        if (_dashWarmTimer is not null) return;
        var queue = DispatcherQueue;
        _dashWarmTimer = queue.CreateTimer();
        _dashWarmTimer.Interval = DashboardWarmDelay;
        _dashWarmTimer.IsRepeating = false;
        _dashWarmTimer.Tick += (timer, _) =>
        {
            timer.Stop();
            queue.TryEnqueue(DispatcherQueuePriority.Low, WarmDashboardStep);
        };
        _dashWarmTimer.Start();
    }

    /// <summary>One idle item per tick: the page's controls and header, hidden; then their templates and layout; then the
    /// list's first item. Each is its own short item.</summary>
    private void WarmDashboardStep()
    {
        if (_windowClosed) return;
        switch (_dashWarmStep++)
        {
            case 0:
                if (_dash is not null) return; // the user opened it first: its first show did this
                EnsureDashboard();
                _dash!.Visibility = Visibility.Collapsed; // in the same item: no frame or UI Automation client sees it shown
                SyncDashLayout();
                break;
            case 1:
                LayOutDashboardAtIdle(withRow: false);
                break;
            default:
                LayOutDashboardAtIdle(withRow: true);
                return;
        }
        _dashWarmTimer!.Interval = DashboardLayoutDelay;
        _dashWarmTimer.Start();
    }

    /// <summary>
    /// Show the page, lay it out (which applies the control templates; with <paramref name="withRow"/>, over one
    /// placeholder row) and hide it again, all in this one dispatcher item: nothing renders or answers UI Automation in
    /// between, so no frame paints it and no client sees it. A collapsed page keeps its templates. Skipped once the
    /// user has opened the page.
    /// </summary>
    private void LayOutDashboardAtIdle(bool withRow)
    {
        if (_dashShownOnce || _dash is not { Visibility: Visibility.Collapsed } page) return;
        var placeholder = withRow && _dashList.Items.Count == 0;
        page.Visibility = Visibility.Visible;
        try
        {
            if (placeholder) _dashList.ItemsSource = DashWarmRow;
            page.UpdateLayout();
        }
        catch (COMException ex)
        {
            // A warm-up only: the first show then does this work itself, as before.
            System.Diagnostics.Debug.WriteLine("Dashboard warm-up skipped: " + ex.Message);
        }
        finally
        {
            if (placeholder) _dashList.ItemsSource = null;
            page.Visibility = Visibility.Collapsed;
        }
    }

    // ---- Speed suite trace (BASTION_PERF_TRACE only) ----

    /// <summary>Phase lines are written for this long after an open, and at most this many frame lines.</summary>
    private const double DashPhaseWindowMs = 1000;
    private const int DashFrameMarks = 8;

    private long _dashOpenT0;
    private (int G0, int G1, int G2) _dashOpenGc;

    /// <summary>
    /// The dashboard opens: its steps and the next frames are written as "DETAIL dash-open phase &lt;name&gt; at=&lt;ms
    /// after the open&gt; gc=&lt;collections since&gt;", so a stall in an open's frame shows what that frame held.
    /// </summary>
    private void DashPhaseStart()
    {
        if (!PerfTrace.Enabled) return;
        var t0 = _dashOpenT0 = PerfTrace.Now();
        _dashOpenGc = (GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2));
        DashPhase(_dashShownOnce ? "open" : "first-open");
        var frames = 0;
        EventHandler<RenderedEventArgs>? onFrame = null;
        onFrame = (_, e) =>
        {
            if (_dashOpenT0 != t0 || ++frames > DashFrameMarks || PerfTrace.Ms(t0) > DashPhaseWindowMs)
            {
                CompositionTarget.Rendered -= onFrame;
                return;
            }
            DashPhase(FormattableString.Invariant($"frame render={e.FrameDuration.TotalMilliseconds:0.0}"));
        };
        CompositionTarget.Rendered += onFrame;
    }

    private void DashPhase(string name)
    {
        if (!PerfTrace.Enabled || _dashOpenT0 == 0 || PerfTrace.Ms(_dashOpenT0) > DashPhaseWindowMs) return;
        var (g0, g1, g2) = _dashOpenGc;
        PerfTrace.Line(FormattableString.Invariant(
            $"DETAIL dash-open phase {name} at={PerfTrace.Ms(_dashOpenT0):0.0} gc={GC.CollectionCount(0) - g0}/{GC.CollectionCount(1) - g1}/{GC.CollectionCount(2) - g2}"));
    }
}
