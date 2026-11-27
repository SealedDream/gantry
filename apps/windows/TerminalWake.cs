using Bastion.Shell.Interop;
using Microsoft.UI.Dispatching;

namespace Bastion.Shell;

/// <summary>
/// Wakes a terminal view as soon as its core screen changes (Native Mac TerminalWake.swift). A background thread blocks
/// in the core's wait_change and queues one redraw on the UI thread per change, so a keystroke's echo is drawn in the
/// next frame instead of on the next 33 ms poll. At most one redraw is queued however fast output arrives, and a burst
/// redraws at most 120 times a second so copying the screen never starves the UI thread.
/// </summary>
internal sealed class TerminalWake
{
    /// <summary>How long one wait blocks before the thread checks whether it was stopped (also the longest a
    /// session's Dispose can wait for the thread to let go of the handle).</summary>
    private const uint WaitSliceMs = 50;
    private static readonly TimeSpan MinInterval = TimeSpan.FromSeconds(1.0 / 120.0);

    private readonly TerminalSession _session;
    private readonly DispatcherQueue _ui;
    private readonly Action _onChange;
    private volatile bool _stopped;
    private int _queued;

    private TerminalWake(TerminalSession session, DispatcherQueue ui, Action onChange)
    {
        _session = session;
        _ui = ui;
        _onChange = onChange;
    }

    /// <summary>Start waking <paramref name="onChange"/> (run on <paramref name="ui"/>) for each screen change.</summary>
    public static TerminalWake Start(TerminalSession session, DispatcherQueue ui, Action onChange)
    {
        var wake = new TerminalWake(session, ui, onChange);
        new Thread(wake.Run) { IsBackground = true, Name = "bastion-terminal-wake", Priority = ThreadPriority.AboveNormal }.Start();
        return wake;
    }

    public void Stop() => _stopped = true;

    private void Run()
    {
        var seen = ulong.MaxValue;
        var last = DateTime.MinValue;
        while (!_stopped && !_session.IsDisposed)
        {
            ulong gen;
            try { gen = _session.WaitChange(seen, WaitSliceMs); }
            catch (Exception e) when (e is BastionException or ObjectDisposedException) { return; }
            if (gen == seen || _stopped) continue;
            var wait = MinInterval - (DateTime.UtcNow - last);
            if (wait > TimeSpan.Zero) Thread.Sleep(wait);
            seen = gen;
            last = DateTime.UtcNow;
            // One redraw in flight: a change that lands meanwhile is drawn by that redraw (it reads the latest screen)
            // or wakes the next wait, since `seen` is the generation before it.
            if (Interlocked.Exchange(ref _queued, 1) == 1) continue;
            if (!_ui.TryEnqueue(DispatcherQueuePriority.High, () => { Volatile.Write(ref _queued, 0); if (!_stopped) _onChange(); }))
                return; // the UI thread is gone (window closed)
        }
    }
}
