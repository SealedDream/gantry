using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// The sidebar's column follows its slide (owner 2026-11-15, as on the Mac): the content widens or narrows with the pane
/// instead of jumping when the slide ends. Per-frame width steps for the slide's 300 ms, then the handler is removed, so
/// nothing runs at idle (docs/TESTING.md, "WinUI CPU spin"). With Windows animations off the width changes at once.
/// </summary>
public sealed partial class MainWindow
{
    private static readonly TimeSpan NavColumnDuration = TimeSpan.FromMilliseconds(300);
    private EventHandler<object>? _navColumnFrame;

    /// <summary>Width from <paramref name="from"/> to <paramref name="to"/>; <paramref name="done"/> runs at the end unless a newer move started.</summary>
    private void AnimateNavColumn(double from, double to, int motion, Action done)
    {
        StopNavColumn();
        NavColumn.MinWidth = 0;
        if (Motion.Reduced || !NavPane.IsLoaded || Math.Abs(to - from) < 1)
        {
            NavColumn.Width = new GridLength(Math.Max(0, to));
            done();
            return;
        }
        var start = DateTime.UtcNow;
        NavColumn.Width = new GridLength(from);
        _navColumnFrame = (_, _) =>
        {
            if (motion != _navMotion || _windowClosed) { StopNavColumn(); return; }
            var t = Math.Min(1, (DateTime.UtcNow - start).TotalMilliseconds / NavColumnDuration.TotalMilliseconds);
            var eased = 1 - Math.Pow(1 - t, 3); // close to the slide's cubic-bezier(.32,.72,0,1)
            NavColumn.Width = new GridLength(Math.Max(0, from + (to - from) * eased));
            if (t < 1) return;
            StopNavColumn();
            done();
        };
        CompositionTarget.Rendering += _navColumnFrame;
    }

    private void StopNavColumn()
    {
        if (_navColumnFrame is null) return;
        CompositionTarget.Rendering -= _navColumnFrame;
        _navColumnFrame = null;
    }
}
