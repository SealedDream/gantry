using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>Defers non-essential start-up work until the window is on screen.</summary>
public static class Startup
{
    /// <summary>Frames to let through first: the first one lays out, the second is the one that reaches the screen.</summary>
    public const int FramesBeforeDeferredWork = 2;

    /// <summary>Run <paramref name="work"/> once, at low priority, after <paramref name="window"/>'s first painted frames.</summary>
    public static void AfterFirstFrame(Window window, Action work)
    {
        var frames = 0;
        EventHandler<object>? onFrame = null;
        onFrame = (_, _) =>
        {
            if (++frames < FramesBeforeDeferredWork) return;
            CompositionTarget.Rendering -= onFrame;
            window.DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => work());
        };
        CompositionTarget.Rendering += onFrame;
    }
}
