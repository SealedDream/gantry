using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;

namespace Bastion.Shell;

/// <summary>
/// The shared "Native spring" motion (assets/icon/README.md): 300 ms, cubic-bezier(.32,.72,0,1), 12 px travel both ways,
/// dialogs scale from 0.96. With animations turned off in Windows (Settings › Accessibility › Visual effects) it is
/// a 100 ms fade with no movement. Composition animations run on the compositor and stop when done, so idle CPU
/// stays at zero; nothing here loops.
/// </summary>
internal static class Motion
{
    private static readonly TimeSpan Duration = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan ReducedDuration = TimeSpan.FromMilliseconds(100);
    private const float Travel = 12f;
    private const float DialogScale = 0.96f;

    internal static bool Reduced
    {
        get
        {
            try { return !new Windows.UI.ViewManagement.UISettings().AnimationsEnabled; }
            catch { return false; }
        }
    }

    /// <summary>
    /// A side pane appearing or going away at <paramref name="edge"/> (-1 left, 1 right): slide and fade in, or out
    /// towards the edge. <paramref name="hidden"/> runs when a slide-out ends, so the caller collapses the pane then;
    /// a slide-in started meanwhile replaces the animation and the caller's own state check skips the collapse.
    /// </summary>
    public static void Slide(UIElement element, bool show, int edge, Action hidden)
    {
        // Before first paint (a pane saved as hidden) there is nothing to animate.
        if (element is FrameworkElement { IsLoaded: false }) { if (!show) hidden(); return; }
        if (show) { Play(element, new Vector3(edge * Travel, 0, 0), 1f); return; }
        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;
        var reduced = Reduced;
        var ease = Ease(compositor, reduced);
        var batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);
        var fade = compositor.CreateScalarKeyFrameAnimation();
        fade.InsertKeyFrame(1f, 0f, ease);
        fade.Duration = reduced ? ReducedDuration : Duration;
        visual.StartAnimation("Opacity", fade);
        if (!reduced)
        {
            ElementCompositionPreview.SetIsTranslationEnabled(element, true);
            var slide = compositor.CreateVector3KeyFrameAnimation();
            slide.InsertKeyFrame(1f, new Vector3(edge * Travel, 0, 0), ease);
            slide.Duration = Duration;
            visual.StartAnimation("Translation", slide);
        }
        batch.End();
        var queue = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
        // The batch does not complete while the compositor is not rendering (seen on Windows 10, WIN-EVEN-01): a timer
        // ends the slide-out anyway, so the pane never stays laid out, invisible, after it was hidden. Runs once.
        var done = false;
        void Finish() { if (done) return; done = true; hidden(); }
        batch.Completed += (_, _) => queue.TryEnqueue(Finish);
        var timer = queue.CreateTimer();
        timer.Interval = Duration + SlideGrace;
        timer.IsRepeating = false;
        timer.Tick += (_, _) => { timer.Stop(); Finish(); };
        timer.Start();
    }

    /// <summary>Extra time after a slide-out before the fallback timer ends it.</summary>
    private static readonly TimeSpan SlideGrace = TimeSpan.FromMilliseconds(200);

    private static CompositionEasingFunction Ease(Compositor compositor, bool reduced) => reduced
        ? compositor.CreateLinearEasingFunction()
        : compositor.CreateCubicBezierEasingFunction(new Vector2(0.32f, 0.72f), new Vector2(0f, 1f));

#if BASTION_TEST_HOOKS
    /// <summary>
    /// WIN-SHELL-LEAK drill only: how a dialog appears. "" as shipped; "none"; "translate-only" (12 px up, no fade or
    /// scale); "host-fade" (the overlay fades, the card does not move); "storyboard" (a XAML opacity storyboard on the
    /// card).
    /// </summary>
    internal static string DrillPresent = "";
#endif

    /// <summary>Fade in and grow from 0.96: a dialog that was just presented.</summary>
    public static void Present(FrameworkElement element)
    {
#if BASTION_TEST_HOOKS
        if (DrillPresentVariant(element)) return;
#endif
        var visual = ElementCompositionPreview.GetElementVisual(element);
        visual.CenterPoint = new Vector3((float)element.ActualWidth / 2, (float)element.ActualHeight / 2, 0);
        Play(element, Vector3.Zero, DialogScale);
    }

#if BASTION_TEST_HOOKS
    /// <summary>Run the drill's way of presenting <paramref name="element"/>; false for the shipped one.</summary>
    private static bool DrillPresentVariant(FrameworkElement element)
    {
        switch (DrillPresent)
        {
            case "none":
                return true;
            case "translate-only":
            {
                var visual = ElementCompositionPreview.GetElementVisual(element);
                ElementCompositionPreview.SetIsTranslationEnabled(element, true);
                var slide = visual.Compositor.CreateVector3KeyFrameAnimation();
                slide.InsertKeyFrame(0f, new Vector3(0, Travel, 0));
                slide.InsertKeyFrame(1f, Vector3.Zero, Ease(visual.Compositor, false));
                slide.Duration = Duration;
                visual.StartAnimation("Translation", slide);
                return true;
            }
            case "host-fade" when element.Parent is UIElement host:
            {
                var visual = ElementCompositionPreview.GetElementVisual(host);
                var fade = visual.Compositor.CreateScalarKeyFrameAnimation();
                fade.InsertKeyFrame(0f, 0f);
                fade.InsertKeyFrame(1f, 1f, Ease(visual.Compositor, false));
                fade.Duration = Duration;
                visual.StartAnimation("Opacity", fade);
                return true;
            }
            case "storyboard":
            {
                var fade = new Microsoft.UI.Xaml.Media.Animation.DoubleAnimation { From = 0, To = 1, Duration = new Duration(Duration) };
                Microsoft.UI.Xaml.Media.Animation.Storyboard.SetTarget(fade, element);
                Microsoft.UI.Xaml.Media.Animation.Storyboard.SetTargetProperty(fade, "Opacity");
                var board = new Microsoft.UI.Xaml.Media.Animation.Storyboard { Children = { fade } };
                board.Begin();
                return true;
            }
            default:
                return false;
        }
    }
#endif

    private static void Play(UIElement element, Vector3 from, float scaleFrom)
    {
        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;
        var reduced = Reduced;
        var duration = reduced ? ReducedDuration : Duration;
        var ease = Ease(compositor, reduced);

        var fade = compositor.CreateScalarKeyFrameAnimation();
        fade.InsertKeyFrame(0f, 0f);
        fade.InsertKeyFrame(1f, 1f, ease);
        fade.Duration = duration;
        visual.StartAnimation("Opacity", fade);
        if (reduced) return;

        if (from != Vector3.Zero)
        {
            ElementCompositionPreview.SetIsTranslationEnabled(element, true);
            var slide = compositor.CreateVector3KeyFrameAnimation();
            slide.InsertKeyFrame(0f, from);
            slide.InsertKeyFrame(1f, Vector3.Zero, ease);
            slide.Duration = duration;
            visual.StartAnimation("Translation", slide);
        }
        if (scaleFrom != 1f)
        {
            var grow = compositor.CreateVector3KeyFrameAnimation();
            grow.InsertKeyFrame(0f, new Vector3(scaleFrom, scaleFrom, 1f));
            grow.InsertKeyFrame(1f, Vector3.One, ease);
            grow.Duration = duration;
            visual.StartAnimation("Scale", grow);
        }
    }
}
