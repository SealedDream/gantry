using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Foundation;

namespace Bastion.Shell;

/// <summary>
/// Owner points W16 and W17: the tab strip moves instead of jumping. A strip change that the user caused (a dropped
/// tab, a group collapsed or expanded) is played as a FLIP animation: each tab and chip starts where it was drawn
/// before the change and slides to its new place; tabs that appear (an expanded group) fade in out of their chip.
/// Collapsing first folds the group's tabs into the chip, then the rest slide over. All of it is render-transform and
/// opacity animation, which Windows runs on the compositor thread, so the UI thread is never busy per frame.
/// With "Show animations in Windows" off the strip changes at once.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>Slide time for tabs settling into place.</summary>
    private static readonly TimeSpan StripSlide = TimeSpan.FromMilliseconds(220);

    /// <summary>Fold time for a collapsing group's tabs; short, since the slide follows it.</summary>
    private static readonly TimeSpan StripFold = TimeSpan.FromMilliseconds(140);

    /// <summary>Movement (px) too small to animate.</summary>
    private const double StripEpsilon = 0.5;

    private static readonly Windows.UI.ViewManagement.UISettings MotionSettings = new();

    /// <summary>The next <see cref="RenderStrip"/> animates from the positions drawn before it.</summary>
    private bool _animateNextStrip;

    /// <summary>The strip animation running now, if any.</summary>
    private Storyboard? _stripStoryboard;

    private static bool MotionOn
    {
        get
        {
            try { return MotionSettings.AnimationsEnabled; }
            catch (Exception) { return true; }
        }
    }

    /// <summary>A stable key for a strip child: a tab by its strip id, a chip (rebuilt every render) by its group.</summary>
    private string? StripKey(UIElement element)
    {
        if (_tabs.FirstOrDefault(t => ReferenceEquals(t.Header, element)) is { } tab) return "t:" + tab.StripId;
        var chip = _chips.FirstOrDefault(c => ReferenceEquals(c.Value, element));
        return chip.Key is null ? null : "g:" + chip.Key;
    }

    /// <summary>Where each visible strip child is drawn now, transforms included.</summary>
    private Dictionary<string, Point> StripPositions()
    {
        var result = new Dictionary<string, Point>();
        foreach (var child in TabStrip.Children)
        {
            if (child.Visibility != Visibility.Visible || StripKey(child) is not { } key) continue;
            try { result[key] = child.TransformToVisual(TabStrip).TransformPoint(default); }
            catch (ArgumentException) { /* not in the tree yet */ }
        }
        return result;
    }

    private static TranslateTransform Translation(UIElement element)
    {
        if (element.RenderTransform is TranslateTransform t) return t;
        t = new TranslateTransform();
        element.RenderTransform = t;
        return t;
    }

    /// <summary>Slides of tabs pushed aside by a drag; they hold their end value until stopped.</summary>
    private readonly List<Storyboard> _pushBoards = new();

    /// <summary>Stop every strip animation; each child falls back to its local transform and opacity.</summary>
    private void StopStripAnimation()
    {
        StopBoard(_stripStoryboard);
        _stripStoryboard = null;
        foreach (var b in _pushBoards) StopBoard(b);
        _pushBoards.Clear();
    }

    /// <summary>
    /// A strip storyboard may outlive its target: a group chip is rebuilt on every render, so a slide started on the old
    /// chip (pushed aside during a drag) points at an element no longer in the tree. Stopping or starting such a board
    /// can throw; that must never take the app down, it only loses one slide.
    /// </summary>
    private static void StopBoard(Storyboard? board)
    {
        if (board is null) return;
        try { board.Stop(); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"strip animation stop: {ex.Message}"); }
    }

    private static void RunBoard(Storyboard board)
    {
        try { board.Begin(); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"strip animation start: {ex.Message}"); }
    }

    private static DoubleAnimation Slide(DependencyObject target, string property, double? from, double to, TimeSpan duration)
    {
        var a = new DoubleAnimation { From = from, To = to, Duration = duration, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        Storyboard.SetTarget(a, target);
        Storyboard.SetTargetProperty(a, property);
        return a;
    }

    /// <summary>
    /// Play the move from <paramref name="before"/> (from <see cref="StripPositions"/>) to the current layout. Children
    /// that were not drawn before fade in, sliding out of <paramref name="growFrom"/> when it is given.
    /// </summary>
    private void AnimateStripFrom(Dictionary<string, Point> before, string? growFrom = null)
    {
        StopStripAnimation();
        foreach (var child in TabStrip.Children)
        {
            var t = Translation(child);
            t.X = 0;
            t.Y = 0;
        }
        if (!MotionOn || before.Count == 0) return;
        TabStrip.UpdateLayout();
        var now = StripPositions();
        Point? origin = growFrom is not null && now.TryGetValue(growFrom, out var o) ? o : null;
        var board = new Storyboard();
        foreach (var child in TabStrip.Children)
        {
            if (child.Visibility != Visibility.Visible || StripKey(child) is not { } key || !now.TryGetValue(key, out var to)) continue;
            var move = Translation(child);
            if (before.TryGetValue(key, out var from))
            {
                if (Math.Abs(from.X - to.X) > StripEpsilon) board.Children.Add(Slide(move, "X", from.X - to.X, 0, StripSlide));
                if (Math.Abs(from.Y - to.Y) > StripEpsilon) board.Children.Add(Slide(move, "Y", from.Y - to.Y, 0, StripSlide));
                continue;
            }
            board.Children.Add(Slide(child, "Opacity", 0, 1, StripSlide));
            if (origin is { } start)
            {
                if (VerticalTabs) board.Children.Add(Slide(move, "Y", start.Y - to.Y, 0, StripSlide));
                else board.Children.Add(Slide(move, "X", start.X - to.X, 0, StripSlide));
            }
        }
        if (board.Children.Count == 0) return;
        _stripStoryboard = board;
        RunBoard(board);
    }

    /// <summary>Slide every strip child back to its laid-out place (after a cancelled drag, or a move the core refused).</summary>
    private void SettleStrip() => AnimateStripFrom(StripPositions());

    /// <summary>
    /// Collapse with motion: the group's tabs (all but the active one, which stays visible) fold into the chip, then
    /// <paramref name="collapse"/> asks the core and the tabs after the group slide over.
    /// </summary>
    private void CollapseGroupAnimated(string group, Action collapse)
    {
        var folding = _tabs.Where(t => t.Group == group && !ReferenceEquals(t, _active) && t.Header.Visibility == Visibility.Visible).ToList();
        if (!MotionOn || folding.Count == 0 || !_chips.TryGetValue(group, out var chip))
        {
            _animateNextStrip = true;
            collapse();
            return;
        }
        StopStripAnimation();
        var chipAt = chip.TransformToVisual(TabStrip).TransformPoint(default);
        var board = new Storyboard();
        foreach (var tab in folding)
        {
            var at = tab.Header.TransformToVisual(TabStrip).TransformPoint(default);
            var move = Translation(tab.Header);
            board.Children.Add(Slide(tab.Header, "Opacity", 1, 0, StripFold));
            if (VerticalTabs) board.Children.Add(Slide(move, "Y", 0, chipAt.Y - at.Y, StripFold));
            else board.Children.Add(Slide(move, "X", 0, chipAt.X - at.X, StripFold));
        }
        board.Completed += (_, _) =>
        {
            if (!ReferenceEquals(_stripStoryboard, board)) return; // something else took over the strip
            _animateNextStrip = true;
            collapse();
        };
        _stripStoryboard = board;
        RunBoard(board);
    }
}
