using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.System;

namespace Bastion.Shell;

public enum SplitAxis
{
    /// <summary>Side by side (Alt+Shift+=).</summary>
    Right,
    /// <summary>Stacked (Alt+Shift+-).</summary>
    Down,
}

public enum PaneDirection { Left, Right, Up, Down }

/// <summary>
/// One tab's terminals as a binary split tree, like Splits.swift on macOS. A leaf is a <see cref="TerminalView"/>; a
/// split is a <see cref="Grid"/> with the two subtrees in star-sized tracks and a <see cref="SplitDivider"/> between
/// them. Panes keep their own sessions; the tree only lays them out and tracks which one has focus.
/// </summary>
public sealed partial class SplitPanes : UserControl
{
    private const double DividerSize = 5;
    private readonly Border _host = new();
    private readonly List<TerminalView> _panes = new();

    public SplitPanes(TerminalView first)
    {
        IsTabStop = false;
        Content = _host;
        _host.Child = first;
        Track(first);
        Focused = first;
    }

    /// <summary>Every pane, in the order they were opened (the first is the tab's own session).</summary>
    public IReadOnlyList<TerminalView> Panes => _panes;

    /// <summary>The pane that had focus last; new splits open beside it and Ctrl+Shift+W closes it.</summary>
    public TerminalView Focused { get; private set; }

    /// <summary>Raised when the focused pane changes, so the tab can show that pane's title.</summary>
    public event EventHandler? FocusedChanged;

    private void Track(TerminalView view)
    {
        _panes.Add(view);
        view.GotFocus += (_, _) =>
        {
            if (ReferenceEquals(Focused, view)) return;
            Focused = view;
            FocusedChanged?.Invoke(this, EventArgs.Empty);
        };
    }

    /// <summary>
    /// The split tree in pre-order as the core's workspace layout steps (core/src/workspace.rs): <c>leaf</c>, or
    /// <c>right:0.620</c> / <c>down:0.500</c> followed by its two subtrees, the ratio being the first one's share.
    /// Empty for a single pane.
    /// </summary>
    public List<string> Layout()
    {
        var steps = new List<string>();
        void Walk(UIElement? e)
        {
            if (e is Grid split && split.Children.OfType<SplitDivider>().FirstOrDefault() is { } divider)
            {
                var across = split.ColumnDefinitions.Count == 3;
                steps.Add($"{(across ? "right" : "down")}:{divider.Share.ToString("0.000", System.Globalization.CultureInfo.InvariantCulture)}");
                FrameworkElement Slot(int i) => split.Children.OfType<FrameworkElement>().First(c => c is not SplitDivider && (across ? Grid.GetColumn(c) : Grid.GetRow(c)) == i);
                Walk(Slot(0));
                Walk(Slot(2));
            }
            else steps.Add("leaf");
        }
        Walk(_host.Child);
        return steps.Count == 1 ? [] : steps;
    }

    /// <summary>Put <paramref name="added"/> beside <paramref name="at"/>, sharing its space half and half.</summary>
    public void Split(TerminalView at, TerminalView added, SplitAxis axis) => Split(at, added, axis, 0.5);

    /// <summary>Put <paramref name="added"/> beside <paramref name="at"/>; <paramref name="share"/> is <paramref name="at"/>'s part (a saved ratio).</summary>
    public void Split(TerminalView at, TerminalView added, SplitAxis axis, double share)
    {
        var grid = new Grid();
        var across = axis == SplitAxis.Right;
        for (var i = 0; i < 3; i++)
        {
            var length = i == 1 ? new GridLength(DividerSize) : new GridLength(1, GridUnitType.Star);
            if (across) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = length });
            else grid.RowDefinitions.Add(new RowDefinition { Height = length });
        }
        Replace(at, grid);
        Place(grid, at, 0, across);
        var divider = new SplitDivider(grid, across);
        divider.SetShare(share);
        Place(grid, divider, 1, across);
        Place(grid, added, 2, across);
        Track(added);
        added.Focus(FocusState.Programmatic);
        Focused = added;
        FocusedChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Take <paramref name="view"/> out of the tree; its sibling subtree takes the space. The caller disposes the
    /// view. Returns the pane that gets focus, or null when it was the last one (the tab should close instead).
    /// </summary>
    public TerminalView? Remove(TerminalView view)
    {
        if (_panes.Count <= 1) return null;
        var index = _panes.IndexOf(view);
        if (index < 0) return null;
        if (view.Parent is Grid split)
        {
            var other = split.Children.OfType<FrameworkElement>().First(c => c is not SplitDivider && !ReferenceEquals(c, view));
            split.Children.Clear();
            Replace(split, other);
        }
        _panes.RemoveAt(index);
        var next = _panes[Math.Clamp(index - 1, 0, _panes.Count - 1)];
        Focused = next;
        next.Focus(FocusState.Programmatic);
        FocusedChanged?.Invoke(this, EventArgs.Empty);
        return next;
    }

    /// <summary>Move focus to the nearest pane beyond <paramref name="direction"/>'s edge of the focused one,
    /// preferring the most overlap on the other axis. Returns false at the edge of the tab.</summary>
    public bool MoveFocus(PaneDirection direction)
    {
        var from = Bounds(Focused);
        TerminalView? best = null;
        double bestGap = double.MaxValue, bestOverlap = -1;
        foreach (var p in _panes)
        {
            if (ReferenceEquals(p, Focused)) continue;
            var r = Bounds(p);
            var (gap, overlap) = direction switch
            {
                PaneDirection.Left => (from.Left - r.Right, Overlap(from.Top, from.Bottom, r.Top, r.Bottom)),
                PaneDirection.Right => (r.Left - from.Right, Overlap(from.Top, from.Bottom, r.Top, r.Bottom)),
                PaneDirection.Up => (from.Top - r.Bottom, Overlap(from.Left, from.Right, r.Left, r.Right)),
                _ => (r.Top - from.Bottom, Overlap(from.Left, from.Right, r.Left, r.Right)),
            };
            if (gap < -1 || overlap <= 0) continue;
            if (gap < bestGap - 1 || (Math.Abs(gap - bestGap) <= 1 && overlap > bestOverlap)) { best = p; bestGap = gap; bestOverlap = overlap; }
        }
        if (best is null) return false;
        best.Focus(FocusState.Keyboard);
        return true;
    }

    private static double Overlap(double a0, double a1, double b0, double b1) => Math.Min(a1, b1) - Math.Max(a0, b0);

    private Windows.Foundation.Rect Bounds(FrameworkElement e) =>
        e.TransformToVisual(this).TransformBounds(new Windows.Foundation.Rect(0, 0, e.ActualWidth, e.ActualHeight));

    private void Replace(FrameworkElement old, FrameworkElement with)
    {
        if (ReferenceEquals(_host.Child, old)) { _host.Child = with; return; }
        if (old.Parent is not Grid parent) return;
        var across = parent.ColumnDefinitions.Count == 3;
        var slot = across ? Grid.GetColumn(old) : Grid.GetRow(old);
        parent.Children.Remove(old);
        Place(parent, with, slot, across);
    }

    private static void Place(Grid grid, FrameworkElement e, int slot, bool across)
    {
        if (e.Parent is Grid g) g.Children.Remove(e);
        else if (e.Parent is Border b) b.Child = null;
        if (across) Grid.SetColumn(e, slot); else Grid.SetRow(e, slot);
        grid.Children.Add(e);
    }
}

/// <summary>
/// The bar between two split panes. Dragging it (or Left/Right, Up/Down when focused) moves the share between the
/// two star tracks, kept within 10–90% as on macOS. A plain colour change on hover, no animation.
/// </summary>
public sealed partial class SplitDivider : ContentControl
{
    private const double MinShare = 0.1, KeyStep = 0.05;
    private readonly Grid _grid;
    private readonly bool _across;
    /// <summary>
    /// The drawn bar. A ContentControl without content renders nothing, not even its Background, so the divider was
    /// invisible, never received the pointer (it fell through to the terminals) and could not be dragged.
    /// </summary>
    private readonly Border _bar = new();
    private bool _dragging, _hover;

    public SplitDivider(Grid grid, bool across)
    {
        _grid = grid;
        _across = across;
        IsTabStop = true;
        UseSystemFocusVisuals = true;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
        Content = _bar;
        AutomationProperties.SetName(this, across ? "Resize panes left and right" : "Resize panes up and down");
        ProtectedCursor = InputSystemCursor.Create(across ? InputSystemCursorShape.SizeWestEast : InputSystemCursorShape.SizeNorthSouth);
        Loaded += (_, _) => Paint();
        PointerEntered += (_, _) => { _hover = true; Paint(); };
        PointerExited += (_, _) => { _hover = false; Paint(); };
        PointerPressed += (_, e) => { _dragging = CapturePointer(e.Pointer); Paint(); e.Handled = true; };
        PointerMoved += OnMoved;
        PointerReleased += (_, e) => { _dragging = false; ReleasePointerCapture(e.Pointer); Paint(); };
        PointerCaptureLost += (_, _) => { _dragging = false; Paint(); };
        DoubleTapped += (_, _) => SetShare(0.5);
        KeyDown += OnKey;
    }

    private void Paint() => _bar.Background = Ui.Brush(this, _dragging || _hover ? "SplitterHoverBrush" : "DividerBrush");

    /// <summary>The first pane's share of the two, 0.1–0.9.</summary>
    public double Share
    {
        get
        {
            var a = _across ? _grid.ColumnDefinitions[0].Width.Value : _grid.RowDefinitions[0].Height.Value;
            var b = _across ? _grid.ColumnDefinitions[2].Width.Value : _grid.RowDefinitions[2].Height.Value;
            return a / Math.Max(0.0001, a + b);
        }
    }

    public void SetShare(double share)
    {
        share = Math.Clamp(share, MinShare, 1 - MinShare);
        var a = new GridLength(share, GridUnitType.Star);
        var b = new GridLength(1 - share, GridUnitType.Star);
        if (_across) { _grid.ColumnDefinitions[0].Width = a; _grid.ColumnDefinitions[2].Width = b; }
        else { _grid.RowDefinitions[0].Height = a; _grid.RowDefinitions[2].Height = b; }
    }

    private void OnMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_dragging) return;
        var p = e.GetCurrentPoint(_grid).Position;
        var total = (_across ? _grid.ActualWidth : _grid.ActualHeight) - (_across ? ActualWidth : ActualHeight);
        if (total <= 0) return;
        SetShare((_across ? p.X : p.Y) / total);
        e.Handled = true;
    }

    private void OnKey(object sender, KeyRoutedEventArgs e)
    {
        var step = e.Key switch
        {
            VirtualKey.Left when _across => -KeyStep,
            VirtualKey.Right when _across => KeyStep,
            VirtualKey.Up when !_across => -KeyStep,
            VirtualKey.Down when !_across => KeyStep,
            _ => 0.0,
        };
        if (e.Key == VirtualKey.Enter) { SetShare(0.5); e.Handled = true; return; }
        if (step == 0) return;
        SetShare(Share + step);
        e.Handled = true;
    }
}
