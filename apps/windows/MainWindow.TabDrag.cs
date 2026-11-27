using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Foundation;

namespace Bastion.Shell;

/// <summary>
/// Drag a tab to reorder it, and so into or out of a group, as on Native Mac. Owner point W16: the drag is live, as in
/// a browser. The tab follows the pointer along the strip and the tabs it passes slide aside to open its slot; on
/// release it settles into the slot and the core's <c>move</c> op decides the group (between two tabs of a group joins
/// it, at its own group's edge it stays in, anywhere else it leaves). Releasing over a group chip adds the tab to that
/// group. The drag captures the pointer instead of using system drag-and-drop, so there is no drag image, no
/// "Move after" caption and no OLE round trip on every move. Tabs only move inside the strip.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>Pointer travel (px) before a press on a tab becomes a drag, about the Windows SM_CXDRAG default.</summary>
    private const double DragThreshold = 4;

    /// <summary>Time for a passed tab to slide aside.</summary>
    private static readonly TimeSpan MakeRoom = TimeSpan.FromMilliseconds(150);

    /// <summary>The drag under way, or null.</summary>
    private TabDragState? _tabDrag;

    /// <summary>One live tab drag: the strip's laid-out slots at the start and how far each passed child is pushed.</summary>
    private sealed class TabDragState
    {
        public required WorkspaceTab Tab { get; init; }
        public required List<UIElement> Children { get; init; }
        public required List<Rect> Slots { get; init; }
        public required int From { get; init; }
        public required double Grab { get; init; }
        public Dictionary<UIElement, double> Pushed { get; } = new();
        public double Offset { get; set; }
        /// <summary>The pointer along the strip, for dropping onto a chip (the tab itself may be wider than the chip).</summary>
        public double Pointer { get; set; }
    }

    private void EnableTabDrag(WorkspaceTab tab)
    {
        // The tab's Select button takes the pointer, so watch the press (handled events too) and start the drag once
        // the pointer moves past the system threshold; from then on the header holds the capture.
        Point? pressed = null;
        tab.Header.AddHandler(UIElement.PointerPressedEvent, new PointerEventHandler((_, e) =>
        {
            var pt = e.GetCurrentPoint(TabStrip);
            pressed = pt.Properties.IsLeftButtonPressed ? pt.Position : null;
        }), true);
        tab.Header.AddHandler(UIElement.PointerMovedEvent, new PointerEventHandler((_, e) =>
        {
            var pt = e.GetCurrentPoint(TabStrip);
            if (_tabDrag is { } drag && ReferenceEquals(drag.Tab, tab))
            {
                DragTo(drag, pt.Position);
                e.Handled = true;
                return;
            }
            if (pressed is not { } from) return;
            if (!pt.Properties.IsLeftButtonPressed) { pressed = null; return; }
            if (Math.Abs(pt.Position.X - from.X) < DragThreshold && Math.Abs(pt.Position.Y - from.Y) < DragThreshold) return;
            pressed = null;
            if (!BeginTabDrag(tab, from)) return;
            // The tab's Select button captured the pointer on the press, so the header usually cannot take it; the
            // button's moves and release still bubble here (handled events too), which is all the drag needs.
            tab.Header.CapturePointer(e.Pointer);
            DragTo(_tabDrag!, pt.Position);
            e.Handled = true;
        }), true);
        tab.Header.AddHandler(UIElement.PointerReleasedEvent, new PointerEventHandler((_, e) =>
        {
            pressed = null;
            if (_tabDrag is not { } drag || !ReferenceEquals(drag.Tab, tab)) return;
            e.Handled = true;
            EndTabDrag(drag); // before the release, so the capture-lost handler below sees no drag
            tab.Header.ReleasePointerCaptures();
            // B12-W2b: released well above or below the strip: the tab tears off into a window at the pointer.
            if (ReleasedOffStrip(e))
            {
                SettleStrip();
                TearOff(tab, TabWindow.ScreenOf(this, e.GetCurrentPoint(null).Position));
                return;
            }
            _ = DropTabAsync(drag);
        }), true);
        // Capture lost without a release (Alt+Tab, a window over the strip): the tab goes back.
        tab.Header.PointerCaptureLost += (_, e) =>
        {
            // Only the header's own capture: the Select button losing its capture (to the header) bubbles here too.
            if (!ReferenceEquals(e.OriginalSource, tab.Header)) return;
            if (_tabDrag is not { } drag || !ReferenceEquals(drag.Tab, tab)) return;
            EndTabDrag(drag);
            SettleStrip();
        };
    }

    private bool BeginTabDrag(WorkspaceTab tab, Point pressedAt)
    {
        if (_tabDrag is not null || tab.Header.Visibility != Visibility.Visible) return false;
        StopStripAnimation();
        var children = TabStrip.Children.Where(c => c.Visibility == Visibility.Visible).ToList();
        var from = children.IndexOf(tab.Header);
        if (from < 0) return false;
        var slots = children.Select(c => new Rect(c.TransformToVisual(TabStrip).TransformPoint(default), new Size(c.ActualSize.X, c.ActualSize.Y))).ToList();
        _tabDrag = new TabDragState { Tab = tab, Children = children, Slots = slots, From = from, Grab = Along(pressedAt) };
        Canvas.SetZIndex(tab.Header, 1);
        tab.Header.Opacity = DraggedTabOpacity;
        return true;
    }

    /// <summary>The lifted tab is a touch see-through, so the slot opening under it stays visible.</summary>
    private const double DraggedTabOpacity = 0.9;

    private double Along(Point p) => VerticalTabs ? p.Y : p.X;
    private double Start(Rect r) => VerticalTabs ? r.Y : r.X;
    private double Extent(Rect r) => VerticalTabs ? r.Height : r.Width;

    /// <summary>Move the dragged tab with the pointer (kept inside the strip) and push the tabs it has passed.</summary>
    private void DragTo(TabDragState drag, Point pointer)
    {
        var mine = drag.Slots[drag.From];
        var first = Start(drag.Slots[0]);
        var last = Start(drag.Slots[^1]) + Extent(drag.Slots[^1]);
        drag.Pointer = Along(pointer);
        drag.Offset = Math.Clamp(Along(pointer) - drag.Grab, first - Start(mine), Math.Max(first - Start(mine), last - Start(mine) - Extent(mine)));
        var move = Translation(drag.Tab.Header);
        if (VerticalTabs) move.Y = drag.Offset; else move.X = drag.Offset;

        // A passed child moves aside once the dragged tab's leading edge crosses its middle (browser-like). Comparing
        // centres would never pass the last tab: the drag is clamped there, so with equal widths the centres only meet.
        var lead = Start(mine) + drag.Offset;
        var trail = lead + Extent(mine);
        var room = Extent(mine) + TabStrip.Spacing;
        for (var i = 0; i < drag.Children.Count; i++)
        {
            if (i == drag.From) continue;
            // Group chips stay put: they are drop targets, not slots.
            if (IsChip(drag.Children[i])) continue;
            var mid = Start(drag.Slots[i]) + Extent(drag.Slots[i]) / 2;
            var push = i > drag.From && trail > mid ? -room : i < drag.From && lead < mid ? room : 0;
            Push(drag, drag.Children[i], push);
        }
    }

    /// <summary>Slide a passed child to <paramref name="to"/> (px along the strip) unless it is already headed there.</summary>
    private void Push(TabDragState drag, UIElement child, double to)
    {
        var current = drag.Pushed.GetValueOrDefault(child);
        if (current == to) return;
        drag.Pushed[child] = to;
        var move = Translation(child);
        if (!MotionOn)
        {
            if (VerticalTabs) move.Y = to; else move.X = to;
            return;
        }
        var board = new Storyboard();
        board.Children.Add(Slide(move, VerticalTabs ? "Y" : "X", null, to, MakeRoom)); // from wherever it is drawn now
        _pushBoards.Add(board);
        RunBoard(board);
    }

    private void EndTabDrag(TabDragState drag)
    {
        if (ReferenceEquals(_tabDrag, drag)) _tabDrag = null;
        Canvas.SetZIndex(drag.Tab.Header, 0);
        drag.Tab.Header.Opacity = 1;
    }

    /// <summary>Commit the slot the tab was released in: onto a group chip, or before or after a neighbouring tab.</summary>
    private async System.Threading.Tasks.Task DropTabAsync(TabDragState drag)
    {
        var mine = drag.Slots[drag.From];
        if (ChipUnder(drag, drag.Pointer) is { } group)
        {
            _animateNextStrip = true;
            if (drag.Tab.Group != group) await RunStripOp(new JsonObject { ["op"] = "addToGroup", ["tab"] = drag.Tab.StripId.ToString(), ["group"] = group });
            SettleStrip();
            return;
        }
        var passed = drag.Pushed.Where(p => p.Value != 0).Select(p => drag.Children.IndexOf(p.Key)).ToList();
        if (passed.Count == 0) { SettleStrip(); return; }
        // The new visual order: the other children, with the dragged tab after the last one it passed going forward,
        // or before the first one it passed going back. In `others` the children after it sit one index lower.
        var others = drag.Children.Where(c => !ReferenceEquals(c, drag.Tab.Header)).ToList();
        var slot = passed.Max() > drag.From ? passed.Max() : passed.Min();
        var before = others.Take(slot).Reverse().Select(TabOf).FirstOrDefault(t => t is not null);
        var after = others.Skip(slot).Select(TabOf).FirstOrDefault(t => t is not null);
        _animateNextStrip = true;
        if (before is not null) await MoveTabAsync(drag.Tab, before, after: true);
        else if (after is not null) await MoveTabAsync(drag.Tab, after, after: false);
        SettleStrip();
    }

    /// <summary>The group whose chip is under the <paramref name="pointer"/> (chips never move during a drag), if any.</summary>
    private string? ChipUnder(TabDragState drag, double pointer)
    {
        for (var i = 0; i < drag.Children.Count; i++)
        {
            var group = _chips.FirstOrDefault(c => ReferenceEquals(c.Value, drag.Children[i])).Key;
            if (group is null) continue;
            var at = Start(drag.Slots[i]);
            if (pointer >= at && pointer <= at + Extent(drag.Slots[i])) return group;
        }
        return null;
    }

    private bool IsChip(UIElement element) => _chips.Values.Any(c => ReferenceEquals(c, element));

    private WorkspaceTab? TabOf(UIElement element) => _tabs.FirstOrDefault(t => ReferenceEquals(t.Header, element));

    /// <summary>The core's <c>to</c> is an index into the strip without the moved tab.</summary>
    private System.Threading.Tasks.Task MoveTabAsync(WorkspaceTab dragged, WorkspaceTab target, bool after)
    {
        var rest = _tabs.Where(t => !ReferenceEquals(t, dragged)).ToList();
        var to = rest.IndexOf(target) + (after ? 1 : 0);
        return RunStripOp(new JsonObject { ["op"] = "move", ["tab"] = dragged.StripId.ToString(), ["to"] = to });
    }
}
