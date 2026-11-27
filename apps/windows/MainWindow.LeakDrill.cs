#if BASTION_TEST_HOOKS
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace Bastion.Shell;

/// <summary>
/// WIN-SHELL-LEAK drill (test builds, BASTION_LEAK_PROBE=file and BASTION_LEAK_DRILL=1 only): which part of a closed tab
/// leaves native objects behind. After start-up the window runs soak-like cycles of ten local shell tabs (open; switch;
/// close, with and without the confirmation), then (BASTION_LEAK_DRILL=1) opens and closes single tabs and creates and
/// removes one kind of element at a time, and writes per step how many heap bytes and heap blocks typed by module
/// (their vtable's DLL; d2d1 counted on its own) are left after a full GC. The first round or cycle may include
/// one-time caches. An owner build has none of this code.
/// </summary>
public sealed partial class MainWindow
{
    private const int DrillElements = 50, DrillTabs = 20, DrillRounds = 2, DrillShownFrames = 3, DrillModalFrames = 20;
    private const int DrillSettleFrames = 10, DrillSettleMs = 500, DrillStartDelayMs = 4000, DrillTabWaitMs = 10_000;
    private const int DrillShellMs = 1200, DrillPollMs = 100, DrillTopModules = 4;
    private const int DrillCycles = 3, DrillCycleTabs = 10, DrillSwitchMs = 150, DrillSettleTries = 8;
    private const long DrillSteadyBytes = 64 * 1024;
    private static readonly TimeSpan DrillFrameTimeout = TimeSpan.FromSeconds(10);

    private sealed record DrillKind(string Name, Func<FrameworkElement> Make, Action<FrameworkElement>? Shown = null);

    private DrillKind[] DrillKinds() =>
    [
        new("textblock", () => new TextBlock { Text = "Local shell" }),
        new("fonticon", () => Ui.Icon("GlyphTerminal", "SmallIconSize")),
        new("ellipse-dot", () => new Ellipse { Width = UnreadDotSize, Height = UnreadDotSize, Fill = Ui.Brush(RootGrid, "AccentFillColorDefaultBrush") }),
        new("ellipse-collapsed", () => new Ellipse { Width = TabDotSize, Height = TabDotSize, Visibility = Visibility.Collapsed }),
        new("rect-opacity0", () => new Rectangle { Width = 300, Height = 120, Opacity = 0, IsHitTestVisible = false, Fill = new SolidColorBrush(Microsoft.UI.Colors.White) }),
        new("rect-visible", () => new Rectangle { Width = 40, Height = 16, Fill = new SolidColorBrush(Microsoft.UI.Colors.SteelBlue) }),
        new("grid-rounded-clear", () => new Grid { CornerRadius = Ui.Radius("TabCornerRadius"), Width = 160, Height = Ui.Double("ControlHeight"), Background = _transparent }),
        new("grid-rounded-filled", () => new Grid { CornerRadius = Ui.Radius("TabCornerRadius"), Width = 160, Height = Ui.Double("ControlHeight"), Background = Ui.Brush(RootGrid, "AccentFillColorDefaultBrush") }),
        new("border-rounded-text", () => new Border
        {
            CornerRadius = new CornerRadius(4), Padding = new Thickness(10, 4, 10, 4),
            Background = new SolidColorBrush(Microsoft.UI.Colors.DimGray), Child = new TextBlock { Text = "Reconnecting" },
        }),
        new("button-tabselect", () => new Button
        {
            Style = Ui.Style("TabSelectButtonStyle"),
            Content = new StackPanel { Orientation = Orientation.Horizontal, Children = { Ui.Icon("GlyphTerminal", "SmallIconSize"), new TextBlock { Text = "Local shell" } } },
        }),
        new("button-tabclose", () => new Button { Style = Ui.Style("TabCloseButtonStyle"), Content = Ui.Icon("GlyphClose", "TabCloseGlyphSize") }),
        new("button-keyboard-focus", () => new Button { Style = Ui.Style("TabCloseButtonStyle"), Content = Ui.Icon("GlyphClose", "TabCloseGlyphSize") },
            e => ((Control)e).Focus(FocusState.Keyboard)),
    ];

    private async Task RunLeakDrill()
    {
        try
        {
            await Task.Delay(DrillStartDelayMs); // deferred start-up work first
            LeakProbe.Note("DRILL start mode=" + LeakProbe.DrillMode);
            // Soak-like cycles (mem-soak-keys-test.ps1: ten tabs open, Ctrl+Tab through them, Ctrl+Shift+W + confirm each):
            // first the plain open/close, then with the switching, then all of it, to tell which step leaves objects.
            if (LeakProbe.DrillMode == "bisect4")
            {
                // Bisect 3: any animation of the dialog card over a terminal leaves the objects (fade or scale, new or
                // reused), an animated plain card does not. Which part of the card, and which entrance leaves none?
                foreach (var mode in new[] { "", "translate-only", "host-fade", "storyboard" })
                {
                    Motion.DrillPresent = mode;
                    await DrillCycles3("modal-each-" + (mode.Length == 0 ? "shipped" : mode), true, DrillCloseNow);
                }
                Motion.DrillPresent = "";
                var corners = _drillCorners = DrillCardCorners();
                DrillSetCardCorners(corners, inner: true, card: false);
                await DrillCycles3("modal-each-square-inner", true, DrillCloseNow);
                DrillSetCardCorners(corners, inner: true, card: true);
                await DrillCycles3("modal-each-square-all", true, DrillCloseNow);
                DrillRestoreCardCorners(corners);
                _drillCorners = null;
                LeakProbe.Note("DRILL done");
                return;
            }
            if (LeakProbe.DrillMode == "bisect")
            {
                // Which part of "close through the confirmation" leaves the objects (cycle-soak leaks, cycle-switch not).
                await DrillCycles3("modal-then-close", false, tab => DrillModalThenClose(tab, keyboard: true, returnFocus: true));
                await DrillCycles3("modal-pointer-then-close", false, tab => DrillModalThenClose(tab, keyboard: false, returnFocus: true));
                await DrillCycles3("modal-noreturn-then-close", false, tab => DrillModalThenClose(tab, keyboard: true, returnFocus: false));
                await DrillCycles3("modal-each-close-later", true, DrillCloseNow);
                await DrillCycles3("focus-away-then-close", false, DrillFocusAwayThenClose);
                LeakProbe.Note("DRILL done");
                return;
            }
            await DrillCycles3("cycle-open-close", false, DrillCloseNow, switching: false);
            await DrillCycles3("cycle-switch", false, DrillCloseNow);
            await DrillCycles3("cycle-soak", false, DrillConfirmClose);
            if (LeakProbe.DrillMode == "cycles") { LeakProbe.Note("DRILL done"); return; }
            for (var round = 1; round <= DrillRounds; round++) await DrillStep("local-tab", round, DrillTabs, () => DrillRepeat(DrillTabs, DrillOneTab));
            for (var round = 1; round <= DrillRounds; round++) await DrillStep("close-confirm", round, DrillElements, () => DrillRepeat(DrillElements, DrillOneModal));
            var host = new Grid { HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(40) };
            Grid.SetRowSpan(host, 2);
            RootGrid.Children.Add(_drillHost = host);
            foreach (var kind in DrillKinds())
                for (var round = 1; round <= DrillRounds; round++)
                    await DrillStep(kind.Name, round, DrillElements, () => DrillRepeat(DrillElements, () => DrillOneElement(host, kind)));
            RootGrid.Children.Remove(host);
            _drillHost = null;
            LeakProbe.Note("DRILL done");
        }
        catch (Exception e)
        {
            LeakProbe.Note("DRILL error " + e.GetType().Name + ": " + e.Message);
        }
        finally
        {
            // Leave the window as it was, also after an error: shipped entrance, rounded card, no drill host, no dialog,
            // no tabs.
            Motion.DrillPresent = "";
            if (_drillCorners is { } corners) DrillRestoreCardCorners(corners);
            _drillCorners = null;
            if (_drillHost is { } host) RootGrid.Children.Remove(host);
            _drillHost = null;
            if (_modal is not null) CloseModal(false);
            foreach (var tab in _tabs.ToList()) CloseTab(tab);
        }
    }

    private List<(FrameworkElement Element, CornerRadius Radius)>? _drillCorners;
    private Grid? _drillHost;

    /// <summary>
    /// Count, run <paramref name="one"/> once (<paramref name="units"/> tabs or <paramref name="units"/> elements), settle,
    /// count again, write the change: heap bytes, Direct2D objects (blocks typed d2d1) and the modules that changed most.
    /// </summary>
    private static async Task DrillStep(string name, int round, int units, Func<Task> one)
    {
        var before = await DrillSettledCount();
        await one();
        var after = await DrillSettledCount();
        var heap = after.HeapAllocated - before.HeapAllocated;
        var d2d = after.Typed.GetValueOrDefault("d2d1").Count - before.Typed.GetValueOrDefault("d2d1").Count;
        LeakProbe.Note(FormattableString.Invariant(
            $"DRILL {name} r{round} n={units}: heap {heap / 1024.0:+0.0;-0.0}KB ({heap / units:+0;-0} B each) d2d1 {d2d:+0;-0} | typed {LeakProbe.DrillGrowth(after.Typed, before.Typed, DrillTopModules)}"));
    }

    /// <summary>
    /// After a full GC (off the UI thread: finalizers may need it) and a few frames, repeated until the heap stops
    /// shrinking: closed terminals free their sessions on other threads for a while after the tab is gone.
    /// </summary>
    private static async Task<(Dictionary<string, (long Count, long Bytes)> Typed, long HeapAllocated)> DrillSettledCount()
    {
        (Dictionary<string, (long Count, long Bytes)> Typed, long HeapAllocated) last = default;
        for (var i = 0; i < DrillSettleTries; i++)
        {
            await Task.Run(() =>
            {
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
                GC.WaitForPendingFinalizers();
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
            });
            await DrillFrames(DrillSettleFrames);
            await Task.Delay(DrillSettleMs);
            var now = await Task.Run(LeakProbe.DrillCount);
            if (i > 0 && Math.Abs(now.HeapAllocated - last.HeapAllocated) < DrillSteadyBytes) return now;
            last = now;
        }
        return last;
    }

    /// <summary>The dialog card and its rounded parts (body scroller, body panel, command row) with their corner radii.</summary>
    private List<(FrameworkElement Element, CornerRadius Radius)> DrillCardCorners()
    {
        var list = new List<(FrameworkElement, CornerRadius)> { (ModalCard, ModalCard.CornerRadius) };
        if (ModalCard.Child is not Grid grid) return list;
        foreach (var child in grid.Children.OfType<FrameworkElement>())
        {
            list.Add((child, DrillCorner(child)));
            if (child is ScrollViewer { Content: FrameworkElement body }) list.Add((body, DrillCorner(body)));
        }
        return list;
    }

    private static CornerRadius DrillCorner(FrameworkElement e) => e switch
    {
        Control c => c.CornerRadius,
        Grid g => g.CornerRadius,
        StackPanel p => p.CornerRadius,
        Border b => b.CornerRadius,
        _ => default,
    };

    private static void DrillSetCorner(FrameworkElement e, CornerRadius r)
    {
        switch (e)
        {
            case Control c: c.CornerRadius = r; break;
            case Grid g: g.CornerRadius = r; break;
            case StackPanel p: p.CornerRadius = r; break;
            case Border b: b.CornerRadius = r; break;
        }
    }

    private void DrillSetCardCorners(List<(FrameworkElement Element, CornerRadius Radius)> corners, bool inner, bool card)
    {
        foreach (var (e, _) in corners)
            if (ReferenceEquals(e, ModalCard) ? card : inner) DrillSetCorner(e, default);
    }

    private static void DrillRestoreCardCorners(List<(FrameworkElement Element, CornerRadius Radius)> corners)
    {
        foreach (var (e, r) in corners) DrillSetCorner(e, r);
    }

    private Task DrillCycles3(string name, bool modalEach, Func<WorkspaceTab, Task> closeOne, bool switching = true,
        int modalFrames = DrillModalFrames, Func<Task>? beforeClose = null) =>
        DrillRepeatNumbered(DrillCycles, cycle => DrillStep(name, cycle, DrillCycleTabs, () => DrillCycle(switching, modalEach, closeOne, modalFrames, beforeClose)));

    private static async Task DrillRepeatNumbered(int times, Func<int, Task> one)
    {
        for (var i = 1; i <= times; i++) await one(i);
    }

    /// <summary>
    /// One soak cycle: <see cref="DrillCycleTabs"/> local shell tabs opened one after another, then (with
    /// <paramref name="switching"/>) Ctrl+Tab through all of them, then (with <paramref name="modalEach"/>) the close
    /// confirmation shown and dismissed over each tab in turn, then each tab closed by <paramref name="closeOne"/>.
    /// </summary>
    private async Task DrillCycle(bool switching, bool modalEach, Func<WorkspaceTab, Task> closeOne,
        int modalFrames = DrillModalFrames, Func<Task>? beforeClose = null)
    {
        for (var i = 0; i < DrillCycleTabs; i++) await DrillOpenTab();
        if (switching)
            for (var i = 0; i < DrillCycleTabs; i++)
            {
                CycleTab(1);
                await DrillFrames(DrillShownFrames);
                await Task.Delay(DrillSwitchMs);
            }
        if (modalEach)
            foreach (var tab in _tabs.ToList())
            {
                PickTab(tab);
                await DrillFrames(DrillShownFrames);
                await DrillModal(keyboard: true, returnFocus: true, modalFrames);
            }
        if (beforeClose is not null) await beforeClose();
        for (var left = DrillCycleTabs * 2; _active is { } tab; left--)
        {
            if (left == 0) throw new InvalidOperationException("tabs did not close");
            await closeOne(tab);
            await DrillFrames(DrillShownFrames);
            await Task.Delay(DrillSwitchMs);
        }
    }

    private Task DrillCloseNow(WorkspaceTab tab)
    {
        CloseTab(tab, FocusState.Keyboard);
        return Task.CompletedTask;
    }

    /// <summary>Ctrl+Shift+W as the soak presses it: the confirmation, Tab to Close Tab, Enter.</summary>
    private async Task DrillConfirmClose(WorkspaceTab tab)
    {
        var closing = tab.Panes is { } panes ? RequestClosePane(tab, panes.Focused, FocusState.Keyboard) : RequestCloseTab(tab, FocusState.Keyboard);
        await DrillFrames(DrillModalFrames);
        ModalPrimary.Focus(FocusState.Keyboard);
        await DrillFrames(DrillShownFrames);
        CloseModal(true, FocusState.Keyboard);
        await closing;
    }

    /// <summary>The confirmation's dialog over the tab, then the tab closed straight away (not from the dialog's result).</summary>
    private async Task DrillModalThenClose(WorkspaceTab tab, bool keyboard, bool returnFocus)
    {
        await DrillModal(keyboard, returnFocus);
        CloseTab(tab, FocusState.Keyboard);
    }

    /// <summary>
    /// The close confirmation shown (Cancel focused) and accepted; with <paramref name="keyboard"/> Close Tab takes
    /// keyboard focus first (Tab), and without <paramref name="returnFocus"/> focus does not go back to the terminal.
    /// </summary>
    private async Task DrillModal(bool keyboard, bool returnFocus, int modalFrames = DrillModalFrames)
    {
        var body = Ui.Text("“Local shell” is still running. Closing it ends its program.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        var shown = ShowModal("Close running session?", body, primary: "Close Tab", cancel: "Cancel", focusCancel: true);
        await DrillFrames(modalFrames);
        if (keyboard)
        {
            ModalPrimary.Focus(FocusState.Keyboard);
            await DrillFrames(DrillShownFrames);
        }
        if (!returnFocus) _modalReturnFocus = null;
        CloseModal(true, keyboard ? FocusState.Keyboard : FocusState.Pointer);
        await shown;
        await DrillFrames(DrillShownFrames);
    }

    /// <summary>Keyboard focus to the tab's own select button and back to its terminal, no dialog, then close.</summary>
    private async Task DrillFocusAwayThenClose(WorkspaceTab tab)
    {
        tab.Select.Focus(FocusState.Keyboard);
        await DrillFrames(DrillModalFrames);
        tab.View?.Focus(FocusState.Keyboard);
        await DrillFrames(DrillShownFrames);
        CloseTab(tab, FocusState.Keyboard);
    }

    /// <summary>Open one local shell tab as Ctrl+Shift+T does and give it time to draw its prompt.</summary>
    private async Task<WorkspaceTab> DrillOpenTab()
    {
        var open = _tabs.ToHashSet();
        NewLocalShell();
        WorkspaceTab? tab = null;
        for (var waited = 0; (tab = _tabs.FirstOrDefault(t => !open.Contains(t))) is null && waited < DrillTabWaitMs; waited += DrillPollMs)
            await Task.Delay(DrillPollMs);
        if (tab is null) throw new TimeoutException("local shell tab did not open");
        await Task.Delay(DrillShellMs);
        return tab;
    }

    private static async Task DrillRepeat(int times, Func<Task> one)
    {
        for (var i = 0; i < times; i++) await one();
    }

    private static Task DrillFrames(int frames)
    {
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var left = frames;
        EventHandler<object>? tick = null;
        tick = (_, _) =>
        {
            if (--left > 0) return;
            CompositionTarget.Rendering -= tick;
            done.TrySetResult();
        };
        CompositionTarget.Rendering += tick;
        // No frames while the window is minimised or covered: fail the step instead of waiting for ever.
        return done.Task.WaitAsync(DrillFrameTimeout);
    }

    private static async Task DrillOneElement(Grid host, DrillKind kind)
    {
        var element = kind.Make();
        host.Children.Add(element);
        await DrillFrames(DrillShownFrames);
        if (kind.Shown is { } shown)
        {
            shown(element);
            await DrillFrames(DrillShownFrames);
        }
        host.Children.Remove(element);
    }

    /// <summary>The close confirmation as the soak drives it: shown with Cancel focused, Tab to the primary button, closed.</summary>
    private async Task DrillOneModal()
    {
        var body = Ui.Text("“Local shell” is still running. Closing it ends its program.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        _ = ShowModal("Close running session?", body, primary: "Close Tab", cancel: "Cancel", focusCancel: true);
        await DrillFrames(DrillModalFrames);
        ModalPrimary.Focus(FocusState.Keyboard);
        await DrillFrames(DrillShownFrames);
        CloseModal(true);
    }

    /// <summary>One local shell tab as Ctrl+Shift+T opens it, given time to draw its prompt, then closed without asking.</summary>
    private async Task DrillOneTab() => CloseTab(await DrillOpenTab());
}
#endif
