using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Broadcast input across a split tab's panes (core C ABI 53): with Broadcast Input on, what is typed or pasted in the
/// focused pane goes to every other pane of the tab. The core decides who receives it (disconnected panes are skipped)
/// and when to ask first (a multi-line paste to several panes); it refuses NUL, over 64 KiB and a paste holding the
/// bracketed-paste end sequence. The tab title shows "(Broadcast)" while it is on.
/// </summary>
public sealed partial class MainWindow
{
    private const string BroadcastStatus = "Broadcast";

    private static IEnumerable<BroadcastTarget> BroadcastTargets(WorkspaceTab tab, TerminalView from) =>
        tab.AllPanes.Where(p => !ReferenceEquals(p, from))
            .Select(p => new BroadcastTarget(p.PaneId.ToString(), tab.Title, !p.Session.IsDisposed && p.Session.IsAlive, Sensitive: false));

    private WorkspaceTab? BroadcastingTabOf(TerminalView view) => _tabs.FirstOrDefault(t => t.Broadcast && t.AllPanes.Contains(view));

    private static IEnumerable<TerminalView> Receivers(WorkspaceTab tab, BroadcastReview review)
    {
        var ids = review.SendTo.ToHashSet();
        return tab.AllPanes.Where(p => ids.Contains(p.PaneId.ToString()) && !p.Session.IsDisposed);
    }

    /// <summary>Keys the user typed in <paramref name="from"/>: mirrored to the tab's other panes while broadcasting.</summary>
    private void OnPaneKeys(TerminalView from, string keys)
    {
        if (BroadcastingTabOf(from) is not { } tab) return;
        BroadcastReview review;
        try { review = Broadcast.Review(paste: false, keys, BroadcastTargets(tab, from), tab.BroadcastAcked); }
        catch (BastionException) { return; } // refused input (NUL) is not mirrored
        foreach (var pane in Receivers(tab, review))
        {
            try { pane.Session.Write(keys); } catch (BastionException) { /* that program exited */ }
        }
    }

    /// <summary>A paste in <paramref name="from"/>: sent to the other panes after the core's review (and the user's yes when it asks).</summary>
    private async Task OnPanePasted(TerminalView from, string text)
    {
        if (BroadcastingTabOf(from) is not { } tab) return;
        BroadcastReview review;
        try { review = Broadcast.Review(paste: true, text, BroadcastTargets(tab, from), tab.BroadcastAcked); }
        catch (BastionException ex) { await ShowModal("Not sent to the other panes", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
        if (review.SendTo.Count == 0) return;
        if (review.NeedsConfirm && !await ConfirmClose($"Paste this text into {review.SendTo.Count} other pane{(review.SendTo.Count == 1 ? "" : "s")} too?", "Paste to All"))
            return;
        foreach (var pane in Receivers(tab, review))
        {
            try { pane.Session.Paste(text); } catch (BastionException) { /* that program exited */ }
        }
    }

    private void SetBroadcast(WorkspaceTab tab, bool on)
    {
        tab.Broadcast = on;
        if (!on) tab.BroadcastAcked = false;
        SetTabStatus(tab, on ? BroadcastStatus : null);
    }

    /// <summary>Broadcast Input to All Panes in a terminal tab's menu; enabled once the tab is split.</summary>
    private void AddBroadcastItem(MenuFlyout menu, WorkspaceTab tab)
    {
        if (tab.View is null) return;
        var item = new ToggleMenuFlyoutItem { Text = "Broadcast Input to All Panes" };
        item.Click += (_, _) => SetBroadcast(tab, item.IsChecked);
        menu.Opening += (_, _) =>
        {
            if (tab.Broadcast && tab.AllPanes.Count() < 2) SetBroadcast(tab, false);
            item.IsChecked = tab.Broadcast;
            item.IsEnabled = tab.AllPanes.Count() >= 2;
        };
        menu.Items.Add(item);
    }
}
