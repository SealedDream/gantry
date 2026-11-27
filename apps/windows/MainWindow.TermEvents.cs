using System;
using System.Collections.Generic;
using System.Linq;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// TERM-MARKS (C ABI 132): what a terminal reports besides its screen. The core parses and cleans everything
/// (<c>shellmarks</c>); this polls once a second, only while a terminal is open, and shows it:
/// an unread dot on a background tab, a notice when a long command (10 s or more, OSC 133 marks) ends in a background
/// tab, program notifications (OSC 9 / 777, setting <c>terminal.program-notifications</c>), and a one-click
/// "Save as connection" when <c>ssh [user@]host[:port]</c> is typed in a local shell. Also the red accent of a
/// production-tagged connection's tab.
/// </summary>
public sealed partial class MainWindow
{
    private static readonly TimeSpan TermEventsInterval = TimeSpan.FromSeconds(1);
    private const double UnreadDotSize = 6;
    private DispatcherTimer? _termEventsTimer;
    /// <summary>Saved connections tagged production, read once per tree reload.</summary>
    private HashSet<string> _production = new(StringComparer.Ordinal);

    /// <summary>Called for every new terminal view: make sure the poll runs.</summary>
    private void AttachTermEvents()
    {
        if (_termEventsTimer is not null) return;
        _termEventsTimer = new DispatcherTimer { Interval = TermEventsInterval };
        _termEventsTimer.Tick += (_, _) => PollTermEvents();
        _termEventsTimer.Start();
    }

    private void PollTermEvents()
    {
        var any = false;
        foreach (var tab in _tabs.ToList())
        {
            foreach (var pane in tab.AllPanes)
            {
                if (pane.Session.IsDisposed) continue;
                any = true;
                TerminalEvents ev;
                try { ev = pane.Session.TakeEvents(); }
                catch (Exception ex) when (ex is BastionException or System.Text.Json.JsonException) { continue; }
                HandleTermEvents(tab, ev);
            }
        }
        if (!any) { _termEventsTimer?.Stop(); _termEventsTimer = null; }
    }

    private void HandleTermEvents(WorkspaceTab tab, TerminalEvents ev)
    {
        var background = !ReferenceEquals(tab, _active) && tab.Window is null;
        if (ev.Activity && background) SetUnread(tab, true);
        if (ev.Finished is { } done && background)
        {
            _tray?.Balloon(FinishedTitle(done), tab.Title);
            tab.Notice = FinishedTitle(done);
            PaintTabStatus(tab);
        }
        if (ev.Notification is { } note && SettingValue("terminal.program-notifications") != "false")
        {
            var shown = ProgramTitle.Notice(tab.ConnectionId is null ? tab.DefaultTitle : tab.Title, note.Title, note.Body);
            _tray?.Balloon(shown.Title, shown.Body);
        }
        if (ev.TypedSsh is { } ssh && tab.StartLocal is not null && tab.ConnectionId is null) OfferSaveSsh(tab, ssh);
    }

    /// <summary>"Command finished (2 min)" or "Command failed, exit 2 (40 s)".</summary>
    internal static string FinishedTitle(FinishedCommand done)
    {
        var secs = done.DurationMs / 1000;
        var took = secs >= 120 ? $"{secs / 60} min" : $"{secs} s";
        return done.ExitCode is { } code and not 0 ? $"Command failed, exit {code} ({took})" : $"Command finished ({took})";
    }

    /// <summary>The unread dot: on when a background tab gets output, off when the tab is shown (which also drops a
    /// "Command finished" notice). The state is part of the tab's automation ItemStatus, for tests and screen readers.</summary>
    private void SetUnread(WorkspaceTab tab, bool unread)
    {
        if (tab.UnreadDot is not { } dot) return;
        if (!unread) tab.Notice = null;
        if (tab.Unread != unread) dot.Visibility = unread ? Visibility.Visible : Visibility.Collapsed;
        tab.Unread = unread;
        PaintTabStatus(tab);
    }

    /// <summary>The tab's automation ItemStatus, built in one place: "Active", then a command notice, else "unread
    /// output"; joined with ", ". PaintTab and the event poll both use it, so neither overwrites the other.</summary>
    private string TabItemStatus(WorkspaceTab tab, bool active)
    {
        var extra = tab.Notice ?? (tab.Unread ? "unread output" : null);
        return active ? (extra is null ? "Active" : "Active, " + extra) : extra ?? "";
    }

    private void PaintTabStatus(WorkspaceTab tab) =>
        AutomationProperties.SetItemStatus(tab.Select, TabItemStatus(tab, ReferenceEquals(tab, _active)));

    private Microsoft.UI.Xaml.Shapes.Ellipse NewUnreadDot()
    {
        var dot = new Microsoft.UI.Xaml.Shapes.Ellipse
        {
            Width = UnreadDotSize, Height = UnreadDotSize, VerticalAlignment = VerticalAlignment.Center,
            Visibility = Visibility.Collapsed, Fill = Ui.Brush(RootGrid, "AccentFillColorDefaultBrush"),
        };
        AutomationProperties.SetAutomationId(dot, "TabUnreadDot");
        return dot;
    }

    /// <summary>A one-line bar over a local tab: "ssh root@web1:2222 — Save as connection". One click saves host, user
    /// and port to the library root; no password is ever captured. A newer ssh line replaces the bar.</summary>
    private void OfferSaveSsh(WorkspaceTab tab, TypedSsh ssh)
    {
        if (tab.SshOffer is { } old) tab.Body.Children.Remove(old);
        var target = (ssh.User is { Length: > 0 } u ? u + "@" : "") + ssh.Host + (ssh.Port is { } p and not 22 ? ":" + p : "");
        var save = new Button { Content = "Save as connection" };
        AutomationProperties.SetAutomationId(save, "TypedSshSave");
        var bar = new InfoBar { Message = "ssh " + target, IsOpen = true, IsClosable = true, Severity = InfoBarSeverity.Informational, ActionButton = save };
        AutomationProperties.SetAutomationId(bar, "TypedSshOffer");
        AutomationProperties.SetName(bar, "Save ssh " + target + " as a connection");
        Grid.SetColumnSpan(bar, 2);
        bar.Closed += (_, _) => { tab.Body.Children.Remove(bar); if (ReferenceEquals(tab.SshOffer, bar)) tab.SshOffer = null; };
        save.Click += async (_, _) =>
        {
            bar.IsOpen = false;
            await Mutate(() => _library.AddConnection(null, ssh.Host, "ssh", ssh.Host, ssh.Port, ssh.User), "Could not save the connection");
            Announce($"Saved {target} as a connection");
        };
        tab.SshOffer = bar;
        tab.Body.Children.Add(bar);
    }

    /// <summary>After a tree read: the production-tagged connections (core rule: tag <c>production</c> or <c>prod</c>).</summary>
    private void LoadProduction(FolderDto tree)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        void Walk(FolderDto f)
        {
            foreach (var c in f.Connections) if (TerminalSession.IsProduction(c.Tags)) set.Add(c.Id);
            foreach (var sub in f.Folders) Walk(sub);
        }
        try { Walk(tree); } catch (BastionException) { /* no accent rather than no tree */ }
        _production = set;
    }

    /// <summary>A production tab with no host colour of its own gets a red leading bar and border.</summary>
    private bool PaintProduction(WorkspaceTab tab)
    {
        if (tab.HostColorId is not { } id || !_production.Contains(id)) return false;
        var red = Ui.Brush(RootGrid, "CriticalBrush");
        tab.HostBar.Background = red;
        tab.HostBar.Visibility = Visibility.Visible;
        AutomationProperties.SetName(tab.HostBar, "Production");
        tab.Body.BorderBrush = red;
        tab.Body.BorderThickness = new Thickness(HostBorderWidth);
        return true;
    }
}
