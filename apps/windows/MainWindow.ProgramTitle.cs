namespace Bastion.Shell;

/// <summary>
/// Owner, 2026-11-17: an unsaved terminal tab (local shell, WSL, PowerShell, cmd, Quick Connect) is named after the
/// program's window title (OSC 0/2), so after `ssh host` it reads as the server. A tab of a saved connection keeps the
/// connection's name. The title comes from the remote side, so it is cleaned first.
/// </summary>
public sealed partial class MainWindow
{
    private void FollowProgramTitle(WorkspaceTab tab, string? programTitle)
    {
        if (tab.ConnectionId is not null || !_tabs.Contains(tab)) return; // saved connections keep their name
        var title = ProgramTitle.Marked(programTitle) ?? tab.DefaultTitle;
        if (tab.CustomTitle is not null) { tab.AutoTitle = title; return; } // a renamed tab keeps its name (TABBAR-WIN)
        if (title == tab.Title) return;
        tab.Title = title;
        var label = tab.Broadcast ? $"{title} ({BroadcastStatus})" : title;
        if (tab.Label.Text.StartsWith(BellMark, StringComparison.Ordinal)) label = BellMark + label;
        tab.Label.Text = label;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(tab.Close, "Close " + title);
        ApplyTabName(tab);
        SyncSessionRows(); // the Other sessions row takes the same name
    }
}
