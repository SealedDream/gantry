using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// TABBAR-WIN (Mac #1277, owner items 4 and 6): Home shows the start page (recent sessions) while tabs stay open, from
// the home button at the start of the strip, Ctrl+Shift+H, the palette and the Bastion menu; picking a tab leaves it.
// Rename Tab (double-click a tab, or right-click > Rename Tab…) names a tab for its life; an empty name brings back the
// automatic one (the connection name or the program title).
public sealed partial class MainWindow
{
    private bool _homeShown;

    private void ShowHome()
    {
        var docked = _tabs.Any(IsDocked);
        if (!docked && _pageConnectionId is null) return; // the start page already shows
        _homeShown = docked; // with no tab, leaving the connection page is enough (WIN-BUGS-01: Home did nothing there)
        _pageConnectionId = null;
        ApplyHome();
        if (_roots.Count > 0) EmptyTitle.Text = "Home";
        RefreshRecents();
    }

    private void LeaveHome()
    {
        if (!_homeShown) return;
        _homeShown = false;
        ApplyHome();
    }

    /// <summary>The start page shows with no docked tab, or while Home is picked; the sessions otherwise.</summary>
    private void ApplyHome()
    {
        var docked = _tabs.Any(IsDocked);
        if (!docked) _homeShown = false;
        var page = ApplyConnectionPage(); // UI-04: a clicked connection with no open session shows its page
        var home = !page && (_homeShown || !docked);
        SessionHost.Visibility = home || page ? Visibility.Collapsed : Visibility.Visible;
        StartPage.Visibility = home ? Visibility.Visible : Visibility.Collapsed;
        SyncSessionSurface(); // UI-06: window tones follow what shows
    }

    private void Home_Click(object sender, RoutedEventArgs e) => ShowHome();

    /// <summary>Rename Tab…: the typed name, or empty for the automatic name.</summary>
    private async Task RenameTabAsync(WorkspaceTab tab)
    {
        var name = new TextBox { Header = "Name", Text = tab.CustomTitle ?? tab.Title, PlaceholderText = tab.AutoTitle ?? tab.Title };
        AutomationProperties.SetName(name, "Tab name");
        ToolTipService.SetToolTip(name, "Empty: automatic name");
        if (!await ShowModal("Rename Tab", name, primary: "Rename", cancel: "Cancel", focus: name)) return;
        RenameTab(tab, name.Text);
    }

    internal void RenameTab(WorkspaceTab tab, string? text)
    {
        var name = (text ?? "").Trim();
        if (name.Length == 0)
        {
            if (tab.CustomTitle is null) return;
            var auto = tab.AutoTitle ?? tab.DefaultTitle;
            tab.CustomTitle = null;
            tab.AutoTitle = null;
            ShowTabTitle(tab, auto);
            return;
        }
        if (tab.CustomTitle is null) tab.AutoTitle = tab.Title;
        tab.CustomTitle = name;
        ShowTabTitle(tab, name);
    }

    /// <summary>Puts <paramref name="title"/> on the tab, keeping the bell mark and the broadcast word.</summary>
    private void ShowTabTitle(WorkspaceTab tab, string title)
    {
        tab.Title = title;
        var label = tab.Broadcast ? $"{title} ({BroadcastStatus})" : title;
        if (tab.Label.Text.StartsWith(BellMark, System.StringComparison.Ordinal)) label = BellMark + label;
        tab.Label.Text = label;
        AutomationProperties.SetName(tab.Close, "Close " + title);
        ApplyTabName(tab);
        SyncSessionRows();
        LayoutTabs();
    }
}
