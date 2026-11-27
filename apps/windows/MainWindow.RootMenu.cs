using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The sidebar's right-click menu on empty space (the core's menu has none for the root): New Folder and New Connection.
/// New Folder uses the New folder form for now; win-tree-fast turns it into an inline rename on its flat tree.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>The root menu's own entries: the core's menu has none for empty space.</summary>
    private List<MenuFlyoutItemBase> RootMenuEntries()
    {
        var folder = new MenuFlyoutItem { Text = "New Folder", Icon = MenuIcon(FluentIcons.Action("folder-add")) };
        AutomationProperties.SetName(folder, "New Folder");
        folder.Click += (_, _) => _ = NewFolderInAsync(null);
        var connection = new MenuFlyoutItem { Text = "New Connection…", Icon = MenuIcon(FluentIcons.Action("add")) };
        AutomationProperties.SetName(connection, "New Connection");
        connection.Click += (_, _) => _ = NewConnectionAsync();
        return [folder, connection];
    }
}
