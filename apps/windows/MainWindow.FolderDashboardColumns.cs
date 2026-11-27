using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;

namespace Bastion.Shell;

// FOLDER-COLUMNS: the folder dashboard's column chooser, from the Columns button or a right-click on the header.
public sealed partial class MainWindow
{
    /// <summary>One menu of the columns, rebuilt each time it opens so the button and the header menu always agree.</summary>
    private MenuFlyout DashColumnsFlyout(FlyoutPlacementMode placement)
    {
        var menu = new MenuFlyout { Placement = placement };
        menu.Opening += (_, _) =>
        {
            menu.Items.Clear();
            foreach (var c in Enum.GetValues<DashColumn>().Where(c => c != DashColumn.Name))
            {
                var item = new ToggleMenuFlyoutItem { Text = DashColumns[c].Title, IsChecked = DashChosen.Contains(c) };
                AutomationProperties.SetName(item, "Show " + DashColumns[c].Title + " column");
                AutomationProperties.SetAutomationId(item, "folder-dashboard-column-" + c.ToString().ToLowerInvariant());
                item.Click += (_, _) =>
                {
                    if (item.IsChecked) DashChosen.Add(c); else DashChosen.Remove(c);
                    DashColumnsChanged();
                };
                menu.Items.Add(item);
            }
            menu.Items.Add(new MenuFlyoutSeparator());
            var reset = new MenuFlyoutItem { Text = "Default columns" };
            AutomationProperties.SetAutomationId(reset, "folder-dashboard-columns-reset");
            reset.Click += (_, _) =>
            {
                DashChosen.Clear();
                DashChosen.UnionWith(DashColumnStore.Defaults);
                DashColumnsChanged();
            };
            menu.Items.Add(reset);
        };
        return menu;
    }

    private void DashColumnsChanged()
    {
        DashColumnStore.Save(DashChosen);
        SyncDashLayout();
        ApplyDashFilter(); // the containers fill again with the new layout
    }

    /// <summary>The chosen columns, in %LOCALAPPDATA%\Bastion\dashboard-columns.json (column names only).</summary>
    private static class DashColumnStore
    {
        internal static readonly DashColumn[] Defaults =
            [DashColumn.Name, DashColumn.Address, DashColumn.Type, DashColumn.Status, DashColumn.User, DashColumn.Login, DashColumn.LastConnected];

        private static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Gantry", "dashboard-columns.json");

        internal static HashSet<DashColumn> Load()
        {
            try
            {
                if (File.Exists(FilePath) && JsonSerializer.Deserialize(File.ReadAllText(FilePath), DashColumnJson.Default.ListString) is { } names)
                {
                    var chosen = names.Select(n => Enum.TryParse<DashColumn>(n, out var c) ? c : (DashColumn?)null).OfType<DashColumn>().ToHashSet();
                    chosen.Add(DashColumn.Name);
                    return chosen;
                }
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                System.Diagnostics.Debug.WriteLine($"dashboard columns not read: {ex.Message}");
            }
            return [.. Defaults];
        }

        internal static void Save(IEnumerable<DashColumn> chosen)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                File.WriteAllText(FilePath, JsonSerializer.Serialize(chosen.Select(c => c.ToString()).ToList(), DashColumnJson.Default.ListString));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                System.Diagnostics.Debug.WriteLine($"dashboard columns not saved: {ex.Message}");
            }
        }
    }
}

[JsonSerializable(typeof(List<string>))]
internal sealed partial class DashColumnJson : JsonSerializerContext { }
