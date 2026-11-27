using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Attached Tasks… on a connection or a folder (B5, Mac TaskHooksSheet): one row per task with Before connect, After connect,
// After disconnect and All hosts (folders only), then one row per snippet with After connect. A folder's hooks run for every
// connection inside, before the connection's own. Save errors (the core's rules) are shown in the dialog.
public sealed partial class MainWindow
{
    private static readonly (string When, string Target, string Label)[] TaskHookColumns =
    [
        ("before_connect", "task", "Before connect"),
        ("after_connect", "task", "After connect"),
        ("after_disconnect", "task", "After disconnect"),
        ("after_connect", "multi_host", "All hosts"),
    ];

    private async Task EditTaskHooksAsync(TreeItem owner)
    {
        if (_modal is not null) return;
        var isFolder = owner.Folder is not null;
        List<TaskHookDto> hooks;
        List<TaskDto> tasks;
        IReadOnlyList<SnippetDto> snippets;
        try
        {
            hooks = TaskHookClient.Hooks(_library, owner.Id);
            tasks = TaskClient.List(_library);
            snippets = Snippets.Search("");
        }
        catch (BastionException ex) { await ShowModal("Attached Tasks", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }

        var boxes = new List<(CheckBox Box, TaskHookDto Hook)>();
        var grid = new Grid { ColumnSpacing = Ui.Double("Space8"), RowSpacing = Ui.Double("Space4") };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        foreach (var _ in TaskHookColumns) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        AddHookRow(grid, "Task", TaskHookColumns.Select(c => (object)c.Label).ToList());
        foreach (var t in tasks)
        {
            var cells = new List<object>();
            foreach (var c in TaskHookColumns)
            {
                var hook = new TaskHookDto(t.Id, c.When, c.Target);
                var box = HookBox(hooks, hook, $"{t.Name} {c.Label}", TaskHookHelp(c.When, c.Target));
                if (c.Target == "multi_host") box.IsEnabled = isFolder;
                boxes.Add((box, hook));
                cells.Add(box);
            }
            AddHookRow(grid, t.Name, cells);
        }
        if (snippets.Count > 0)
        {
            AddHookRow(grid, "Snippet", ["After connect"]);
            foreach (var s in snippets)
            {
                var hook = new TaskHookDto("", "after_connect", "snippet", s.Id);
                var box = HookBox(hooks, hook, $"{s.Name} After connect", "");
                boxes.Add((box, hook));
                AddHookRow(grid, s.Name, [box]);
            }
        }
        var error = Ui.Text("", "CaptionTextStyle");
        var body = new StackPanel
        {
            Spacing = Ui.Double("Space8"),
            Children = { Ui.Text(owner.Name, "BodyTextBlockStyle"), new ScrollViewer { Content = grid, MaxHeight = 420 }, error },
        };
        bool Save()
        {
            try
            {
                TaskHookClient.SetHooks(_library, owner.Id, boxes.Where(b => b.Box.IsChecked == true).Select(b => b.Hook).ToList());
                SaveLibrary();
                return true;
            }
            catch (BastionException ex) { error.Text = Capitalised(ex.Message); return false; }
        }
        if (await ShowModal("Attached Tasks", body, primary: "Save", cancel: "Cancel", validate: Save, wide: true)) Announce("Attached tasks saved");
    }

    private static string TaskHookHelp(string when, string target) => (when, target) switch
    {
        (_, "multi_host") => "After a connection in this folder connects, run on every host in it",
        ("after_disconnect", _) => "Run once when the session ends",
        _ => "",
    };

    private static CheckBox HookBox(List<TaskHookDto> hooks, TaskHookDto hook, string name, string help)
    {
        var on = hooks.Any(h => h.When == hook.When && h.TargetOrTask == hook.Target
            && (hook.Target == "snippet" ? h.SnippetId == hook.SnippetId : h.TaskId == hook.TaskId));
        var box = new CheckBox { IsChecked = on, MinWidth = 0, HorizontalAlignment = HorizontalAlignment.Center };
        AutomationProperties.SetName(box, name);
        if (help.Length > 0) ToolTipService.SetToolTip(box, help);
        return box;
    }

    /// <summary>A row: the name in column 0, then one cell per column (a header string or a check box).</summary>
    private static void AddHookRow(Grid grid, string name, IReadOnlyList<object> cells)
    {
        var row = grid.RowDefinitions.Count;
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var label = Ui.Text(name, "BodyTextBlockStyle");
        label.TextTrimming = TextTrimming.CharacterEllipsis;
        label.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetRow(label, row);
        grid.Children.Add(label);
        for (var i = 0; i < cells.Count; i++)
        {
            var cell = cells[i] as FrameworkElement ?? Ui.Text((string)cells[i], "CaptionTextStyle");
            cell.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetRow(cell, row);
            Grid.SetColumn(cell, i + 1);
            grid.Children.Add(cell);
        }
    }
}
