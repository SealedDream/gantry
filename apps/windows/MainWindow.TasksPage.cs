using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

// Tasks page, design C (Native Mac TasksPage.swift, #1158): one card per task with its command, scope and last result,
// Run (saved scope, else pick), Run on… and More (Edit, Favourite, Delete). Hooks attached to folders and connections are
// listed below. Ad-hoc commands go through Run Command… (Run Command on Hosts). The last result is a tally only.
public sealed partial class MainWindow
{
    private const double TaskCardMinWidth = 260;
    private string _taskFilter = "";
    private const double HookWhenWidth = 140;
    private const string TaskMonoFont = "Cascadia Mono, Consolas";
    private const uint TaskExampleTimeoutSecs = 30;

    /// <summary>Built-in quick checks offered while the library has none of them (SSH, 30 s, trusted after save).</summary>
    private static readonly (string Name, string Program, string[] Args)[] TaskExamples =
    [
        ("Uptime check", "uptime", []),
        ("Disk space", "df", ["-h", "/"]),
    ];

    private void ShowTaskManagerPage()
    {
        if (_pageKind != "tasks") return;
        List<TaskDto> all;
        try { all = TaskClient.List(_library); }
        catch (BastionException ex) { ShowPage(null, "Tasks", CodedErrorText("APP", ex.Message)); return; }
        var ordered = all.OrderByDescending(t => t.Favorite).ThenBy(t => t.Builtin).ThenBy(t => t.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        var content = new StackPanel { Spacing = Ui.Double("Space12") };
        if (ordered.Count == 0) content.Children.Add(Ui.Text("No tasks yet. Add the examples or create one.", "BodySecondaryTextStyle"));
        var built = ordered.Select(t => (Card: TaskCard(t), Task: t)).ToList();
        List<Border> Shown() => built.Where(c => FilterMatches(_taskFilter, c.Task.Name, c.Task.Program, string.Join(' ', c.Task.Args), TaskSummary(c.Task))).Select(c => c.Card).ToList();
        var cards = new ItemsRepeater
        {
            Layout = new UniformGridLayout
            {
                MinItemWidth = TaskCardMinWidth, MinColumnSpacing = Ui.Double("Space8"), MinRowSpacing = Ui.Double("Space8"),
                ItemsStretch = UniformGridLayoutItemsStretch.Fill,
            },
            ItemsSource = Shown(),
        };
        AutomationProperties.SetName(cards, "Tasks");
        if (ordered.Count > 0) content.Children.Add(ListFilterBox(_taskFilter, "Name or command", f => { _taskFilter = f; cards.ItemsSource = Shown(); }));
        content.Children.Add(cards);
        content.Children.Add(TaskHooksSection(all));
        ShowPage(null, "Tasks", content, TaskPageActions(all));
    }

    private StackPanel TaskPageActions(List<TaskDto> all)
    {
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space4") };
        var missing = TaskExamples.Where(e => all.All(t => t.Name != e.Name)).ToList();
        if (missing.Count > 0)
        {
            var examples = PageAction("Add Examples", () => AddTaskExamples(missing), "GlyphImport");
            ToolTipService.SetToolTip(examples, "Add examples: " + string.Join(", ", missing.Select(e => e.Name)));
            bar.Children.Add(examples);
        }
        bar.Children.Add(PageAction("Run Command…", () => _ = MultiExecAsync(), "GlyphTerminal"));
        bar.Children.Add(PageAction("Add Task…", () => _ = EditTaskAsync(null), "GlyphAdd"));
        return bar;
    }

    private static Button PageAction(string label, Action click, string glyph)
    {
        var b = new Button { Content = Ui.Icon(glyph), Style = Ui.Style("SubtleButtonStyle") };
        AutomationProperties.SetName(b, label.TrimEnd('…'));
        ToolTipService.SetToolTip(b, label.TrimEnd('…'));
        b.Click += (_, _) => click();
        return b;
    }

    private Border TaskCard(TaskDto t)
    {
        var scope = TaskTargetStore.Load(t.Id);
        var last = TaskLastResultStore.Load(t.Id);
        var commandText = t.Builtin ? TaskSummary(t) : string.Join(' ', new[] { t.Program }.Concat(t.Args));
        var command = new TextBlock { Text = commandText, FontFamily = new FontFamily(TaskMonoFont), TextTrimming = TextTrimming.CharacterEllipsis, IsTextSelectionEnabled = true };
        ToolTipService.SetToolTip(command, commandText);
        var card = new Border
        {
            Padding = new Thickness(Ui.Double("Space8")),
            BorderThickness = new Thickness(1),
            BorderBrush = Ui.Brush(RootGrid, "CardStrokeColorDefaultBrush"),
            CornerRadius = new CornerRadius(Ui.Double("Space4")),
            Child = new StackPanel
            {
                Spacing = Ui.Double("Space4"),
                Children =
                {
                    TaskCardHead(t), command, CardLine(TaskScopeText(scope)),
                    CardLine(last is null ? "Not run yet" : $"{last.Summary} · {RelativeTime(last.At)}"), TaskCardButtons(t, scope is not null),
                },
            },
        };
        AutomationProperties.SetName(card, "Task " + t.Name);
        AttachTaskMenu(card, t);
        return card;
    }

    private static Grid TaskCardHead(TaskDto t)
    {
        var title = Ui.Text(t.Name + (t.Favorite ? " ★" : ""), "BodyStrongTextStyle");
        title.TextTrimming = TextTrimming.CharacterEllipsis;
        var runs = Ui.Text(t.Builtin ? "Built-in" : t.RunOn == "ssh" ? "SSH" : "This PC", "CaptionSecondaryTextStyle");
        var head = new Grid { ColumnSpacing = Ui.Double("Space8") };
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(runs, 1);
        head.Children.Add(title);
        head.Children.Add(runs);
        return head;
    }

    private Grid TaskCardButtons(TaskDto t, bool hasScope)
    {
        var run = new Button { Content = "Run", Style = Ui.Style("AccentButtonStyle") };
        AutomationProperties.SetName(run, "Run task " + t.Name);
        ToolTipService.SetToolTip(run, hasScope ? "Run on the saved scope" : "Choose a connection");
        run.Click += (_, _) => _ = RunTaskSavedAsync(t);
        var runOn = new Button { Content = "Run on…" };
        AutomationProperties.SetName(runOn, $"Run task {t.Name} on");
        runOn.Click += (_, _) => _ = RunTaskOnAsync(t);
        var more = new Button { Content = Ui.Icon("GlyphMore", "IconSize"), Style = Ui.Style("SubtleButtonStyle"), Flyout = TaskCardMenu(t) };
        AutomationProperties.SetName(more, "More for " + t.Name);
        ToolTipService.SetToolTip(more, "More");
        var buttons = new Grid { ColumnSpacing = Ui.Double("Space8") };
        foreach (var w in new[] { GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        Grid.SetColumn(runOn, 1);
        Grid.SetColumn(more, 3);
        buttons.Children.Add(run);
        buttons.Children.Add(runOn);
        buttons.Children.Add(more);
        return buttons;
    }

    private static TextBlock CardLine(string text)
    {
        var line = Ui.Text(text, "CaptionSecondaryTextStyle");
        line.TextTrimming = TextTrimming.CharacterEllipsis;
        ToolTipService.SetToolTip(line, text);
        return line;
    }

    private MenuFlyout TaskCardMenu(TaskDto t)
    {
        var menu = new MenuFlyout();
        foreach (var item in TaskMenuItems(t, withRun: false)) menu.Items.Add(item);
        return menu;
    }

    /// <summary>
    /// TABBAR-WIN (Mac #1277, owner round 3 item 9 and round 4 item 2): one task menu for the card's More button, a right-click on
    /// a card and a task row in the library tree. Built-in tasks edit in place; Restore Default drops the edit (the core keeps
    /// the built-in's hooks and favourite); Edit a Copy… saves a new task.
    /// </summary>
    private List<MenuFlyoutItemBase> TaskMenuItems(TaskDto t, bool withRun)
    {
        var items = new List<MenuFlyoutItemBase>();
        void Add(string text, string name, string? tip, Action click)
        {
            var item = new MenuFlyoutItem { Text = text };
            AutomationProperties.SetName(item, name);
            if (tip is not null) ToolTipService.SetToolTip(item, tip);
            item.Click += (_, _) => click();
            items.Add(item);
        }
        if (withRun)
        {
            Add("Run", "Run task " + t.Name, "Run on the saved scope, or choose", () => _ = RunTaskSavedAsync(t));
            Add("Run on…", $"Run task {t.Name} on", null, () => _ = RunTaskOnAsync(t));
            AutomationProperties.SetAutomationId(items[^1], "TaskRunOn");
            items.Add(new MenuFlyoutSeparator());
        }
        Add(t.Favorite ? "Remove from Favourites" : "Add to Favourites", (t.Favorite ? "Remove from favourites: " : "Add to favourites: ") + t.Name, null,
            () => SetTaskFavorite(t, !t.Favorite));
        Add("Edit…", "Edit task " + t.Name, t.Builtin ? "Edit this built-in task; Restore Default undoes it" : null, () => _ = EditTaskAsync(t));
        if (t.Builtin && t.Kind == "custom")
            Add("Restore Default", "Restore default: " + t.Name, "Drop your edit of this built-in task", () => _ = RestoreTaskDefaultAsync(t));
        Add("Edit a Copy…", "Edit a copy of task " + t.Name, "Save as a new task", () => _ = EditTaskAsync(t with { Id = "", Builtin = false, Favorite = false, Name = t.Name + " copy" }, copy: true));
        if (t.Builtin) return items;
        items.Add(new MenuFlyoutSeparator());
        Add("Delete", "Delete task " + t.Name, null, () => _ = RemoveTaskAsync(t));
        return items;
    }

    private Task RestoreTaskDefaultAsync(TaskDto t)
    {
        try
        {
            TaskClient.Remove(_library, t.Id); // on a built-in id the core restores the default
            Announce("Default restored " + t.Name);
        }
        catch (BastionException ex) { return ShowModal("Could not restore the default", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        ShowTaskManagerPage();
        RefreshApplicationSection();
        return Task.CompletedTask;
    }

    private string TaskScopeText(TaskTargetChoice? scope)
    {
        if (scope is null) return "Scope: choose on first run";
        if (scope.FolderId is { } f) return "Scope: folder " + (FindFolder(f)?.Name ?? "(deleted)");
        var names = scope.ConnectionIds.Select(id => FindItem(_roots, id)?.Name).OfType<string>().ToList();
        return "Scope: " + (names.Count <= 3 ? string.Join(", ", names) : $"{names.Count} hosts");
    }

    private static string RelativeTime(DateTime at)
    {
        var ago = DateTime.UtcNow - at;
        return ago.TotalMinutes < 1 ? "just now"
            : ago.TotalHours < 1 ? $"{(int)ago.TotalMinutes} min ago"
            : ago.TotalDays < 1 ? $"{(int)ago.TotalHours} h ago"
            : at.ToLocalTime().ToString("d", CultureInfo.CurrentCulture);
    }

    /// <summary>Run: the saved scope straight into the grid; without one, the single-connection run (selection first).</summary>
    private async Task RunTaskSavedAsync(TaskDto t)
    {
        if (_modal is not null) return;
        if (TaskTargetStore.Load(t.Id) is not { } scope) { await RunTaskAsync(t, null); return; }
        var targets = TaskTargets(scope);
        if (targets.Count == 0) { await RunTaskOnAsync(t); return; }
        await RunTaskOnTargetsAsync(t, targets);
        ShowTaskManagerPage();
    }

    /// <summary>Every hook on every folder and connection: when, what, and where it is attached.</summary>
    private StackPanel TaskHooksSection(List<TaskDto> tasks)
    {
        var section = new StackPanel { Spacing = Ui.Double("Space4") };
        section.Children.Add(Ui.Text("Hooks", "BodyStrongTextStyle"));
        var rows = new List<(string When, string What, string Owner)>();
        void Walk(IEnumerable<TreeItem> items)
        {
            foreach (var i in items.Where(i => !i.IsGroup && (i.Folder is not null || i.Connection is not null)))
            {
                try
                {
                    foreach (var h in TaskHookClient.Hooks(_library, i.Id))
                        rows.Add((HookWhen(h.When, h.TargetOrTask), h.TargetOrTask == "snippet" ? "Snippet" : tasks.FirstOrDefault(t => t.Id == h.TaskId)?.Name ?? "Missing task", i.Name));
                }
                catch (BastionException) { /* an item removed meanwhile */ }
                Walk(i.Children);
            }
        }
        Walk(_roots);
        if (rows.Count == 0)
        {
            var none = Ui.Text("None. Attach tasks to a folder or connection from its right-click menu (Attached Tasks…).", "CaptionSecondaryTextStyle");
            none.TextWrapping = TextWrapping.Wrap;
            section.Children.Add(none);
        }
        foreach (var (when, what, owner) in rows) section.Children.Add(HookLine(when, what, owner));
        return section;
    }

    private static Grid HookLine(string when, string what, string owner)
    {
        var line = new Grid { ColumnSpacing = Ui.Double("Space8") };
        foreach (var w in new[] { new GridLength(HookWhenWidth), new GridLength(1, GridUnitType.Star), GridLength.Auto })
            line.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        TextBlock[] cells = [Ui.Text(when, "CaptionSecondaryTextStyle"), Ui.Text(what, "CaptionTextStyle"), Ui.Text(owner, "CaptionSecondaryTextStyle")];
        for (var c = 0; c < cells.Length; c++) { cells[c].TextTrimming = TextTrimming.CharacterEllipsis; Grid.SetColumn(cells[c], c); line.Children.Add(cells[c]); }
        AutomationProperties.SetName(line, $"{when}: {what} on {owner}");
        return line;
    }

    private static string HookWhen(string when, string target) => (when, target) switch
    {
        (_, "multi_host") => "All hosts",
        ("before_connect", _) => "Before connect",
        ("after_connect", _) => "After connect",
        ("after_disconnect", _) => "After disconnect",
        _ => when,
    };

    /// <summary>Saves the example checks the library lacks; each is trusted, as a task the user saves here is (T01).</summary>
    private void AddTaskExamples(IEnumerable<(string Name, string Program, string[] Args)> missing)
    {
        try
        {
            foreach (var e in missing)
            {
                var id = TaskClient.Save(_library, new TaskDto("", e.Name, false, false, "custom", e.Program, [.. e.Args], "ssh", TaskExampleTimeoutSecs));
                TaskHookClient.Trust(_library, id, SessionDataDir);
            }
            Announce("Examples added");
        }
        catch (BastionException ex) { _ = ShowModal("Could not add the examples", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        ShowTaskManagerPage();
    }
}

/// <summary>A task's last run on this PC: the tally only ("3 ok · 1 failed") and when, never the output.</summary>
public sealed record TaskLastResult(string Summary, DateTime At);

/// <summary>Each task's last result, in %LOCALAPPDATA%\Bastion\task-last.json (task ids, tallies and times; no output, no secrets).</summary>
internal static class TaskLastResultStore
{
    private static string Path => System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Gantry", "task-last.json");

    private static Dictionary<string, TaskLastResult> Read()
    {
        try { return File.Exists(Path) ? JsonSerializer.Deserialize(File.ReadAllText(Path), TaskLastJson.Default.DictionaryStringTaskLastResult) ?? [] : []; }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { return []; }
    }

    internal static TaskLastResult? Load(string taskId) => Read().GetValueOrDefault(taskId);

    internal static void Save(string taskId, string summary)
    {
        if (summary.Length == 0) return;
        var all = new Dictionary<string, TaskLastResult>(Read()) { [taskId] = new TaskLastResult(summary, DateTime.UtcNow) };
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            File.WriteAllText(Path, JsonSerializer.Serialize(all, TaskLastJson.Default.DictionaryStringTaskLastResult));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { System.Diagnostics.Debug.WriteLine($"task result not saved: {ex.Message}"); }
    }
}

[JsonSerializable(typeof(Dictionary<string, TaskLastResult>))]
internal sealed partial class TaskLastJson : JsonSerializerContext { }
