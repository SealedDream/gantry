using System.Collections.ObjectModel;
using System.Globalization;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace Bastion.Shell;

// LOG-NATIVE-01 (Windows): Application › Activity, the session history the core keeps (C ABI 98). Newest first, in pages
// of 500 from the core; filters for range, protocol, result and free text; sortable columns; Export… writes exactly the
// rows shown. Read-only: nothing here writes to or deletes from the store. A virtualised ListView, no animated templates.
public sealed partial class MainWindow
{
    /// <summary>One row of the list; plain properties for the data template's bindings.</summary>
    [WinRT.GeneratedBindableCustomProperty] // AOT: {Binding} in XamlReader templates reads properties through this, not reflection
    public sealed partial class ActivityRow(ActivitySessionDto s)
    {
        public ActivitySessionDto Session { get; } = s;
        public string Started { get; } = FormatWhen(DateTimeOffset.FromUnixTimeMilliseconds(s.StartedAt).ToLocalTime(), DateTimeOffset.Now);
        public string Connection { get; } = s.ConnectionName;
        public string Protocol { get; } = ActivityFormat.Protocol(s.Protocol);
        public string Target { get; } = ActivityFormat.Target(s) + (s.Username is { Length: > 0 } u ? " as " + u : "");
        public string Duration { get; } = ActivityFormat.Duration(s.DurationMs);
        public string Result { get; } = ActivityFormat.Result(s);
        public string Name => $"{Started}, {Connection}, {Protocol}, {Target}, {Duration}, {Result}";
    }

    private static readonly (string Label, string? Value)[] ActivityProtocols =
        [("All protocols", null), ("SSH", "ssh"), ("SFTP", "sftp"), ("SCP", "scp"), ("FTPS", "ftps"), ("RDP", "rdp"), ("VNC", "vnc"), ("Telnet", "telnet"), ("Web", "web")];
    private static readonly (string Label, string? Value)[] ActivityResults = [("Any result", null), ("OK", "ok"), ("Failed", "failed"), ("Open", "open")];
    private static readonly (string Label, string Value)[] ActivityRanges = [("Last 24 hours", "day"), ("Last 7 days", "week"), ("Last 30 days", "month"), ("All time", "all")];

    private readonly List<ActivitySessionDto> _activityLoaded = [];
    private readonly ObservableCollection<ActivityRow> _activityShown = [];
    private bool _activityMore;
    private string _activitySort = "Started";
    private bool _activityDescending = true;
    private int _activityProtocol, _activityResult, _activityRange = 1;
    private string _activityText = "";
    private TextBlock? _activityStatus;
    private Button? _activityMoreButton;
    /// <summary>"Show all…" from a connection's or folder's History: only that one ("connection" or "folder").</summary>
    private (string Kind, string Id, string Name)? _activityScope;

    /// <summary>At launch, off the UI thread: purge past retention, close what a crashed run left open. Never blocks.</summary>
    private void StartActivityHousekeeping()
    {
        if (_demo) return;
        var dir = SessionDataDir;
        _ = Task.Run(() =>
        {
            try { ActivityClient.Housekeep(dir); }
            catch (BastionException) { } // history is informational; the next launch tries again
            catch (DllNotFoundException) { }
        });
    }

    internal void OpenActivity() => OpenActivityFor(null);

    /// <summary>Activity for one connection or folder (its History's "Show all…"), or for everything (null).</summary>
    internal void OpenActivityFor((string Kind, string Id, string Name)? scope)
    {
        _activityScope = scope;
        if (scope is not null) _activityRange = ActivityRanges.Length - 1; // all time: the History shows the newest
        _pageKind = "activity";
        ShowActivityPage();
        _ = ReloadActivityAsync();
    }

    private void ShowActivityPage()
    {
        if (_pageKind != "activity") return;
        var content = new Grid { RowSpacing = Ui.Double("Space8") };
        foreach (var h in new[] { GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            content.RowDefinitions.Add(new RowDefinition { Height = h });

        var filters = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        filters.Children.Add(ActivityChoice("Range", ActivityRanges.Select(r => r.Label), _activityRange, i => { _activityRange = i; _ = ReloadActivityAsync(); }));
        filters.Children.Add(ActivityChoice("Protocol", ActivityProtocols.Select(r => r.Label), _activityProtocol, i => { _activityProtocol = i; _ = ReloadActivityAsync(); }));
        filters.Children.Add(ActivityChoice("Result", ActivityResults.Select(r => r.Label), _activityResult, i => { _activityResult = i; _ = ReloadActivityAsync(); }));
        var search = new TextBox { PlaceholderText = "Filter", Text = _activityText, MinWidth = 160 };
        AutomationProperties.SetName(search, "Filter by connection, host or user");
        ToolTipService.SetToolTip(search, "Connection, host or user");
        search.TextChanged += (_, _) => { _activityText = search.Text.Trim(); ShowActivityRows(); };
        filters.Children.Add(search);
        if (_activityScope is { } scope)
        {
            var clear = new Button { Content = "Show all sessions", Style = Ui.Style("SubtleButtonStyle") };
            clear.Click += (_, _) => { _activityScope = null; ShowActivityPage(); _ = ReloadActivityAsync(); };
            var only = Ui.Text("Only " + scope.Name, "BodyStrongTextStyle");
            only.VerticalAlignment = VerticalAlignment.Center;
            only.TextTrimming = TextTrimming.CharacterEllipsis;
            filters.Children.Insert(0, clear);
            filters.Children.Insert(0, only);
        }
        content.Children.Add(new ScrollViewer { Content = filters, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled });

        var header = ActivityColumns();
        foreach (var (col, key) in new[] { (0, "Started"), (1, "Connection"), (2, "Protocol"), (3, "Host"), (4, "Duration"), (5, "Result") })
        {
            var b = new Button { Content = key + (key == _activitySort ? (_activityDescending ? " ↓" : " ↑") : ""), Style = Ui.Style("SubtleButtonStyle"), Padding = new Thickness(4, 2, 4, 2) };
            AutomationProperties.SetName(b, "Sort by " + key);
            b.Click += (_, _) => { _activityDescending = _activitySort == key ? !_activityDescending : key == "Started"; _activitySort = key; ShowActivityPage(); ShowActivityRows(); };
            Grid.SetColumn(b, col);
            header.Children.Add(b);
        }
        Grid.SetRow(header, 1);
        content.Children.Add(header);

        var list = new ListView { ItemsSource = _activityShown, SelectionMode = ListViewSelectionMode.Single, ItemTemplate = ActivityTemplate.Value };
        AutomationProperties.SetName(list, "Sessions");
        WireTranscriptOpen(list);
        Grid.SetRow(list, 2);
        content.Children.Add(list);

        var footer = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        _activityStatus = Ui.Text("", "CaptionSecondaryTextStyle");
        _activityStatus.VerticalAlignment = VerticalAlignment.Center;
        _activityMoreButton = new Button { Content = "Show more", Style = Ui.Style("SubtleButtonStyle"), Visibility = _activityMore ? Visibility.Visible : Visibility.Collapsed };
        _activityMoreButton.Click += (_, _) => _ = LoadMoreActivityAsync();
        footer.Children.Add(_activityStatus);
        footer.Children.Add(_activityMoreButton);
        // LOG-NATIVE-01 item 4: the selected session's transcript, when it has one (also double-click, Enter, right-click).
        var open = new Button { Content = Ui.Icon("GlyphDocument"), Style = Ui.Style("SubtleButtonStyle"), IsEnabled = false };
        AutomationProperties.SetName(open, "Open Transcript");
        ToolTipService.SetToolTip(open, "Open the selected session's transcript");
        open.Click += (_, _) => { if (list.SelectedItem is ActivityRow { Session.TranscriptPath: { Length: > 0 } } r) OpenTranscript(r.Session); };
        list.SelectionChanged += (_, _) => open.IsEnabled = list.SelectedItem is ActivityRow { Session.TranscriptPath: { Length: > 0 } };
        footer.Children.Add(open);
        Grid.SetRow(footer, 3);
        content.Children.Add(footer);

        var export = new Button { Content = Ui.Icon("GlyphImport"), Style = Ui.Style("SubtleButtonStyle") };
        AutomationProperties.SetName(export, "Export the sessions shown");
        ToolTipService.SetToolTip(export, "Export the sessions shown");
        export.Click += (_, _) => _ = ExportActivityAsync();
        AddPageNote(content, "What happened in your sessions: connects, disconnects, task runs.", "Audit log", OpenAuditLog);
        ShowPage(null, "Activity", content, export);
        UpdateActivityStatus();
    }

    /// <summary>Double-click or Enter opens the row's transcript; right-click offers Open Transcript and Show Transcript in
    /// Explorer. Rows without a transcript do nothing.</summary>
    private void WireTranscriptOpen(ListView list)
    {
        static ActivitySessionDto? WithTranscript(object? item) =>
            item is ActivityRow { Session: { TranscriptPath: { Length: > 0 } } s } ? s : null;
        list.DoubleTapped += (_, e) =>
        {
            if (WithTranscript((e.OriginalSource as FrameworkElement)?.DataContext) is { } s) { OpenTranscript(s); e.Handled = true; }
        };
        list.KeyDown += (_, e) =>
        {
            if (e.Key == Windows.System.VirtualKey.Enter && WithTranscript(list.SelectedItem) is { } s) { OpenTranscript(s); e.Handled = true; }
        };
        list.ContextRequested += (_, e) =>
        {
            var item = (e.OriginalSource as FrameworkElement)?.DataContext ?? list.SelectedItem;
            if (WithTranscript(item) is not { } s) return;
            var menu = new MenuFlyout();
            var open = new MenuFlyoutItem { Text = "Open Transcript" };
            open.Click += (_, _) => OpenTranscript(s);
            var reveal = new MenuFlyoutItem { Text = "Show Transcript in Explorer" };
            reveal.Click += (_, _) => RevealInExplorer(s.TranscriptPath!);
            menu.Items.Add(open);
            menu.Items.Add(reveal);
            if (e.TryGetPosition(list, out var at)) menu.ShowAt(list, at); else menu.ShowAt(e.OriginalSource as FrameworkElement ?? list);
            e.Handled = true;
        };
    }

    /// <summary>Fixed column widths shared by the header and the rows (the template repeats them), so they line up.</summary>
    private static Grid ActivityColumns()
    {
        var g = new Grid { ColumnSpacing = 8 };
        foreach (var w in new[] { new GridLength(130), new GridLength(1, GridUnitType.Star), new GridLength(60), new GridLength(1, GridUnitType.Star), new GridLength(80), new GridLength(120) })
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        return g;
    }

    private static readonly Lazy<DataTemplate> ActivityTemplate = new(() => (DataTemplate)XamlReader.Load(
        """
        <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
          <Grid ColumnSpacing="8" MinHeight="28" AutomationProperties.Name="{Binding Name}">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="130"/><ColumnDefinition Width="*"/><ColumnDefinition Width="60"/>
              <ColumnDefinition Width="*"/><ColumnDefinition Width="80"/><ColumnDefinition Width="120"/>
            </Grid.ColumnDefinitions>
            <TextBlock Grid.Column="0" Text="{Binding Started}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
            <TextBlock Grid.Column="1" Text="{Binding Connection}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
            <TextBlock Grid.Column="2" Text="{Binding Protocol}" VerticalAlignment="Center"/>
            <TextBlock Grid.Column="3" Text="{Binding Target}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
            <TextBlock Grid.Column="4" Text="{Binding Duration}" VerticalAlignment="Center"/>
            <TextBlock Grid.Column="5" Text="{Binding Result}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
          </Grid>
        </DataTemplate>
        """));

    private static ComboBox ActivityChoice(string name, IEnumerable<string> items, int selected, Action<int> changed)
    {
        var box = new ComboBox { ItemsSource = items.ToList(), SelectedIndex = selected, MinWidth = 130 };
        AutomationProperties.SetName(box, name);
        box.SelectionChanged += (_, _) => { if (box.SelectedIndex >= 0) changed(box.SelectedIndex); };
        return box;
    }

    private ActivityFilter CurrentActivityFilter() => new(
        Protocol: ActivityProtocols[_activityProtocol].Value,
        Result: ActivityResults[_activityResult].Value,
        From: ActivityFormat.RangeStart(ActivityRanges[_activityRange].Value, DateTimeOffset.Now),
        Connection: _activityScope is ("connection", var c, _) ? c : null,
        Folder: _activityScope is ("folder", var f, _) ? f : null);

    private async Task ReloadActivityAsync()
    {
        _activityLoaded.Clear();
        _activityMore = false;
        await LoadMoreActivityAsync();
    }

    /// <summary>The next page from the core, off the UI thread.</summary>
    private async Task LoadMoreActivityAsync()
    {
        var dir = SessionDataDir;
        var filter = CurrentActivityFilter();
        var offset = _activityLoaded.Count;
        var choice = (_activityProtocol, _activityResult, _activityRange, _activityScope);
        if (_activityStatus is { } st) st.Text = "Loading…";
        try
        {
            var page = await Task.Run(() => ActivityClient.Query(dir, filter, offset));
            // A later choice or a closed page wins over this answer.
            if (_pageKind != "activity" || choice != (_activityProtocol, _activityResult, _activityRange, _activityScope) || offset != _activityLoaded.Count) return;
            _activityLoaded.AddRange(page);
            _activityMore = page.Count == ActivityClient.PageSize;
            ShowActivityRows();
        }
        catch (BastionException ex)
        {
            if (_activityStatus is { } s) s.Text = "Could not read the session history: " + ex.Message;
        }
    }

    private IEnumerable<ActivitySessionDto> SortedActivity()
    {
        var rows = _activityLoaded.Where(s => ActivityFormat.Matches(s, _activityText));
        Func<ActivitySessionDto, object> key = _activitySort switch
        {
            "Connection" => s => s.ConnectionName.ToLower(CultureInfo.CurrentCulture),
            "Protocol" => s => s.Protocol,
            "Host" => s => ActivityFormat.Target(s).ToLower(CultureInfo.CurrentCulture),
            "Duration" => s => s.DurationMs ?? -1,
            "Result" => s => ActivityFormat.Result(s),
            _ => s => s.StartedAt,
        };
        return _activityDescending ? rows.OrderByDescending(key) : rows.OrderBy(key);
    }

    private void ShowActivityRows()
    {
        _activityShown.Clear();
        foreach (var s in SortedActivity()) _activityShown.Add(new ActivityRow(s));
        UpdateActivityStatus();
    }

    private void UpdateActivityStatus()
    {
        if (_activityStatus is { } st)
            st.Text = _activityLoaded.Count == 0 ? "No sessions." : Plural(_activityShown.Count, "session");
        if (_activityMoreButton is { } more) more.Visibility = _activityMore ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Export… writes exactly the rows shown, as CSV or JSON.</summary>
    private async Task ExportActivityAsync()
    {
        var rows = _activityShown.Select(r => r.Session).ToList();
        if (rows.Count == 0) { Announce("No sessions to export"); return; }
        // UI tests give the file (TestHooks.ExportPath, test builds only); its extension picks CSV or JSON as the picker's would.
        var path = TestHooks.ExportPath is { } fixedPath ? fixedPath : await PickActivityExportFile();
        if (path is null) return;
        var text = path.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? ActivityFormat.JsonExport(rows) : ActivityFormat.Csv(rows);
        try
        {
            await File.WriteAllTextAsync(path, text);
            Announce($"Exported {Plural(rows.Count, "session")}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Announce("Export failed: " + ex.Message);
        }
    }

    private async Task<string?> PickActivityExportFile()
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "bastion-activity" };
        picker.FileTypeChoices.Add("CSV", new List<string> { ".csv" });
        picker.FileTypeChoices.Add("JSON", new List<string> { ".json" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        return (await picker.PickSaveFileAsync())?.Path;
    }

    // ---- Snapshot hooks ----

    internal IReadOnlyList<string> ActivityLinesForSnapshot() => _activityShown.Select(r => r.Name).ToList();
}
