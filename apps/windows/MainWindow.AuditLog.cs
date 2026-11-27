using System.Collections.ObjectModel;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace Bastion.Shell;

// LOG-NATIVE-01 item 5 (Windows): Application › Audit log. A read-only table of the security audit log, newest first,
// in pages of 500, with the hash chain's state on top: "Log intact" or "Changed at record N". Nothing here writes to or
// deletes from the log (core audit_view, C ABI 123). A virtualised ListView, no animated templates.
public sealed partial class MainWindow
{
    /// <summary>One row; plain properties for the template's bindings.</summary>
    [WinRT.GeneratedBindableCustomProperty] // AOT: {Binding} in XamlReader templates reads properties through this, not reflection
    public sealed partial class AuditRow(AuditRecordDto r)
    {
        public string Time { get; } = AuditFormat.Time(r.TsUnixMs);
        public string Category { get; } = AuditFormat.Category(r.Category);
        public string Action { get; } = r.Action;
        public string Target { get; } = r.Target ?? "";
        public string Outcome { get; } = AuditFormat.Outcome(r.Outcome);
        public string Details { get; } = AuditFormat.Details(r.Details);
        public string Name => $"{Time}, {Category}, {Action}, {Target}, {Outcome}, {Details}";
    }

    private readonly List<AuditRecordDto> _auditLoaded = [];
    private readonly ObservableCollection<AuditRow> _auditShown = [];
    private int _auditTotal, _auditRead; // _auditRead: lines read so far (a damaged line is read but not shown)
    private string _auditText = "";
    private TextBlock? _auditStatus, _auditCount;
    private Button? _auditMoreButton;

    internal void OpenAuditLog()
    {
        _pageKind = "audit";
        _auditLoaded.Clear();
        _auditShown.Clear();
        _auditTotal = _auditRead = 0;
        ShowAuditLogPage();
        _ = LoadAuditAsync(verify: true);
    }

    private void ShowAuditLogPage()
    {
        if (_pageKind != "audit") return;
        var content = new Grid { RowSpacing = Ui.Double("Space8") };
        foreach (var h in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            content.RowDefinitions.Add(new RowDefinition { Height = h });

        _auditStatus = Ui.Text("Checking…", "BodyStrongTextStyle");
        AutomationProperties.SetName(_auditStatus, "Log status");
        ToolTipService.SetToolTip(_auditStatus, "Each record holds a hash of the one before it, so an edit, a deletion or a reorder shows here. A local administrator can still rewrite the whole file.");
        content.Children.Add(_auditStatus);

        var search = new TextBox { PlaceholderText = "Filter", Text = _auditText, MaxWidth = 320, HorizontalAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetName(search, "Filter by action, target, category or details");
        ToolTipService.SetToolTip(search, "Action, target, category or details");
        search.TextChanged += (_, _) => { _auditText = search.Text.Trim(); ShowAuditRows(); };
        Grid.SetRow(search, 1);
        content.Children.Add(search);

        var header = AuditColumns();
        var col = 0;
        foreach (var name in new[] { "Time", "Category", "Action", "Target", "Outcome", "Details" })
        {
            var t = Ui.Text(name, "CaptionTextStyle");
            Grid.SetColumn(t, col++);
            header.Children.Add(t);
        }
        Grid.SetRow(header, 2);
        content.Children.Add(header);

        var list = new ListView { ItemsSource = _auditShown, SelectionMode = ListViewSelectionMode.Single, ItemTemplate = AuditTemplate.Value };
        AutomationProperties.SetName(list, "Audit records");
        Grid.SetRow(list, 3);
        content.Children.Add(list);

        var footer = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        _auditCount = Ui.Text("", "CaptionSecondaryTextStyle");
        _auditCount.VerticalAlignment = VerticalAlignment.Center;
        _auditMoreButton = new Button { Content = "Show more", Style = Ui.Style("SubtleButtonStyle"), Visibility = Visibility.Collapsed };
        _auditMoreButton.Click += (_, _) => _ = LoadAuditAsync(verify: false);
        footer.Children.Add(_auditCount);
        footer.Children.Add(_auditMoreButton);
        Grid.SetRow(footer, 4);
        content.Children.Add(footer);

        AddPageNote(content, "Security record: vault unlocks, credential use, host keys, exports. Append-only.", "Session activity", OpenActivity);
        ShowPage(null, "Audit log", content);
    }

    private static Grid AuditColumns()
    {
        var g = new Grid { ColumnSpacing = 8 };
        foreach (var w in new[] { new GridLength(140), new GridLength(130), new GridLength(1, GridUnitType.Star), new GridLength(1, GridUnitType.Star), new GridLength(70), new GridLength(1.5, GridUnitType.Star) })
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        return g;
    }

    private static readonly Lazy<DataTemplate> AuditTemplate = new(() => (DataTemplate)XamlReader.Load(
        """
        <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
          <Grid ColumnSpacing="8" MinHeight="28" AutomationProperties.Name="{Binding Name}">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="140"/><ColumnDefinition Width="130"/><ColumnDefinition Width="*"/>
              <ColumnDefinition Width="*"/><ColumnDefinition Width="70"/><ColumnDefinition Width="1.5*"/>
            </Grid.ColumnDefinitions>
            <TextBlock Grid.Column="0" Text="{Binding Time}" VerticalAlignment="Center"/>
            <TextBlock Grid.Column="1" Text="{Binding Category}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
            <TextBlock Grid.Column="2" Text="{Binding Action}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
            <TextBlock Grid.Column="3" Text="{Binding Target}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
            <TextBlock Grid.Column="4" Text="{Binding Outcome}" VerticalAlignment="Center"/>
            <TextBlock Grid.Column="5" Text="{Binding Details}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
          </Grid>
        </DataTemplate>
        """));

    /// <summary>The next page (and, when opening, the chain check), off the UI thread.</summary>
    private async Task LoadAuditAsync(bool verify)
    {
        var dir = SessionDataDir;
        var offset = _auditRead;
        try
        {
            var (page, check) = await Task.Run(() => (AuditClient.Read(dir, offset), verify ? AuditClient.Verify(dir) : null));
            if (_pageKind != "audit" || offset != _auditRead) return;
            if (check is not null && _auditStatus is { } st) st.Text = AuditFormat.Status(check);
            _auditTotal = page.Total;
            _auditLoaded.AddRange(page.Records);
            _auditRead = Math.Min(page.Total, offset + AuditClient.PageSize);
            ShowAuditRows();
        }
        catch (BastionException ex)
        {
            if (_auditStatus is { } s) s.Text = "Could not read the audit log: " + ex.Message;
        }
    }

    private void ShowAuditRows()
    {
        _auditShown.Clear();
        foreach (var r in _auditLoaded.Where(r => AuditFormat.Matches(r, _auditText))) _auditShown.Add(new AuditRow(r));
        if (_auditCount is { } c) c.Text = $"{Plural(_auditShown.Count, "record")} of {_auditTotal}";
        if (_auditMoreButton is { } more) more.Visibility = _auditRead < _auditTotal ? Visibility.Visible : Visibility.Collapsed;
    }

    // ---- Snapshot hooks ----

    internal string AuditStatusForSnapshot() => _auditStatus?.Text ?? "";
}
