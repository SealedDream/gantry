using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Media.Imaging;

namespace Bastion.Shell;

// The start window (owner-approved design, 2026-11-23): two halves over the gated window. Left, on Mica: the product,
// Recent documents (a ListView, so the arrow keys move through it) and three quiet actions. Right, on the layer fill:
// whatever MainWindow.DocumentGate.cs puts there (unlock, open, missing, welcome, the create form).
public sealed partial class MainWindow
{
    private const string ProductName = "Gantry Terminal";
    private const double StartLeftWidth = 300;
    private const double StartRightMaxWidth = 360;

    private ContentPresenter? _startPane;
    /// <summary>The right half's pinned action row (the create form's Cancel / Create), under its scroller.</summary>
    private ContentPresenter? _startPinned;
    private ListView? _startList;
    private bool _startSyncing;
    private bool _startCreating;
    private string? _startSelected;
    /// <summary>"Keep unlocked until screen locks": no idle lock this run; screen lock and sleep still lock.</summary>
    private bool _keepUnlockedUntilScreenLock;

    private void BuildStartWindow(UIElement right, UIElement? pinned)
    {
        if (_startPane is null || _gate!.Children.Count == 0) CreateStartLayout();
        SyncStartList();
        _startPane!.Content = right;
        _startPinned!.Content = pinned;
        _startPinned.Visibility = pinned is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private void CreateStartLayout()
    {
        _gate!.Children.Clear();
        var mica = ReferenceEquals(RootGrid.Background, _transparent);
        // Mica shows through the left half; the right half is the layer above it (WinUI's standard Mica layering).
        _gate.Background = mica ? _transparent : Ui.Brush(RootGrid, "ShellBackgroundBrush");
        _gate.ColumnDefinitions.Clear();
        _gate.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(StartLeftWidth) });
        _gate.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star), MinWidth = 340 });

        var left = new Grid { Padding = new Thickness(Ui.Double("Space8"), Ui.Double("Space24"), Ui.Double("Space8"), Ui.Double("Space8")) };
        left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        left.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        AddRow(left, StartHeader(), 0);
        var label = Ui.Text("Recent documents", "CaptionSecondaryTextStyle");
        label.Margin = new Thickness(Ui.Double("Space8"), Ui.Double("Space16"), 0, Ui.Double("Space4"));
        AddRow(left, label, 1);
        _startList = new ListView { SelectionMode = ListViewSelectionMode.Single, IsItemClickEnabled = false };
        AutomationProperties.SetName(_startList, "Recent documents");
        _startList.SelectionChanged += (_, _) => StartListSelected();
        AddRow(left, _startList, 2);
        AddRow(left, StartActions(), 3);

        // One surface: with Mica both halves show it (a hairline divides them); without, the shell background.
        var right = new Grid
        {
            Background = mica ? _transparent : Ui.Brush(RootGrid, "ShellBackgroundBrush"),
            BorderBrush = Ui.Brush(RootGrid, "DividerStrokeColorDefaultBrush"),
            BorderThickness = new Thickness(1, 0, 0, 0),
            Padding = new Thickness(Ui.Double("Space32"), Ui.Double("Space24"), Ui.Double("Space32"), Ui.Double("Space24")),
        };
        // The pane, its pinned actions and the footer are one group, centred vertically; when the window is too short
        // the star row (the pane's scroller) gives way first, so the actions and footer stay on screen.
        var group = new Grid { VerticalAlignment = VerticalAlignment.Center, MaxWidth = StartRightMaxWidth, HorizontalAlignment = HorizontalAlignment.Stretch };
        group.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        group.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        group.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        // ContentThemeTransition: Fluent's short fade-and-slide; Windows turns it off with "Animation effects" off.
        _startPane = new ContentPresenter
        {
            HorizontalAlignment = HorizontalAlignment.Stretch,
            ContentTransitions = new TransitionCollection { new ContentThemeTransition { HorizontalOffset = 0, VerticalOffset = 12 } },
        };
        var scroll = new ScrollViewer { Content = _startPane, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        AddRow(group, scroll, 0);
        _startPinned = new ContentPresenter { Margin = new Thickness(0, Ui.Double("Space16"), 0, 0), HorizontalAlignment = HorizontalAlignment.Stretch };
        AddRow(group, _startPinned, 1);
        var footer = Ui.Text("Works offline · No telemetry", "CaptionTertiaryTextStyle");
        footer.Margin = new Thickness(0, Ui.Double("Space24"), 0, 0);
        AddRow(group, footer, 2);
        right.Children.Add(group);
        Grid.SetColumn(right, 1);

        _gate.Children.Add(left);
        _gate.Children.Add(right);
    }

    private readonly Dictionary<UIElement, Visibility> _hiddenByGate = new();

    /// <summary>The library is collapsed while the start window is up, not just covered: nothing of it renders, takes a
    /// click or reaches UI Automation (no connection names before unlock), and the left half shows plain Mica.</summary>
    private void HideBehindGate(bool hide)
    {
        if (!hide)
        {
            foreach (var e in _hiddenByGate.Keys.Where(k => RootGrid.Children.Contains(k)).ToList())
                if (_hiddenByGate.Remove(e, out var v)) e.Visibility = v;
            return;
        }
        foreach (var child in RootGrid.Children)
        {
            if (child is not FrameworkElement e || ReferenceEquals(e, _gate) || ReferenceEquals(e, ModalHost) || Grid.GetRow(e) == 0) continue;
            if (_hiddenByGate.ContainsKey(e)) continue;
            _hiddenByGate[e] = e.Visibility;
            e.Visibility = Visibility.Collapsed;
        }
    }

    private static void AddRow(Grid grid, FrameworkElement child, int row)
    {
        Grid.SetRow(child, row);
        grid.Children.Add(child);
    }

    private FrameworkElement StartHeader()
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space12"), Margin = new Thickness(Ui.Double("Space8"), 0, 0, 0) };
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "Bastion.ico");
        if (File.Exists(icon)) row.Children.Add(new Image { Source = new BitmapImage(new Uri(icon)), Width = 40, Height = 40 });
        var version = typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "dev";
        var text = Stack(Ui.Text(ProductName, "BodyStrongTextStyle"), Ui.Text("Version " + version, "CaptionSecondaryTextStyle"));
        text.Spacing = 0;
        text.VerticalAlignment = VerticalAlignment.Center;
        row.Children.Add(text);
        AutomationProperties.SetName(row, $"{ProductName}, version {version}");
        return row;
    }

    private FrameworkElement StartActions()
    {
        var panel = new StackPanel { Spacing = 2, Padding = new Thickness(0, Ui.Double("Space8"), 0, 0), BorderBrush = Ui.Brush(RootGrid, "DividerStrokeColorDefaultBrush"), BorderThickness = new Thickness(0, 1, 0, 0) };
        // The accessible names are what the UI tests (and screen readers) know these by.
        panel.Children.Add(QuietAction("New document", "", "Ctrl+Shift+N", "Create new document", ShowCreate));
        panel.Children.Add(QuietAction("Open document…", "", "Ctrl+O", "Open document", () => _ = GateOpenAsync(null)));
        // Personal opens with the device key (Personal.bastion) or is the older library.json: never a password.
        panel.Children.Add(QuietAction("Personal library", "", "no password", "Personal library", () => { HideGate(); _ = ShowDocumentAsync(null); }));
        return panel;
    }

    private Button QuietAction(string text, string glyph, string hint, string name, Action click)
    {
        var grid = new Grid { ColumnSpacing = Ui.Double("Space12") };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var icon = Glyph(glyph);
        icon.Foreground = Ui.Brush(RootGrid, "TextFillColorSecondaryBrush");
        var label = Ui.Text(text, "BodyTextStyle");
        var tail = Ui.Text(hint, "CaptionTertiaryTextStyle");
        tail.VerticalAlignment = label.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(label, 1);
        Grid.SetColumn(tail, 2);
        grid.Children.Add(icon);
        grid.Children.Add(label);
        grid.Children.Add(tail);
        var b = new Button
        {
            Content = grid,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            MinHeight = 32,
            Background = _transparent,
            BorderThickness = new Thickness(0),
        };
        AutomationProperties.SetName(b, name);
        b.Click += (_, _) => click();
        return b;
    }

    // ---- Recents ----

    private IReadOnlyList<RecentDocumentDto> StartRecents()
    {
        try { return DocumentClient.RecentDetails(SessionDataDir).Where(r => !IsPersonalPath(r.Path)).Take(GateRecentLimit).ToList(); }
        catch (BastionException) { return []; }
    }

    private static string RecentName(RecentDocumentDto r) => r.Name ?? Path.GetFileNameWithoutExtension(r.Path);

    /// <summary>Refill the list (when it changed) and select the shown document, without re-running the selection.</summary>
    private void SyncStartList()
    {
        if (_startList is null) return;
        _startSyncing = true;
        try
        {
            var recents = StartRecents();
            var paths = recents.Select(r => r.Path).ToList();
            var current = _startList.Items.OfType<ListViewItem>().Select(i => (string)i.Tag).ToList();
            if (!paths.SequenceEqual(current))
            {
                _startList.Items.Clear();
                foreach (var r in recents) _startList.Items.Add(StartRow(r));
            }
            if (recents.Count == 0)
            {
                var none = Ui.Text("No documents yet.", "CaptionTertiaryTextStyle");
                none.Margin = new Thickness(Ui.Double("Space8"), Ui.Double("Space4"), 0, 0);
                _startList.Header = none;
            }
            else _startList.Header = null;
            _startList.SelectedItem = _startCreating ? null
                : _startList.Items.OfType<ListViewItem>().FirstOrDefault(i => _startSelected is { } s && string.Equals((string)i.Tag, s, StringComparison.OrdinalIgnoreCase));
        }
        finally { _startSyncing = false; }
    }

    private ListViewItem StartRow(RecentDocumentDto r)
    {
        var name = RecentName(r);
        var grid = new Grid { ColumnSpacing = Ui.Double("Space8"), Padding = new Thickness(0, Ui.Double("Space4"), 0, Ui.Double("Space4")) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var caution = Ui.Brush(RootGrid, "SystemFillColorCautionBrush");
        var icon = Glyph(r.Present ? (r.Protected ? "" : "") : "");
        icon.FontSize = 12;
        icon.VerticalAlignment = VerticalAlignment.Top;
        icon.Margin = new Thickness(0, 4, 0, 0);
        icon.Foreground = r.Present ? Ui.Brush(RootGrid, "TextFillColorSecondaryBrush") : caution;
        var title = Ui.Text(name, "BodyTextStyle");
        title.TextTrimming = TextTrimming.CharacterEllipsis;
        var folder = FriendlyFolder(r.Path);
        var detail = Ui.Text(r.Present ? Join(folder, Connections(r.ConnectionCount), r.LastOpenedAt is { } s ? Ago(s) : null) : "Not found · " + folder, "CaptionSecondaryTextStyle");
        detail.TextTrimming = TextTrimming.CharacterEllipsis;
        if (!r.Present)
        {
            title.Foreground = caution;
            // The core reports a file whose header cannot be read as not present too: say so instead of calling it missing.
            AutomationProperties.SetName(title, name + (File.Exists(r.Path) ? " (unreadable)" : " (missing)"));
        }
        var text = Stack(title, detail);
        text.Spacing = 0;
        Grid.SetColumn(text, 1);
        grid.Children.Add(icon);
        grid.Children.Add(text);
        if (!r.Present)
        {
            var locate = new Button { Content = "Locate", VerticalAlignment = VerticalAlignment.Center };
            AutomationProperties.SetName(locate, "Locate " + name);
            locate.Click += (_, _) => _ = GateOpenAsync(Path.GetDirectoryName(r.Path));
            Grid.SetColumn(locate, 2);
            grid.Children.Add(locate);
        }
        var item = new ListViewItem { Content = grid, Tag = r.Path, HorizontalContentAlignment = HorizontalAlignment.Stretch };
        var menu = new MenuFlyout();
        var forget = new MenuFlyoutItem { Text = "Remove from Recents" };
        forget.Click += (_, _) => RemoveRecent(r);
        menu.Items.Add(forget);
        item.ContextFlyout = menu;
        AutomationProperties.SetName(item, r.Present ? "Open " + name : name + " (missing)");
        ToolTipService.SetToolTip(item, r.Path);
        return item;
    }

    /// <summary>A row picked (click or arrow keys): a protected one shows its unlock, an unprotected one Open, a
    /// missing one Locate.</summary>
    private void StartListSelected()
    {
        if (_startSyncing || _startList?.SelectedItem is not ListViewItem { Tag: string path }) return;
        var r = StartRecents().FirstOrDefault(x => x.Path == path);
        if (r is null) return;
        _startCreating = false;
        _startSelected = path;
        if (!r.Present) ShowMissingPane(r);
        else if (r.Protected) GateOpen(path);
        else ShowOpenPane(r);
        // Keep the keyboard on the list so the arrows keep moving through it.
        DispatcherQueue.TryEnqueue(() => (_startList.ContainerFromItem(_startList.SelectedItem) as Control)?.Focus(FocusState.Keyboard));
    }

    /// <summary>Ctrl+Shift+N (Ctrl+N stays New Connection, as ⌥⌘N on the Mac), Ctrl+O, and Esc out of the create
    /// form, while the start window is up. No other shortcut runs behind the gate, so Ctrl+Shift+N (New Subfolder
    /// in the tree) cannot collide here.</summary>
    private bool StartWindowKey(Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        var ctrl = Down(Windows.System.VirtualKey.Control);
        var shift = Down(Windows.System.VirtualKey.Shift);
        if (ctrl && shift && e.Key == Windows.System.VirtualKey.N) { ShowCreate(); return true; }
        if (ctrl && e.Key == Windows.System.VirtualKey.O) { _ = GateOpenAsync(null); return true; }
        if (e.Key == Windows.System.VirtualKey.Escape && _startCreating) { LeaveCreate(); return true; }
        return false;
    }

    // ---- Small pieces shared by the panes ----

    private static StackPanel StartTitle(string title, string? detail)
    {
        var heading = Ui.Text(title, "SubtitleTextStyle");
        heading.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetHeadingLevel(heading, Microsoft.UI.Xaml.Automation.Peers.AutomationHeadingLevel.Level1);
        var s = Stack(heading);
        s.Spacing = Ui.Double("Space4");
        if (detail is { Length: > 0 })
        {
            var d = Ui.Text(detail, "BodySecondaryTextStyle");
            d.TextTrimming = TextTrimming.CharacterEllipsis;
            s.Children.Add(d);
        }
        return s;
    }

    private Grid OrDivider(string text)
    {
        var g = new Grid { ColumnSpacing = Ui.Double("Space8") };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Border Line(int col)
        {
            var b = new Border { Height = 1, VerticalAlignment = VerticalAlignment.Center, Background = Ui.Brush(RootGrid, "DividerStrokeColorDefaultBrush") };
            Grid.SetColumn(b, col);
            return b;
        }
        var t = Ui.Text(text, "CaptionSecondaryTextStyle");
        Grid.SetColumn(t, 1);
        g.Children.Add(Line(0));
        g.Children.Add(t);
        g.Children.Add(Line(2));
        return g;
    }

    private static FontIcon Glyph(string glyph) => new()
    {
        Glyph = glyph,
        FontFamily = (FontFamily)Application.Current.Resources["SymbolFontFamily"],
        FontSize = Ui.Double("IconSize"),
    };

    /// <summary>The document's folder for a row: under the user profile as ~\Documents\…, elsewhere the folder itself.
    /// The full path is the row's tooltip.</summary>
    private static string FriendlyFolder(string path)
    {
        var folder = Path.GetDirectoryName(path) ?? "";
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return home.Length > 0 && folder.StartsWith(home, StringComparison.OrdinalIgnoreCase) ? "~" + folder[home.Length..] : folder;
    }

    /// <summary>"12 connections"; nothing when the count was never recorded.</summary>
    private static string? Connections(int? n) => n switch { null => null, 1 => "1 connection", _ => $"{n} connections" };

    private static string Join(params string?[] parts) => string.Join(" · ", parts.Where(p => !string.IsNullOrEmpty(p)));

    /// <summary>"2 h ago", "3 days ago", then the date.</summary>
    private static string Ago(long unixSeconds)
    {
        var at = DateTimeOffset.FromUnixTimeSeconds(unixSeconds).ToLocalTime();
        var d = DateTimeOffset.Now - at;
        if (d.TotalMinutes < 1) return "just now";
        if (d.TotalHours < 1) return $"{(int)d.TotalMinutes} min ago";
        if (d.TotalDays < 1) return $"{(int)d.TotalHours} h ago";
        if (d.TotalDays < 7) return $"{(int)d.TotalDays} days ago";
        return at.ToString("d");
    }
}
