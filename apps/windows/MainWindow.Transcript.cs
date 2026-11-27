using System.Collections.ObjectModel;
using System.Collections.Specialized;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;

namespace Bastion.Shell;

// LOG-NATIVE-01 item 4 (Native Windows, as the Mac's TranscriptView): Activity › Open Transcript shows a session's
// transcript read-only, titled "<connection> — <started>", with Find (Ctrl+F, Enter / Shift+Enter, F3), Show times (only
// when the log has timestamps), Copy and Show in Explorer. Pages of 1 MB are read off the UI thread and appended, so a
// large log shows its first page at once. An ItemsRepeater: only the rows in view exist, also for UI Automation (a ListView made a peer per line, and 3000 lines stalled UIA). Nothing here writes the file, logs
// its text or keeps it anywhere but in this page; the copy is kept out of clipboard history and cloud sync.
public sealed partial class MainWindow
{
    /// <summary>One row of the viewer; plain properties for the data template's binding.</summary>
    [WinRT.GeneratedBindableCustomProperty] // AOT: {Binding} in XamlReader templates reads properties through this, not reflection
    public sealed partial class TranscriptRow(TranscriptLine line, bool showTimes)
    {
        public TranscriptLine Line { get; } = line;
        public string Text { get; } = line.Display(showTimes);
    }

    /// <summary>Appends a page with one Reset instead of one event per line (WinUI takes no multi-item Add).</summary>
    private sealed partial class PagedRows : ObservableCollection<TranscriptRow>
    {
        public void AddPage(IEnumerable<TranscriptRow> rows)
        {
            foreach (var r in rows) Items.Add(r);
            OnPropertyChanged(new System.ComponentModel.PropertyChangedEventArgs(nameof(Count)));
            OnPropertyChanged(new System.ComponentModel.PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }

    private sealed class TranscriptState(ActivitySessionDto session)
    {
        public ActivitySessionDto Session { get; } = session;
        public List<TranscriptLine> Lines { get; } = [];
        public PagedRows Rows { get; } = [];
        public CancellationTokenSource Cancel { get; } = new();
        public bool Loading { get; set; } = true;
        public bool HasTimes { get; set; }
        public bool ShowTimes { get; set; } = true;
        public string? Error { get; set; }
        public string Query { get; set; } = "";
        public IReadOnlyList<int> Hits { get; set; } = [];
        public int? Current { get; set; }
        public ItemsRepeater? List { get; set; }
        public HashSet<int> Selected { get; } = [];
        public int? Anchor { get; set; }
        public TextBlock? Status { get; set; }
        public CheckBox? Times { get; set; }
        public ProgressRing? Ring { get; set; }
        public Button? Copy { get; set; }
        public Button? Previous { get; set; }
        public Button? Next { get; set; }
    }

    private TranscriptState? _transcript;

    private static readonly Lazy<DataTemplate> TranscriptTemplate = new(() => (DataTemplate)XamlReader.Load(
        """
        <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
          <Border Padding="8,1,8,1" Background="Transparent">
            <TextBlock Text="{Binding Text}" FontFamily="Cascadia Mono, Consolas" TextWrapping="NoWrap" AutomationProperties.Name="{Binding Text}"/>
          </Border>
        </DataTemplate>
        """));

    /// <summary>Opens the viewer for a session that has a transcript; Done goes back to Activity.</summary>
    internal void OpenTranscript(ActivitySessionDto session)
    {
        if (session.TranscriptPath is not { Length: > 0 } path) return;
        CloseTranscript();
        var state = _transcript = new TranscriptState(session);
        _pageKind = "transcript";
        ShowTranscriptPage(state);
        _ = LoadTranscriptAsync(state, path);
    }

    /// <summary>Stops a running read; called when the viewer closes.</summary>
    private void CloseTranscript()
    {
        if (_transcript is not { } old) return;
        old.Cancel.Cancel();
        _transcript = null;
    }

    private void ShowTranscriptPage(TranscriptState state)
    {
        var content = new Grid { RowSpacing = Ui.Double("Space8") };
        foreach (var h in new[] { GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            content.RowDefinitions.Add(new RowDefinition { Height = h });

        content.Children.Add(TranscriptFindBar(state, out var find));

        var list = state.List = new ItemsRepeater { ItemsSource = state.Rows, ItemTemplate = TranscriptTemplate.Value, Layout = new StackLayout() };
        list.ElementPrepared += (_, e) => PaintRow(state, e.Element);
        list.Tapped += (_, e) => SelectRow(state, (e.OriginalSource as FrameworkElement)?.DataContext as TranscriptRow);
        var scroll = new ScrollViewer
        {
            Content = list, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollMode = ScrollMode.Auto,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, BorderThickness = new Thickness(1),
            BorderBrush = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
            Background = (Brush)Application.Current.Resources["TextControlBackground"],
        };
        AutomationProperties.SetName(scroll, "Transcript");
        Grid.SetRow(scroll, 1);
        content.Children.Add(scroll);

        var footer = TranscriptFooter(state);
        Grid.SetRow(footer, 2);
        content.Children.Add(footer);

        var ctrlF = new KeyboardAccelerator { Key = VirtualKey.F, Modifiers = VirtualKeyModifiers.Control };
        ctrlF.Invoked += (_, e) => { find.Focus(FocusState.Keyboard); find.SelectAll(); e.Handled = true; };
        var f3 = new KeyboardAccelerator { Key = VirtualKey.F3 };
        f3.Invoked += (_, e) => { StepTranscript(state, forward: true); e.Handled = true; };
        var shiftF3 = new KeyboardAccelerator { Key = VirtualKey.F3, Modifiers = VirtualKeyModifiers.Shift };
        shiftF3.Invoked += (_, e) => { StepTranscript(state, forward: false); e.Handled = true; };
        foreach (var a in new[] { ctrlF, f3, shiftF3 }) content.KeyboardAccelerators.Add(a);
        content.KeyboardAcceleratorPlacementMode = KeyboardAcceleratorPlacementMode.Hidden;

        var title = TranscriptText.Title(state.Session.ConnectionName, DateTimeOffset.FromUnixTimeMilliseconds(state.Session.StartedAt));
        ShowPage(null, title, content);
        UpdateTranscriptStatus(state);
    }

    private UIElement TranscriptFindBar(TranscriptState state, out TextBox find)
    {
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        var box = find = new TextBox { PlaceholderText = "Find", MinWidth = 200 };
        AutomationProperties.SetName(box, "Find");
        ToolTipService.SetToolTip(box, "Find in the transcript (Ctrl+F)");
        box.TextChanged += (_, _) => FindInTranscript(state, box.Text);
        box.KeyDown += (_, e) =>
        {
            if (e.Key != VirtualKey.Enter) return;
            var shift = Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Shift).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down);
            StepTranscript(state, forward: !shift);
            e.Handled = true;
        };
        state.Previous = TranscriptIconButton("", "Find Previous", () => StepTranscript(state, forward: false));
        state.Next = TranscriptIconButton("", "Find Next", () => StepTranscript(state, forward: true));
        var times = state.Times = new CheckBox { Content = "Show times", IsChecked = state.ShowTimes, Visibility = Visibility.Collapsed };
        AutomationProperties.SetName(times, "Show times");
        times.Click += (_, _) => { state.ShowTimes = times.IsChecked == true; RenderTranscript(state); };
        bar.Children.Add(box);
        bar.Children.Add(state.Previous);
        bar.Children.Add(state.Next);
        bar.Children.Add(times);
        return new ScrollViewer { Content = bar, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };
    }

    private Grid TranscriptFooter(TranscriptState state)
    {
        var footer = new Grid { ColumnSpacing = Ui.Double("Space8") };
        foreach (var w in new[] { new GridLength(1, GridUnitType.Star), GridLength.Auto, GridLength.Auto, GridLength.Auto })
            footer.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        var left = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        var status = state.Status = Ui.Text("Loading…", "CaptionSecondaryTextStyle");
        status.VerticalAlignment = VerticalAlignment.Center;
        status.TextTrimming = TextTrimming.CharacterEllipsis;
        AutomationProperties.SetAutomationId(status, "transcript-status");
        state.Ring = new ProgressRing { IsActive = true, Width = 16, Height = 16, MinWidth = 16, MinHeight = 16 };
        AutomationProperties.SetName(state.Ring, "Loading");
        left.Children.Add(status);
        left.Children.Add(state.Ring);
        footer.Children.Add(left);
        var copy = state.Copy = new Button { Content = "Copy", IsEnabled = false };
        AutomationProperties.SetName(copy, "Copy");
        ToolTipService.SetToolTip(copy, "Copy the selected lines, or the whole transcript");
        copy.Click += (_, _) => CopyTranscript(state);
        var reveal = new Button { Content = "Show in Explorer" };
        AutomationProperties.SetName(reveal, "Show in Explorer");
        reveal.Click += (_, _) => RevealInExplorer(state.Session.TranscriptPath!);
        var done = new Button { Content = "Done", Style = Ui.Style("AccentButtonStyle") };
        AutomationProperties.SetName(done, "Done");
        done.Click += (_, _) => BackToActivity();
        foreach (var (b, col) in new[] { (copy, 1), (reveal, 2), (done, 3) }) { Grid.SetColumn(b, col); footer.Children.Add(b); }
        return footer;
    }

    private static Button TranscriptIconButton(string glyph, string name, Action click)
    {
        var b = new Button
        {
            Content = new FontIcon { Glyph = glyph, FontFamily = (FontFamily)Application.Current.Resources["SymbolFontFamily"], FontSize = Ui.Double("IconSize") },
            Style = Ui.Style("SubtleButtonStyle"), IsEnabled = false, MinWidth = 32, MinHeight = 32,
        };
        AutomationProperties.SetName(b, name);
        ToolTipService.SetToolTip(b, name);
        b.Click += (_, _) => click();
        return b;
    }

    /// <summary>Reads the file page by page off the UI thread; each page waits for the UI to take it, so memory stays
    /// about one page ahead and a closed viewer stops the read at the next page.</summary>
    private async Task LoadTranscriptAsync(TranscriptState state, string path)
    {
        var token = state.Cancel.Token;
        try
        {
            await Task.Run(() => TranscriptText.Read(path, page =>
            {
                using var taken = new ManualResetEventSlim();
                var keep = false;
                if (!DispatcherQueue.TryEnqueue(() => { keep = AppendTranscript(state, page); taken.Set(); })) return false;
                try { taken.Wait(token); } catch (OperationCanceledException) { return false; }
                return keep;
            }, cancel: token), token);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            state.Error = "Transcript unavailable: " + ex.Message;
            AppLog.Warn("Transcript could not be read: " + ex.GetType().Name); // never the path or the text
        }
        state.Loading = false;
        if (_transcript == state) UpdateTranscriptStatus(state);
    }

    private bool AppendTranscript(TranscriptState state, IReadOnlyList<TranscriptLine> page)
    {
        if (_transcript != state || state.Cancel.IsCancellationRequested) return false;
        state.Lines.AddRange(page);
        if (!state.HasTimes && TranscriptText.HasTimes(page))
        {
            state.HasTimes = true;
            RenderTranscript(state);
        }
        else
        {
            state.Rows.AddPage(page.Select(l => new TranscriptRow(l, state.ShowTimes)));
        }
        if (state.Query.Length > 0) state.Hits = TranscriptText.Find(state.Query, state.Lines);
        UpdateTranscriptStatus(state);
        return true;
    }

    /// <summary>Rebuilds the rows (Show times changed, or the time column appeared) and keeps the current match in view.</summary>
    private void RenderTranscript(TranscriptState state)
    {
        state.Rows.Clear();
        state.Selected.Clear();
        state.Anchor = null;
        state.Rows.AddPage(state.Lines.Select(l => new TranscriptRow(l, state.ShowTimes)));
        if (state.Current is { } line) Reveal(state, line);
        UpdateTranscriptStatus(state);
    }

    private void FindInTranscript(TranscriptState state, string query)
    {
        state.Query = query.Trim();
        state.Hits = TranscriptText.Find(state.Query, state.Lines);
        state.Current = null;
        StepTranscript(state, forward: true);
        UpdateTranscriptStatus(state);
    }

    private void StepTranscript(TranscriptState state, bool forward)
    {
        if (TranscriptText.Step(state.Hits, state.Current, forward) is not { } next) return;
        state.Current = next;
        Reveal(state, next);
        UpdateTranscriptStatus(state);
    }

    private static void Reveal(TranscriptState state, int line)
    {
        if (state.List is not { } list || line >= state.Rows.Count) return;
        state.Selected.Clear();
        state.Selected.Add(line);
        state.Anchor = line;
        RepaintRows(state);
        list.GetOrCreateElement(line).StartBringIntoView(new BringIntoViewOptions { VerticalAlignmentRatio = 0.5, AnimationDesired = false });
    }

    /// <summary>Click selects a line; Shift+click extends from the last one; Ctrl+click adds or removes one.</summary>
    private static void SelectRow(TranscriptState state, TranscriptRow? row)
    {
        if (row is null) return;
        var n = row.Line.Number;
        bool Down(VirtualKey k) => Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(k).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down);
        if (Down(VirtualKey.Shift) && state.Anchor is { } a)
        {
            state.Selected.Clear();
            for (var i = Math.Min(a, n); i <= Math.Max(a, n); i++) state.Selected.Add(i);
        }
        else if (Down(VirtualKey.Control))
        {
            if (!state.Selected.Remove(n)) state.Selected.Add(n);
            state.Anchor = n;
        }
        else
        {
            state.Selected.Clear();
            state.Selected.Add(n);
            state.Anchor = n;
        }
        RepaintRows(state);
    }

    private static void RepaintRows(TranscriptState state)
    {
        if (state.List is not { } list) return;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(list); i++)
            if (VisualTreeHelper.GetChild(list, i) is UIElement e) PaintRow(state, e);
    }

    private static void PaintRow(TranscriptState state, UIElement element)
    {
        if (element is not Border { DataContext: TranscriptRow row } border) return;
        var on = state.Selected.Contains(row.Line.Number);
        border.Background = on ? (Brush)Application.Current.Resources["SubtleFillColorSecondaryBrush"] : new SolidColorBrush(Microsoft.UI.Colors.Transparent);
        AutomationProperties.SetItemStatus(border, on ? "Selected" : "");
    }

    private void CopyTranscript(TranscriptState state)
    {
        var selected = state.Selected;
        var package = new DataPackage();
        package.SetText(TranscriptText.CopyText(state.Lines, selected, state.ShowTimes && state.HasTimes));
        // A transcript can hold what the user typed: keep the copy out of clipboard history and cloud sync.
        Clipboard.SetContentWithOptions(package, new ClipboardContentOptions { IsAllowedInHistory = false, IsRoamable = false });
        Announce("Copied " + Plural(selected.Count == 0 ? state.Lines.Count : selected.Count, "line"));
    }

    private static void RevealInExplorer(string path)
    {
        try
        {
            var start = new System.Diagnostics.ProcessStartInfo("explorer.exe") { UseShellExecute = false };
            start.ArgumentList.Add("/select," + path);
            System.Diagnostics.Process.Start(start);
        }
        catch (System.ComponentModel.Win32Exception ex) { AppLog.Warn("Show in Explorer failed: " + ex.NativeErrorCode); }
    }

    private void UpdateTranscriptStatus(TranscriptState state)
    {
        if (state.Status is not { } status) return;
        string text;
        if (state.Error is { } error) text = error;
        else
        {
            text = state.Loading && state.Lines.Count == 0 ? "Loading…" : Plural(state.Lines.Count, "line");
            if (state.Query.Length > 0)
            {
                var k = state.Hits.Count;
                if (k == 0) text += " · no match";
                else if (state.Current is { } c && IndexOf(state.Hits, c) is >= 0 and var i) text += $" · {i + 1} of {k}";
            }
        }
        status.Text = text;
        if (state.Ring is { } ring) { ring.IsActive = state.Loading; ring.Visibility = state.Loading ? Visibility.Visible : Visibility.Collapsed; }
        if (state.Times is { } t) t.Visibility = state.HasTimes ? Visibility.Visible : Visibility.Collapsed;
        if (state.Copy is { } copy) copy.IsEnabled = state.Lines.Count > 0;
        if (state.Previous is { } p) p.IsEnabled = state.Hits.Count > 0;
        if (state.Next is { } n) n.IsEnabled = state.Hits.Count > 0;
    }

    private static int IndexOf(IReadOnlyList<int> hits, int value)
    {
        for (var i = 0; i < hits.Count; i++) if (hits[i] == value) return i;
        return -1;
    }

    /// <summary>Done: back to the Activity page as it was (filters and loaded rows kept).</summary>
    private void BackToActivity()
    {
        CloseTranscript();
        _pageKind = "activity";
        ShowActivityPage();
        ShowActivityRows();
    }
}
