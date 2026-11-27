using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// The Files panel of an SSH tab: a two-pane file transfer panel on the tab's own connection (no new login). The
/// remote pane lists a folder, opens folders, creates folders and renames and deletes (after an inline confirmation;
/// folders with everything in them). The local pane (SftpPanel.Local.cs) is a folder on this PC. Uploads (picked,
/// dropped from Explorer, dragged from the local pane) and downloads (into the local folder) go through the core
/// transfer queue (SftpPanel.Queue.cs) with the "If the file exists" rule: Ask, Replace, Skip, Replace if newer or
/// Keep both. Every SFTP call runs off the UI thread, one at a time; the controls are disabled meanwhile.
/// </summary>
public sealed partial class SftpPanel : UserControl, IDisposable
{
    private readonly SftpSession _sftp;
    private readonly Func<Task<string?>> _pickUpload;
    private readonly TextBox _path = new() { MinWidth = 0 };
    private readonly ListView _list = new() { SelectionMode = ListViewSelectionMode.Single, IsItemClickEnabled = false };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly Grid _nameRow = new() { Visibility = Visibility.Collapsed, ColumnSpacing = 8 };
    private readonly TextBox _name = new();
    private readonly Button _nameOk = new() { Content = "OK" };
    private readonly Grid _confirmRow = new() { Visibility = Visibility.Collapsed, ColumnSpacing = 8 };
    private readonly TextBlock _confirmText = new() { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private readonly ProgressBar _progress = new() { Visibility = Visibility.Collapsed, Minimum = 0 };
    private readonly List<Control> _actions = new();
    private RemoteEntry? _pendingDelete;
    private Func<string, Task>? _nameAction;
    private IReadOnlyList<RemoteEntry> _entries = [];
    private string _dir = "/";
    private bool _busy;

    /// <summary>Where downloads go: the user's Downloads folder.</summary>
    public static string DownloadsDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    public string CurrentDirectory => _dir;

    public SftpPanel(SftpSession sftp, Func<Task<string?>> pickUpload, string protocolLabel = "SFTP")
    {
        _sftp = sftp;
        _pickUpload = pickUpload;
        AutomationProperties.SetName(this, "Files");
        Style? textStyle = Ui.Style("CaptionSecondaryTextStyle");
        _status.Style = textStyle;
        AutomationProperties.SetLiveSetting(_status, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);

        var root = new Grid { Padding = new Thickness(12), RowSpacing = 8 };
        // Theme brushes resolve per theme: repaint when the theme changes (as the tab strip does).
        void Paint() => root.Background = Ui.Brush(this, "LayerBackgroundBrush");
        Loaded += (_, _) => Paint();
        ActualThemeChanged += (_, _) => Paint();
        // The remote list (row 3) and the local pane (row 4) share the free height but never drop below a usable
        // floor (a few entries; the local pane also holds its heading and folder bar). When the window is shorter
        // than that, the panel scrolls (see the ScrollViewer below) instead of collapsing them.
        for (var i = 0; i < 7; i++)
            root.RowDefinitions.Add(i switch
            {
                3 => new RowDefinition { Height = new GridLength(1, GridUnitType.Star), MinHeight = RemoteListMinHeight },
                4 => new RowDefinition { Height = new GridLength(1, GridUnitType.Star), MinHeight = LocalPaneMinHeight },
                _ => new RowDefinition { Height = GridLength.Auto },
            });

        root.Children.Add(Ui.Text($"Files ({protocolLabel})", "BodyStrongTextStyle"));

        var bar = new Grid { ColumnSpacing = 4 };
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var up = IconButton("GlyphUp", "Up one folder", () => Navigate(SftpSession.Parent(_dir)));
        var refresh = IconButton("GlyphRefresh", "Refresh", () => Navigate(_dir));
        AutomationProperties.SetName(_path, "Remote folder");
        _path.KeyDown += (_, e) => { if (e.Key == VirtualKey.Enter) { e.Handled = true; _ = Navigate(_path.Text.Trim()); } };
        bar.Children.Add(up);
        Grid.SetColumn(_path, 1);
        bar.Children.Add(_path);
        Grid.SetColumn(refresh, 2);
        bar.Children.Add(refresh);
        var follow = BuildFollowToggle();
        Grid.SetColumn(follow, 3);
        bar.Children.Add(follow);
        Grid.SetRow(bar, 1);
        root.Children.Add(bar);
        _actions.Add(_path);

        var tools = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 4 };
        tools.Children.Add(IconButton("GlyphDownload", "Download", DownloadSelected));
        tools.Children.Add(IconButton("GlyphUpload", "Upload", Upload));
        tools.Children.Add(IconButton(null, "New folder", () => AskName("New folder name", "", MakeFolder)));
        var edit = IconButton("GlyphDocument", "Edit file", EditSelected);
        ToolTipService.SetToolTip(edit, "Edit the selected file on the server");
        tools.Children.Add(edit);
        tools.Children.Add(BuildMoreButton());
        BuildConfirmRow();
        var top = new StackPanel { Spacing = 8, Children = { tools, _nameRow, _confirmRow } };
        Grid.SetRow(top, 2);
        root.Children.Add(top);

        _nameRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        _nameRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _nameRow.Children.Add(_name);
        Grid.SetColumn(_nameOk, 1);
        _nameRow.Children.Add(_nameOk);
        _nameOk.Click += (_, _) => _ = SubmitName();
        _name.KeyDown += (_, e) =>
        {
            if (e.Key == VirtualKey.Enter) { e.Handled = true; _ = SubmitName(); }
            else if (e.Key == VirtualKey.Escape) { e.Handled = true; _nameRow.Visibility = Visibility.Collapsed; _list.Focus(FocusState.Keyboard); }
        };

        AutomationProperties.SetName(_list, "Remote files");
        _list.ContextFlyout = BuildListMenu();
        _list.DoubleTapped += (_, _) => _ = OpenSelected();
        _list.KeyDown += (_, e) =>
        {
            if (e.Key == VirtualKey.Enter) { e.Handled = true; _ = OpenSelected(); }
            else if (e.Key == VirtualKey.Back) { e.Handled = true; _ = Navigate(SftpSession.Parent(_dir)); }
            else if (e.Key == VirtualKey.Delete) { e.Handled = true; _ = AskDelete(); }
        };
        _list.AllowDrop = true;
        _list.DragOver += OnDragOver;
        _list.Drop += OnDrop;
        Grid.SetRow(_list, 3);
        root.Children.Add(_list);
        var local = BuildLocal();
        Grid.SetRow((FrameworkElement)local, 4);
        root.Children.Add(local);
        var queue = BuildQueue();
        Grid.SetRow((FrameworkElement)queue, 5);
        root.Children.Add(queue);
        var foot = new StackPanel { Spacing = 4, Children = { _progress, _status } };
        AutomationProperties.SetName(_progress, "Transfer progress");
        Grid.SetRow(foot, 6);
        root.Children.Add(foot);
        var editor = BuildEditor();
        Grid.SetRowSpan(editor, 7);
        root.Children.Add(editor);
        // Fill the viewport when there is room (star rows share it); scroll when the floors above do not fit.
        var scroller = new ScrollViewer { Content = root, HorizontalScrollMode = ScrollMode.Disabled, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        scroller.SizeChanged += (_, e) => root.MinHeight = e.NewSize.Height;
        Content = scroller;
    }

    private const double RemoteListMinHeight = 96;
    private const double LocalPaneMinHeight = 150;

    private RemoteEntry? Selected => _list.SelectedIndex >= 0 && _list.SelectedIndex < _entries.Count ? _entries[_list.SelectedIndex] : null;

    private Button IconButton(string? glyph, string name, Func<Task> click)
    {
        var b = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = glyph is null ? new AppIcon { Kind = "FolderAdd" } : Ui.Icon(glyph) };
        AutomationProperties.SetName(b, name);
        ToolTipService.SetToolTip(b, name);
        b.Click += (_, _) => _ = click();
        _actions.Add(b);
        return b;
    }

    /// <summary>The "…" menu for the less frequent actions: Rename and Delete.</summary>
    private Button BuildMoreButton()
    {
        var rename = new MenuFlyoutItem { Text = "Rename…" };
        rename.Click += (_, _) => _ = RenameSelected();
        var delete = new MenuFlyoutItem { Text = "Delete…" };
        delete.Click += (_, _) => _ = AskDelete();
        var menu = new MenuFlyout { Items = { rename, delete } };
        menu.Opening += (_, _) => rename.IsEnabled = delete.IsEnabled = Selected is not null && !_busy;
        var b = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphMore"), Flyout = menu };
        AutomationProperties.SetName(b, "More");
        ToolTipService.SetToolTip(b, "More: Rename, Delete");
        _actions.Add(b);
        return b;
    }

    private Task RenameSelected()
    {
        if (Selected is { } e) return AskName($"Rename {e.Name} to", e.Name, n => RenameTo(e, n));
        Report("Select an entry to rename.");
        return Task.CompletedTask;
    }

    /// <summary>Show the remote home folder.</summary>
    public async Task StartAsync()
    {
        var home = await Run(() => _sftp.Home());
        await NavigateLocal(_localDir);
        await Navigate(home ?? "/");
    }

    public async Task Navigate(string path)
    {
        if (path.Length == 0) path = "/";
        var entries = await Run(() => _sftp.List(path));
        if (entries is null) { _path.Text = _dir; return; }
        _dir = path;
        _path.Text = path;
        _entries = entries.OrderByDescending(e => e.IsDir).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
        _list.Items.Clear();
        foreach (var e in _entries) _list.Items.Add(Row(e));
        if (_entries.Count > 0) _list.SelectedIndex = 0;
        Report(_entries.Count switch { 0 => "Empty folder.", 1 => "1 item", var n => $"{n} items" });
    }

    private static UIElement Row(RemoteEntry e)
    {
        var g = new Grid { ColumnSpacing = 8, Tag = e };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.Children.Add(e.IsDir ? new AppIcon { Kind = "Folder", VerticalAlignment = VerticalAlignment.Center } : Ui.Icon("GlyphDocument", "SmallIconSize"));
        var name = new TextBlock { Text = e.Name, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(name, 1);
        g.Children.Add(name);
        var detail = Ui.Text(e.IsDir ? "" : Size(e.Size), "CaptionSecondaryTextStyle");
        detail.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(detail, 2);
        g.Children.Add(detail);
        AutomationProperties.SetName(g, e.IsDir ? $"{e.Name}, folder" : $"{e.Name}, {Size(e.Size)}");
        return g;
    }

    internal static string Size(ulong n) => n switch
    {
        < 1024 => $"{n} B",
        < 1024 * 1024 => $"{n / 1024.0:0.#} KB",
        < 1024UL * 1024 * 1024 => $"{n / (1024.0 * 1024):0.#} MB",
        _ => $"{n / (1024.0 * 1024 * 1024):0.#} GB",
    };

    private Task OpenSelected() => Selected switch
    {
        { IsDir: true } e => Navigate(SftpSession.Join(_dir, e.Name)),
        { } => DownloadSelected(),
        null => Task.CompletedTask,
    };

    /// <summary>Queue the selected remote file for download into the local pane's folder.</summary>
    public Task DownloadSelected()
    {
        if (Selected is not { IsDir: false } e) { Report("Select a file to download."); return Task.CompletedTask; }
        return QueueDownload(SftpSession.Join(_dir, e.Name));
    }

    private async Task Upload()
    {
        if (await _pickUpload() is not { } local) return;
        await UploadFile(local);
    }

    /// <summary>Upload a local file into the current folder under its own name, through the queue.</summary>
    public Task UploadFile(string local) => UploadFiles([local]);

    private Task AskName(string prompt, string initial, Func<string, Task> action)
    {
        _nameAction = action;
        _name.PlaceholderText = prompt;
        AutomationProperties.SetName(_name, prompt);
        _name.Text = initial;
        _nameRow.Visibility = Visibility.Visible;
        _name.Focus(FocusState.Programmatic);
        _name.SelectAll();
        return Task.CompletedTask;
    }

    private async Task SubmitName()
    {
        var name = _name.Text.Trim();
        if (name.Length == 0 || name.Contains('/') || name is "." or "..") { Report("Enter a name without '/'."); return; }
        _nameRow.Visibility = Visibility.Collapsed;
        if (_nameAction is { } a) await a(name);
    }

    public Task NewFolder(string name) => MakeFolder(name);

    private async Task MakeFolder(string name)
    {
        if (await Run(() => { _sftp.Mkdir(SftpSession.Join(_dir, name)); return true; }) is not true) return;
        await Navigate(_dir);
        Select(name);
        Report($"Created folder {name}");
    }

    private async Task RenameTo(RemoteEntry e, string name)
    {
        if (name == e.Name) return;
        if (await Run(() => { _sftp.Rename(SftpSession.Join(_dir, e.Name), SftpSession.Join(_dir, name)); return true; }) is not true) return;
        await Navigate(_dir);
        Select(name);
        Report($"Renamed {e.Name} to {name}");
    }

    private void BuildConfirmRow()
    {
        _confirmRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        _confirmRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _confirmRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var yes = new Button { Content = "Delete", Style = Ui.Style("AccentButtonStyle") };
        var no = new Button { Content = "Cancel" };
        AutomationProperties.SetName(yes, "Confirm delete");
        yes.Click += (_, _) => _ = ConfirmDelete();
        no.Click += (_, _) => CancelDelete();
        _confirmRow.Children.Add(_confirmText);
        Grid.SetColumn(yes, 1);
        _confirmRow.Children.Add(yes);
        Grid.SetColumn(no, 2);
        _confirmRow.Children.Add(no);
    }

    /// <summary>Ask, inline, before deleting the selected entry.</summary>
    public Task AskDelete()
    {
        if (Selected is not { } e) { Report("Select an entry to delete."); return Task.CompletedTask; }
        _pendingDelete = e;
        _confirmText.Text = e.IsDir ? $"Delete folder {e.Name} and everything in it?" : $"Delete {e.Name}?";
        _nameRow.Visibility = Visibility.Collapsed;
        _confirmRow.Visibility = Visibility.Visible;
        return Task.CompletedTask;
    }

    private void CancelDelete()
    {
        _pendingDelete = null;
        _confirmRow.Visibility = Visibility.Collapsed;
        _list.Focus(FocusState.Keyboard);
    }

    /// <summary>Delete the entry the confirmation row names.</summary>
    public async Task ConfirmDelete()
    {
        if (_pendingDelete is not { } e) return;
        _confirmRow.Visibility = Visibility.Collapsed;
        _pendingDelete = null;
        var n = await Run<long?>(() => _sftp.Remove(SftpSession.Join(_dir, e.Name), e.IsDir));
        if (n is null) return;
        var index = _list.SelectedIndex;
        await Navigate(_dir);
        if (_entries.Count > 0) _list.SelectedIndex = Math.Min(index, _entries.Count - 1);
        Report(e.IsDir ? $"Deleted folder {e.Name} ({n} items)" : $"Deleted {e.Name}");
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems) && !e.DataView.Properties.ContainsKey(LocalDragKey)) return;
        e.AcceptedOperation = DataPackageOperation.Copy;
        e.DragUIOverride.Caption = $"Upload to {_dir}";
    }

    private async void OnDrop(object sender, DragEventArgs e)
    {
        if (e.DataView.Properties.TryGetValue(LocalDragKey, out var p) && p is string path) { await UploadFiles([path]); return; }
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        var deferral = e.GetDeferral();
        IReadOnlyList<IStorageItem> items;
        try { items = await e.DataView.GetStorageItemsAsync(); }
        finally { deferral.Complete(); }
        var files = items.OfType<StorageFile>().Select(f => f.Path).Where(p => !string.IsNullOrEmpty(p)).ToList();
        var folders = items.OfType<StorageFolder>().Select(f => f.Path).Where(p => !string.IsNullOrEmpty(p)).ToList();
        await UploadItems(files, folders);
    }

    /// <summary>
    /// Upload dropped files and folders into the current folder. A folder is copied with everything inside: its
    /// subfolders are made on the server first (an existing folder is reused), then every file is queued. Links and
    /// junctions are not followed, so a loop or a path outside the dropped folder is never uploaded.
    /// </summary>
    public async Task UploadItems(IReadOnlyList<string> files, IReadOnlyList<string> folders)
    {
        if (folders.Count == 0) { await UploadFiles(files); return; }
        var pairs = files.Select(f => (Local: f, Remote: SftpSession.Join(_dir, Path.GetFileName(f)))).ToList();
        var dir = _dir;
        string? failure = null;
        var made = await Run(() =>
        {
            var found = new List<(string Local, string Remote)>();
            try { foreach (var root in folders) found.AddRange(MirrorFolder(root, SftpSession.Join(dir, Path.GetFileName(root.TrimEnd('\\'))))); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { failure = ex.Message; return null; }
            return found;
        }, "Making folders…");
        if (made is null) { if (failure is not null) Report(failure); await Navigate(_dir); return; }
        _remoteChanged = true;
        pairs.AddRange(made);
        await UploadPairs(pairs);
    }

    /// <summary>Off the UI thread: make <paramref name="remote"/> and its subfolders; return the files to copy.</summary>
    private List<(string Local, string Remote)> MirrorFolder(string local, string remote)
    {
        EnsureRemoteDir(remote);
        var files = new List<(string, string)>();
        foreach (var entry in new DirectoryInfo(local).EnumerateFileSystemInfos())
        {
            if (entry.Attributes.HasFlag(System.IO.FileAttributes.ReparsePoint)) continue;
            var target = SftpSession.Join(remote, entry.Name);
            if (entry is DirectoryInfo) files.AddRange(MirrorFolder(entry.FullName, target));
            else files.Add((entry.FullName, target));
        }
        return files;
    }

    private void EnsureRemoteDir(string remote)
    {
        var hit = _sftp.List(SftpSession.Parent(remote)).FirstOrDefault(e => e.Name == SftpLeaf(remote));
        if (hit is null) _sftp.Mkdir(remote);
        else if (!hit.IsDir) throw new IOException($"{SftpLeaf(remote)} already exists on the server and is not a folder.");
    }

    /// <summary>Queue local files for upload into the current folder and run the queue (one at a time).</summary>
    public Task UploadFiles(IReadOnlyList<string> locals) =>
        UploadPairs(locals.Select(l => (Local: l, Remote: SftpSession.Join(_dir, Path.GetFileName(l)))).ToList());

    private async Task UploadPairs(IReadOnlyList<(string Local, string Remote)> pairs)
    {
        if (pairs.Count == 0) { Report("Nothing to upload."); if (_remoteChanged) { _remoteChanged = false; await Navigate(_dir); } return; }
        var ids = new List<ulong>();
        foreach (var (local, remote) in pairs)
        {
            ulong size;
            try { size = (ulong)new FileInfo(local).Length; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Report($"{Path.GetFileName(local)}: {ex.Message}"); continue; }
            if (Enqueue(true, local, remote, size) is { } id) ids.Add(id);
        }
        RefreshQueue();
        await Pump();
        var mine = _jobList.Where(j => ids.Contains(j.Id)).ToList();
        var done = mine.Where(j => j.State == "done").ToList();
        if (done.LastOrDefault() is { } last && SftpSession.Parent(last.Target) == _dir) Select(SftpLeaf(last.Target));
        if (mine.Count <= 1) return;
        var rest = mine.Count - done.Count;
        Report($"Uploaded {done.Count} files" + (rest > 0 ? $", {rest} not uploaded" : ""));
    }

    public void Select(string name)
    {
        var i = _entries.ToList().FindIndex(x => x.Name == name);
        if (i >= 0) { _list.SelectedIndex = i; _list.ScrollIntoView(_list.Items[i]); }
    }

    private void Report(string text) => _status.Text = text;

    /// <summary>Snapshot mode: the status line.</summary>
    internal string StatusForSnapshot => _status.Text;

    /// <summary>Run one SFTP call off the UI thread with the controls disabled. Errors are shown, not thrown; null means it failed.</summary>
    private async Task<T?> Run<T>(Func<T> call, string working = "Working…")
    {
        if (_busy) return default;
        _busy = true;
        foreach (var c in _actions) c.IsEnabled = false;
        _status.Text = working;
        try { return await Task.Run(call); }
        catch (Exception ex) when (ex is BastionException or ObjectDisposedException)
        {
            _status.Text = ex.Message;
            return default;
        }
        finally
        {
            foreach (var c in _actions) c.IsEnabled = true;
            _busy = false;
        }
    }

    /// <summary>Closed by the tab or the Files toggle; a job still copying frees the queue when it returns (Codex W04).</summary>
    private bool _closed;

    /// <summary>Returns at once, on the UI thread, even during a large or stalled transfer (Codex W04).</summary>
    public void Dispose()
    {
        if (_closed) return;
        _closed = true;
        StopPolling();
        _sftp.Dispose();
        if (!_busy) _queue.Dispose();
    }
}
