using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;

namespace Bastion.Shell;

/// <summary>One entry of a local folder in the Files panel's local pane.</summary>
public sealed record LocalEntry(string Path, string Name, bool IsDir, ulong Size);

/// <summary>
/// The local pane of the Files panel: a folder on this PC (Downloads at first). Downloads land in it; files picked
/// here (Upload selected, Enter, or a drag onto the remote list) are queued for upload into the remote folder, and
/// remote files dragged onto it are queued for download.
/// </summary>
public sealed partial class SftpPanel
{
    private const string LocalDragKey = "bastion-local-path";
    private const string RemoteDragKey = "bastion-remote-path";
    private readonly TextBox _localPath = new() { MinWidth = 0 };
    private readonly ListView _local = new() { SelectionMode = ListViewSelectionMode.Single, CanDragItems = true, AllowDrop = true };
    private IReadOnlyList<LocalEntry> _localEntries = [];
    private string _localDir = DownloadsDir;

    public string LocalDirectory => _localDir;

    private static string LocalParent(string dir) => Path.GetDirectoryName(dir.TrimEnd('\\')) ?? dir;

    private UIElement BuildLocal()
    {
        var bar = new Grid { ColumnSpacing = 4 };
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var up = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphUp") };
        AutomationProperties.SetName(up, "Local up one folder");
        ToolTipService.SetToolTip(up, "Up one folder");
        up.Click += (_, _) => _ = NavigateLocal(LocalParent(_localDir));
        AutomationProperties.SetName(_localPath, "Local folder");
        _localPath.KeyDown += (_, e) => { if (e.Key == VirtualKey.Enter) { e.Handled = true; _ = NavigateLocal(_localPath.Text.Trim()); } };
        var send = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.IconLabel(Ui.Icon("GlyphUpload"), "Upload selected") };
        AutomationProperties.SetName(send, "Upload selected");
        send.Click += (_, _) => _ = UploadSelectedLocal();
        bar.Children.Add(up);
        Grid.SetColumn(_localPath, 1);
        bar.Children.Add(_localPath);
        Grid.SetColumn(send, 2);
        bar.Children.Add(send);

        AutomationProperties.SetName(_local, "Local files");
        _local.DoubleTapped += (_, _) => _ = OpenLocalSelected();
        _local.KeyDown += (_, e) =>
        {
            if (e.Key == VirtualKey.Enter) { e.Handled = true; _ = OpenLocalSelected(); }
            else if (e.Key == VirtualKey.Back) { e.Handled = true; _ = NavigateLocal(LocalParent(_localDir)); }
        };
        _local.DragItemsStarting += (_, e) =>
        {
            if (e.Items.FirstOrDefault() is FrameworkElement { Tag: LocalEntry { IsDir: false } entry })
            {
                e.Data.Properties[LocalDragKey] = entry.Path;
                e.Data.RequestedOperation = DataPackageOperation.Copy;
            }
            else e.Cancel = true;
        };
        _local.DragOver += (_, e) =>
        {
            if (!e.DataView.Properties.ContainsKey(RemoteDragKey)) return;
            e.AcceptedOperation = DataPackageOperation.Copy;
            e.DragUIOverride.Caption = $"Download to {_localDir}";
        };
        _local.Drop += (_, e) =>
        {
            if (e.DataView.Properties.TryGetValue(RemoteDragKey, out var p) && p is string remote) _ = QueueDownload(remote);
        };

        _list.CanDragItems = true;
        _list.DragItemsStarting += (_, e) =>
        {
            if (e.Items.FirstOrDefault() is FrameworkElement { Tag: RemoteEntry { IsDir: false } entry })
            {
                e.Data.Properties[RemoteDragKey] = SftpSession.Join(_dir, entry.Name);
                e.Data.RequestedOperation = DataPackageOperation.Copy;
            }
            else e.Cancel = true;
        };

        var grid = new Grid { RowSpacing = 8 };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.Children.Add(Ui.Text("This PC", "BodyStrongTextStyle"));
        Grid.SetRow(bar, 1);
        grid.Children.Add(bar);
        Grid.SetRow(_local, 2);
        grid.Children.Add(_local);
        return grid;
    }

    private LocalEntry? LocalSelected => _local.SelectedIndex >= 0 && _local.SelectedIndex < _localEntries.Count ? _localEntries[_local.SelectedIndex] : null;

    /// <summary>Show a local folder. An unreadable one is reported and the pane stays where it was.</summary>
    public async Task NavigateLocal(string dir)
    {
        IReadOnlyList<LocalEntry> entries;
        try { entries = await Task.Run(() => ListLocal(dir)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            _localPath.Text = _localDir;
            Report(ex.Message);
            return;
        }
        var keep = LocalSelected?.Name;
        _localDir = dir;
        _localPath.Text = dir;
        _localEntries = entries;
        _local.Items.Clear();
        foreach (var e in entries) _local.Items.Add(LocalRow(e));
        if (keep is not null) SelectLocal(keep);
    }

    private Task RefreshLocal() => NavigateLocal(_localDir);

    private static IReadOnlyList<LocalEntry> ListLocal(string dir)
    {
        var info = new DirectoryInfo(dir);
        if (!info.Exists) throw new IOException($"{dir} is not a folder.");
        var dirs = info.EnumerateDirectories().Where(d => !d.Attributes.HasFlag(FileAttributes.Hidden))
            .Select(d => new LocalEntry(d.FullName, d.Name, true, 0));
        var files = info.EnumerateFiles().Where(f => !f.Attributes.HasFlag(FileAttributes.Hidden))
            .Select(f => new LocalEntry(f.FullName, f.Name, false, (ulong)f.Length));
        return dirs.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .Concat(files.OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase)).ToList();
    }

    private static UIElement LocalRow(LocalEntry e)
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

    private Task OpenLocalSelected() => LocalSelected switch
    {
        { IsDir: true } e => NavigateLocal(e.Path),
        { } => UploadSelectedLocal(),
        null => Task.CompletedTask,
    };

    /// <summary>Queue the selected local file for upload into the current remote folder.</summary>
    public Task UploadSelectedLocal()
    {
        if (LocalSelected is not { IsDir: false } e) { Report("Select a local file to upload."); return Task.CompletedTask; }
        return UploadFiles([e.Path]);
    }

    /// <summary>Queue a remote file for download into the local folder and run the queue.</summary>
    public async Task QueueDownload(string remote)
    {
        var size = _entries.FirstOrDefault(x => SftpSession.Join(_dir, x.Name) == remote)?.Size ?? 0;
        if (Enqueue(false, remote, Path.Combine(_localDir, SftpLeaf(remote)), size) is null) return;
        RefreshQueue();
        await Pump();
    }

    /// <summary>Snapshot and test mode: select a local entry by name.</summary>
    public void SelectLocal(string name)
    {
        var i = _localEntries.ToList().FindIndex(x => x.Name == name);
        if (i >= 0) { _local.SelectedIndex = i; _local.ScrollIntoView(_local.Items[i]); }
    }
}
