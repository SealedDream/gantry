using System.Diagnostics;
using Bastion.Shell.Interop;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;

namespace Bastion.Shell;

// Edit Locally and Follow Terminal Folder (core filepanel, #149), as on the Mac (EditLocally.swift, FilesView.swift):
// Edit Locally downloads the file into an owner-only folder under the data dir, opens it in its default app, and every
// save (polled once a second) queues an upload that replaces the remote file. Follow Terminal Folder opens the folder
// the SSH shell beside the docked panel announces with OSC 7.
public sealed partial class SftpPanel
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    private readonly ToggleButton _follow = new() { Visibility = Visibility.Collapsed };
    private EditLocalCopies? _copies;
    private DispatcherQueueTimer? _poll;
    private Func<string?>? _terminalFolder;

    /// <summary>Base for edit-locally copies (the library's data dir); set by the window.</summary>
    public string? EditDataDir { get; init; }

    /// <summary>The docked panel's terminal folder (OSC 7); set for SSH tabs, which shows Follow Terminal Folder.</summary>
    public Func<string?>? TerminalFolder
    {
        get => _terminalFolder;
        init { _terminalFolder = value; _follow.Visibility = value is null ? Visibility.Collapsed : Visibility.Visible; }
    }

    /// <summary>Test seam: the copies being watched are saved and uploaded; the app is not opened.</summary>
    internal bool OpenEditedCopies { get; set; } = true;

    public bool IsFollowing => _follow.IsChecked == true;

    private ToggleButton BuildFollowToggle()
    {
        _follow.Content = Ui.Icon("GlyphTerminal");
        AutomationProperties.SetName(_follow, "Follow terminal folder");
        ToolTipService.SetToolTip(_follow, "Follow terminal folder");
        _follow.Checked += (_, _) => { EnsurePolling(); FollowOnce(); };
        return _follow;
    }

    private MenuFlyout BuildListMenu()
    {
        var edit = new MenuFlyoutItem { Text = "Edit locally" };
        edit.Click += (_, _) => _ = EditSelectedLocally();
        var menu = new MenuFlyout { Items = { edit } };
        menu.Opening += (_, _) => edit.IsEnabled = Selected is { IsDir: false } && !_busy;
        return menu;
    }

    public void SetFollow(bool on) => _follow.IsChecked = on;

    /// <summary>Download the selected file, watch it and open it in its default app.</summary>
    public async Task EditSelectedLocally()
    {
        if (Selected is not { IsDir: false } e) { Report("Select a file to edit."); return; }
        var remote = SftpSession.Join(_dir, e.Name);
        if (EditDataDir is null) { Report("Edit locally is unavailable."); return; }
        _copies ??= new EditLocalCopies(EditDataDir);
        var copies = _copies;
        var local = await Run(() =>
        {
            var path = copies.LocalPath(remote);
            _sftp.Download(remote, path, overwrite: true);
            return path;
        }, $"Downloading {e.Name}…");
        if (local is null) return;
        try { copies.Watch(local, remote); }
        catch (BastionException ex) { Report($"Could not edit {e.Name}: {ex.Message}"); return; }
        EnsurePolling();
        Report($"Editing {e.Name} locally. Saves upload.");
        if (!OpenEditedCopies) return;
        try { Process.Start(new ProcessStartInfo(local) { UseShellExecute = true })?.Dispose(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { Report($"Could not open {e.Name}: {ex.Message}"); }
    }

    private void EnsurePolling()
    {
        if (_poll is not null || _closed) return;
        _poll = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _poll.Interval = PollInterval;
        _poll.Tick += (_, _) => Tick();
        _poll.Start();
    }

    private void StopPolling()
    {
        _poll?.Stop();
        _poll = null;
        _copies?.Dispose();
        _copies = null;
    }

    private void Tick()
    {
        if (_closed) { StopPolling(); return; }
        UploadSavedCopies();
        FollowOnce();
    }

    /// <summary>Queue an upload, always replacing, for each copy saved since the last poll.</summary>
    private void UploadSavedCopies()
    {
        if (_copies is null) return;
        IReadOnlyList<EditCopy> saved;
        try { saved = _copies.Poll(); }
        catch (BastionException ex) { Report(ex.Message); return; }
        if (saved.Count == 0) return;
        foreach (var c in saved)
        {
            ulong size;
            try { size = (ulong)new FileInfo(c.Local).Length; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Report($"{Path.GetFileName(c.Local)}: {ex.Message}"); continue; }
            try { _queue.Add(true, c.Local, c.Remote, size, "replace"); }
            catch (BastionException ex) { Report(ex.Message); }
        }
        RefreshQueue();
        _ = Pump();
    }

    /// <summary>While following, open the terminal's folder whenever it differs from the shown one.</summary>
    private void FollowOnce()
    {
        if (!IsFollowing || _terminalFolder is null || _busy) return;
        string? dir;
        try { dir = _terminalFolder(); }
        catch (Exception ex) when (ex is BastionException or ObjectDisposedException) { return; }
        if (!string.IsNullOrEmpty(dir) && dir != _dir) _ = Navigate(dir);
    }
}
