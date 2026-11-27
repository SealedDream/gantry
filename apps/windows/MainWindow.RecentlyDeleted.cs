using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace Bastion.Shell;

// Recently Deleted (B10): Delete moves folders and connections here; Restore puts them back until the keep time
// (`library.deleted-retention-days`) passes. Inline secrets stay in the vault until then: every prune goes through
// bastion_credentials_prune_inline, which keeps the tree plus Recently Deleted. Ctrl+Z in the tree restores the last delete.
public sealed partial class MainWindow
{
    internal const string RetentionSetting = "library.deleted-retention-days";
    internal const string RestoreDeletedCapability = "restore-deleted";
    private DispatcherTimer? _purgeTimer;
    /// <summary>The last item deleted to Recently Deleted, for Ctrl+Z in the tree.</summary>
    private string? _lastTrashed;
    /// <summary>UI tests: seconds added to the clock, so a suite can pass the keep time.</summary>
    internal static long ClockOffsetForTest;

    private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ClockOffsetForTest;

    private uint RetentionDays()
    {
        try { return uint.TryParse(Settings.Get(RetentionSetting), out var d) ? d : 30; }
        catch (BastionException) { return 30; }
    }

    /// <summary>Once, from the constructor: the purge at start and every 24 hours, and Ctrl+Z in the tree.</summary>
    private void HookRecentlyDeleted()
    {
        // The first purge runs after the first frame (StartDeferredServices, WIN-STARTUP).
        _purgeTimer = new DispatcherTimer { Interval = TimeSpan.FromHours(24) };
        _purgeTimer.Tick += (_, _) => PurgeDeleted();
        _purgeTimer.Start();
        var undo = new KeyboardAccelerator { Key = VirtualKey.Z, Modifiers = VirtualKeyModifiers.Control, ScopeOwner = Tree };
        undo.Invoked += (sender, e) => { e.Handled = true; _ = UndoDeleteAsync(); };
        Tree.KeyboardAccelerators.Add(undo);
    }

    /// <summary>Delete inline secrets of connections in neither the tree nor Recently Deleted (only while the vault is open).</summary>
    private void PruneInlineSecrets()
    {
        if (_credentials is not { } vault) return;
        try { vault.PruneInline(_library); }
        catch (BastionException ex) { Announce("Could not tidy saved passwords: " + ex.Message); }
    }

    /// <summary>
    /// Forget the connection history of connections dropped for good, so connection-history.json holds live
    /// connections only (grow-only stores audit, 2026-11-16). History is informational: a failure is not announced.
    /// </summary>
    private void ForgetHistory(IReadOnlyList<string> goneConnectionIds)
    {
        if (_demo) return;
        foreach (var id in goneConnectionIds)
        {
            try { ConnectionHistory.Forget(HistoryDir, id); }
            catch (BastionException ex) { AppLog.Warn("connection history not pruned: " + ex.Message); return; }
        }
    }

    /// <summary>Drop what is past the keep time; prune and save only when something was dropped.</summary>
    internal void PurgeDeleted(uint? days = null)
    {
        try
        {
            if (_library.DeletedItems().Count == 0) return;
            var purged = _library.PurgeDeleted(Now(), days ?? RetentionDays());
            if (purged.Count == 0) return;
            ForgetHistory(purged);
            SaveLibrary();
            PruneInlineSecrets();
            if (_pageKind == "deleted") ShowRecentlyDeletedPage();
        }
        catch (BastionException ex) { Announce("Could not clear old deleted items: " + ex.Message); }
    }

    /// <summary>Delete one tree item the way the user does: to Recently Deleted, or for good when the keep time is Off.</summary>
    private void TrashItem(string id)
    {
        var days = RetentionDays();
        var gone = _library.Trash(id, Now(), days);
        _lastTrashed = days > 0 ? id : null;
        if (gone.Count == 0) return;
        PruneInlineSecrets();
        ForgetHistory(gone);
    }

    private async Task UndoDeleteAsync()
    {
        if (_lastTrashed is not { } id) return;
        _lastTrashed = null;
        // Restored or purged since (the Recently Deleted page): nothing to undo.
        try { if (_library.DeletedItems().All(d => d.Id != id)) return; }
        catch (BastionException) { return; }
        await RestoreDeletedAsync(id);
    }

    private void RecentlyDeleted_Click(object sender, RoutedEventArgs e) => OpenRecentlyDeleted();

    internal void OpenRecentlyDeleted()
    {
        _pageKind = "deleted";
        ShowRecentlyDeletedPage();
    }

    private void ShowRecentlyDeletedPage()
    {
        if (_pageKind != "deleted") return;
        var days = RetentionDays();
        var content = new StackPanel { Spacing = Ui.Double("Space8") };
        var keep = Ui.Text(days == 0 ? "Keep: off" : $"Keep: {days} days", "CaptionSecondaryTextStyle");
        ToolTipService.SetToolTip(keep, "Items are deleted for good after this time. Change it in Settings › General.");
        AutomationProperties.SetName(keep, "Recently Deleted keep time");
        content.Children.Add(keep);
        IReadOnlyList<DeletedItemDto> items = [];
        try { items = _library.DeletedItems(); }
        catch (BastionException ex) { content.Children.Add(CodedErrorText("APP", ex.Message)); }
        if (items.Count == 0) content.Children.Add(Ui.Text("Nothing deleted.", "BodySecondaryTextStyle"));
        foreach (var d in items.OrderByDescending(i => i.DeletedAt)) content.Children.Add(DeletedRow(d));
        var empty = new Button { Content = "Empty…", Style = Ui.Style("SubtleButtonStyle"), IsEnabled = items.Count > 0 };
        ToolTipService.SetToolTip(empty, "Delete everything here for good");
        AutomationProperties.SetName(empty, "Empty Recently Deleted");
        empty.Click += (_, _) => _ = EmptyDeletedAsync();
        ShowPage(null, "Recently Deleted", content, empty);
    }

    private Grid DeletedRow(DeletedItemDto d)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space8"), MinHeight = Ui.Double("ControlHeight") };
        foreach (var w in new[] { new GridLength(1, GridUnitType.Star), GridLength.Auto, GridLength.Auto })
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        var when = DateTimeOffset.FromUnixTimeSeconds(d.DeletedAt).ToLocalTime().ToString("g");
        var detail = Ui.Text($"{d.ParentName ?? "Library"} · {when}", "CaptionSecondaryTextStyle");
        detail.TextTrimming = TextTrimming.CharacterEllipsis;
        AutomationProperties.SetName(detail, $"{d.Name} from {d.ParentName ?? "the top of the library"}, deleted {when}");
        var name = Ui.Text(d.Name, "BodyTextStyle");
        name.TextTrimming = TextTrimming.CharacterEllipsis;
        if (d.Kind == "folder") ToolTipService.SetToolTip(name, Plural(d.ConnectionCount, "connection"));
        row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { name, detail } });
        var restore = new Button { Content = "Restore", Style = Ui.Style("AccentButtonStyle") };
        ToolTipService.SetToolTip(restore, "Put back in its folder, or at the top if the folder is gone");
        AddRowButton(row, 1, restore, "Restore " + d.Name, () => _ = RestoreDeletedAsync(d.Id));
        var remove = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphDelete", "IconSize") };
        ToolTipService.SetToolTip(remove, "Delete permanently");
        AddRowButton(row, 2, remove, "Delete permanently " + d.Name, () => _ = DeletePermanentlyAsync(d));
        return row;
    }

    internal async Task RestoreDeletedAsync(string id)
    {
        RestoreDto? result = null;
        await Mutate(() =>
        {
            result = _library.Restore(id);
            return id;
        }, "Could not restore");
        if (result?.AtRootBecauseParentMissing == true) Announce("Its folder is gone: restored to the top of the library.");
        if (_pageKind == "deleted") ShowRecentlyDeletedPage();
    }

    private async Task DeletePermanentlyAsync(DeletedItemDto d)
    {
        var body = Ui.Text($"“{d.Name}” cannot be restored afterwards.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        if (!await ShowModal("Delete permanently?", body, primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        IReadOnlyList<string> gone = [];
        await Mutate(() => { gone = _library.DeletePermanently(d.Id); return null; }, "Could not delete " + d.Name);
        ForgetHistory(gone);
        PruneInlineSecrets();
        ShowRecentlyDeletedPage();
    }

    private async Task EmptyDeletedAsync()
    {
        var count = _library.DeletedItems().Count;
        var body = Ui.Text($"{Plural(count, "item")} cannot be restored afterwards.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        if (!await ShowModal("Empty Recently Deleted?", body, primary: "Empty", cancel: "Cancel", focusCancel: true)) return;
        IReadOnlyList<string> gone = [];
        await Mutate(() => { gone = _library.EmptyDeleted(); return null; }, "Could not empty Recently Deleted");
        ForgetHistory(gone);
        PruneInlineSecrets();
        ShowRecentlyDeletedPage();
    }

    private async Task SetRetentionOffAsync()
    {
        try
        {
            if (await ConfirmRetentionOffAsync()) Settings.Set(RetentionSetting, "0");
        }
        catch (BastionException ex) { await ShowModal("Setting not changed", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        if (SettingsOpen) ShowSettingsPage();
    }

    /// <summary>Settings: switching the keep time to Off asks before what is kept is deleted; false keeps the old value.</summary>
    private async Task<bool> ConfirmRetentionOffAsync()
    {
        var count = _library.DeletedItems().Count;
        if (count == 0) return true;
        var body = Ui.Text($"{Plural(count, "kept item")} will be deleted for good.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        if (!await ShowModal("Turn off Recently Deleted?", body, primary: "Delete", cancel: "Cancel", focusCancel: true)) return false;
        PurgeDeleted(0);
        return true;
    }
}
