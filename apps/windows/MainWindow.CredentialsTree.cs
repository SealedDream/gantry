using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

// The Credentials section of the navigation tree (core credtree, C ABI 38): one vault, user folders, stable ids. A host
// or library folder points at ONE credential or inherits it from above. Rows are not library items (IsGroup), so the
// library's commands, drag-and-drop and Delete never act on them; their own menu is built here.
public sealed partial class MainWindow
{
    /// <summary>
    /// The Credentials section for the pane pinned under the library (CredentialsPane, as on Native Mac). While the vault
    /// is locked it holds one "Locked" row that unlocks on open; opening the vault here unasked would undo a lock.
    /// </summary>
    private TreeItem? CredentialsSection()
    {
        if (_demo) return null;
        TreeItem section;
        if (_credentials is null)
        {
            if (_query.Length > 0) return null;
            section = TreeItem.CredentialsSection([], IconBrush, "", locked: true);
            section.Children.Add(new TreeItem
            {
                Id = LockedRowId, Name = "Locked", IsFolder = false, IsGroup = true, IsAppRow = true, ParentId = TreeItem.CredentialsGroupId,
                Glyph = FluentIcons.Object("credential"), IconBrush = IconBrush("icon.neutral"), IconLabel = "Locked",
                Description = "Locked. Open to unlock.", Open = () => _ = UnlockFromTreeAsync(),
            });
        }
        else
        {
            try { section = TreeItem.CredentialsSection(_credentials.Tree(), IconBrush, _query); }
            catch (BastionException) { return null; }
            if (_query.Length > 0 && section.Children.Count == 0) return null;
        }
        MarkCredentialsExpanded(section, everything: _query.Length > 0);
        return section;
    }

    private const string LockedRowId = "cred:locked";

    /// <summary>Which section rows are open: the heading starts open, folders closed; a search opens all of them.</summary>
    private readonly HashSet<string> _credentialsExpanded = [TreeItem.CredentialsGroupId];

    private void MarkCredentialsExpanded(TreeItem item, bool everything)
    {
        item.InitExpanded(everything || _credentialsExpanded.Contains(item.Id)); // a new section, not bound yet
        foreach (var child in item.Children) MarkCredentialsExpanded(child, everything);
    }

    private static bool IsCredentialTarget(TreeItem? t) => t is { Credential: not null } or { Id: TreeItem.CredentialsGroupId };

    /// <summary>The vault folder id an add/new-folder lands in: the folder itself, the folder of a credential, or the root.</summary>
    private static string? VaultFolderOf(TreeItem t) => t.Credential switch
    {
        { IsFolder: true } f => f.Id,
        { } c => c.Parent,
        _ => null,
    };

    private List<MenuFlyoutItemBase> CredentialMenuEntries(TreeItem target)
    {
        var result = new List<MenuFlyoutItemBase>();
        if (_credentials is null)
        {
            result.Add(ExtraEntry("Unlock Vault", "credential", (_, _) => _ = UnlockFromTreeAsync()));
            return result;
        }
        var folder = VaultFolderOf(target);
        result.Add(ExtraEntry("Add Password…", "credential", (_, _) => _ = AddCredentialInFolderAsync(sshKey: false, folder)));
        result.Add(ExtraEntry("Add SSH Key…", "credential", (_, _) => _ = AddCredentialInFolderAsync(sshKey: true, folder)));
        result.Add(ExtraEntry("New Folder", "folder", (_, _) => _ = NewVaultFolderAsync(folder)));
        if (target.Credential is not { } row) return result;
        result.Add(new MenuFlyoutSeparator());
        if (!row.IsFolder) result.Add(ExtraEntry("Edit…", "credential", (_, _) => _ = EditCredentialFromTreeAsync(row)));
        result.Add(ExtraEntry("Rename…", "credential", (_, _) => _ = RenameVaultRowAsync(row)));
        result.Add(ExtraEntry("Move to…", "folder", (_, _) => _ = MoveVaultRowAsync(row)));
        if (!row.IsFolder) result.Add(ExtraEntry("Used By…", "credential", (_, _) => _ = ShowCredentialUsersAsync(row)));
        result.Add(ExtraEntry("Delete…", "credential", (_, _) => _ = DeleteVaultRowAsync(row)));
        return result;
    }

    private async Task UnlockFromTreeAsync()
    {
        if (await ConfirmVaultOpenAsync()) UnlockLocalVault();
        if (_vaultError is { } why) await ShowModal("Could not unlock the vault", CodedErrorText("VAULT", why), primary: "OK", cancel: null);
        ApplyFilter(keepSelection: true);
    }

    /// <summary>Run a vault change, seal the vault and redraw the section; a failure is shown and the section reloads.</summary>
    private async Task VaultChange(Action change, string errorTitle, bool libraryToo = false)
    {
        var saveLibrary = false;
        try
        {
            change();
            OpenCredentials().Save();
            saveLibrary = libraryToo;
        }
        catch (BastionException ex)
        {
            await ShowModal(errorTitle, ErrorText(Capitalised(ex.Message)), primary: "OK", cancel: null);
        }
        if (saveLibrary) ReloadThenSave(CurrentSelectionId);
        else if (libraryToo) Reload(CurrentSelectionId);
        else ApplyFilter(keepSelection: true);
    }

    private async Task AddCredentialInFolderAsync(bool sshKey, string? folder)
    {
        var before = OpenCredentials().List().Select(c => c.Id).ToHashSet();
        await SaveCredentialAsync(new NewCredentialForm(sshKey, pickKeyFile: PickUploadFile));
        var added = OpenCredentials().List().FirstOrDefault(c => !before.Contains(c.Id));
        // Open the folder it lands in, so the new credential shows instead of hiding in a collapsed folder.
        if (added is not null && folder is not null) _credentialsExpanded.Add("cred:" + folder); // tree rows carry the "cred:" prefix (TreeItem.CredentialItem)
        if (added is not null && folder is not null) await VaultChange(() => OpenCredentials().Move(added.Id, folder), "Could not move the credential");
        else ApplyFilter(keepSelection: true);
    }

    private async Task EditCredentialFromTreeAsync(CredentialTreeRowDto row)
    {
        if (OpenCredentials().List().FirstOrDefault(c => c.Id == row.Id) is not { } c) return;
        await SaveCredentialAsync(new NewCredentialForm(false, c, PickUploadFile));
        ApplyFilter(keepSelection: true);
    }

    private async Task NewVaultFolderAsync(string? parent)
    {
        if (_modal is not null) return;
        var form = new RenameForm("New Folder");
        if (!await ShowModal("New credential folder", form.Body, primary: "Create", cancel: "Cancel", validate: form.Validate, focus: form.Field)) return;
        // The parent opens, so the new folder shows where it was made (inside the selected folder, not the top level).
        if (parent is not null) _credentialsExpanded.Add("cred:" + parent);
        await VaultChange(() => OpenCredentials().AddFolder(form.NewName, parent), "Could not create the folder");
    }

    private async Task RenameVaultRowAsync(CredentialTreeRowDto row)
    {
        if (_modal is not null) return;
        var form = new RenameForm(row.Name);
        if (!await ShowModal(row.IsFolder ? "Rename credential folder" : "Rename credential", form.Body, primary: "Rename", cancel: "Cancel",
                caption: row.IsFolder ? null : "Hosts that use it keep using it.", validate: form.Validate, focus: form.Field) || form.NewName == row.Name) return;
        await VaultChange(() =>
        {
            if (row.IsFolder) OpenCredentials().RenameFolder(row.Id, form.NewName);
            else OpenCredentials().Rename(row.Id, form.NewName);
        }, "Could not rename " + row.Name);
    }

    private async Task MoveVaultRowAsync(CredentialTreeRowDto row)
    {
        if (_modal is not null) return;
        var form = new VaultMoveForm(row, OpenCredentials().Tree());
        if (!await ShowModal($"Move “{row.Name}”", form.Body, primary: "Move", cancel: "Cancel", focus: form.List) || form.Destination == row.Parent) return;
        await VaultChange(() =>
        {
            if (row.IsFolder) OpenCredentials().MoveFolder(row.Id, form.Destination);
            else OpenCredentials().Move(row.Id, form.Destination);
        }, "Could not move " + row.Name);
    }

    private async Task ShowCredentialUsersAsync(CredentialTreeRowDto row)
    {
        IReadOnlyList<CredentialUserDto> users;
        try { users = OpenCredentials().Users(_library, row.Id); }
        catch (BastionException ex)
        {
            await ShowModal("Could not list who uses it", CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null);
            return;
        }
        await ShowModal($"Used by “{row.Name}”", UsersList(users, "No host or folder points at this credential. Hosts may still inherit it through a type default."),
            primary: "OK", cancel: null);
    }

    private async Task DeleteVaultRowAsync(CredentialTreeRowDto row)
    {
        if (_modal is not null) return;
        if (row.IsFolder)
        {
            if (!await ShowModal($"Delete folder “{row.Name}”?", ErrorText("Only an empty folder can be deleted."), primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
            await VaultChange(() => OpenCredentials().RemoveFolder(row.Id), "Could not delete " + row.Name);
            return;
        }
        if (!await ShowModal($"Delete credential “{row.Name}”?", ErrorText("It is deleted from the vault."), primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        CredentialRemoveDto first;
        try { first = OpenCredentials().RemoveChecked(_library, row.Id, force: false); }
        catch (BastionException ex)
        {
            await ShowModal("Could not delete " + row.Name, CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null);
            return;
        }
        if (first.Removed)
        {
            await VaultChange(() => { }, "Could not save the vault");
            return;
        }
        // In use: say who points at it; deleting anyway lets them inherit again.
        var body = UsersList(first.Users, "");
        body.Children.Insert(0, ErrorText($"{Plural(first.Users.Count, "host or folder", "hosts or folders")} use it. Delete anyway and they inherit a credential from above again."));
        if (!await ShowModal($"“{row.Name}” is in use", body, primary: "Delete Anyway", cancel: "Cancel", focusCancel: true)) return;
        await VaultChange(() => OpenCredentials().RemoveChecked(_library, row.Id, force: true), "Could not delete " + row.Name, libraryToo: true);
    }

    private static string Plural(int n, string one, string many) => $"{n} {(n == 1 ? one : many)}";

    private static StackPanel UsersList(IReadOnlyList<CredentialUserDto> users, string empty)
    {
        var panel = new StackPanel { Spacing = Ui.Double("Space4") };
        if (users.Count == 0 && empty.Length > 0) panel.Children.Add(Ui.Text(empty, "BodySecondaryTextStyle"));
        foreach (var u in users)
        {
            var where = u.Path.Count == 0 ? "Library" : string.Join(" / ", u.Path);
            var line = Ui.Text($"{u.Name}  ·  {(u.IsFolder ? "folder" : "host")} in {where}", "BodyTextStyle");
            line.TextWrapping = TextWrapping.Wrap;
            panel.Children.Add(line);
        }
        return panel;
    }

    /// <summary>"web-1 key" or, when nothing is set on the host, the one it inherits and from where.</summary>
    private string EffectiveCredentialLabel(ConnectionDto c)
    {
        // Only an open vault is asked; a locked one stays locked (VaultLabels, LOCK-CREDENTIALS-REOPEN).
        var store = CredentialsIfOpen;
        Func<(string, string)?>? effective = store is null ? null : () =>
            store.Effective(_library, c.Id) is { } eff ? (eff.CredentialId, TreeItem.Find(_roots, eff.SourceId)?.Name ?? "a type default") : null;
        try { return VaultLabels.Effective(c.CredentialId, effective, VaultNameLookup()); }
        catch (BastionException) { return "Vault unavailable"; }
    }
}

/// <summary>The Move to… body for a vault row: the vault root and every folder that can take it, indented by depth.</summary>
internal sealed class VaultMoveForm
{
    private readonly List<string?> _targets = new();

    public StackPanel Body { get; }
    public ListView List { get; }

    /// <summary>The chosen vault folder id; null is the root.</summary>
    public string? Destination => List.SelectedIndex is var i and >= 0 ? _targets[i] : null;

    public VaultMoveForm(CredentialTreeRowDto row, IReadOnlyList<CredentialTreeRowDto> rows)
    {
        List = new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = 320 };
        AutomationProperties.SetName(List, "Destination folder");
        Add(null, "Credentials (top level)", 0);
        void Walk(string? parent, int depth)
        {
            foreach (var f in rows.Where(r => r.IsFolder && r.Parent == parent && r.Id != row.Id))
            {
                Add(f.Id, f.Name, depth);
                Walk(f.Id, depth + 1);
            }
        }
        Walk(null, 1);
        List.SelectedIndex = Math.Max(0, _targets.IndexOf(row.Parent));
        Body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { List } };
    }

    private void Add(string? id, string name, int depth)
    {
        _targets.Add(id);
        var label = Ui.IconLabel(new AppIcon { Kind = "Folder" }, name);
        label.Margin = new Thickness(depth * Ui.Double("Space16"), 0, 0, 0);
        AutomationProperties.SetName(label, name);
        List.Items.Add(label);
    }
}

// W12: dragging vault rows. Onto a credential folder or the Credentials heading: move it there. A credential onto a library
// folder or connection: that node uses it (folder credentials are inherited by everything inside).
public sealed partial class MainWindow
{
    private CredentialTreeRowDto? _dragCredential;

    /// <summary>The vault folder a drop on <paramref name="target"/> lands in (null: the root), or false when it is not a vault target.</summary>
    private static (bool IsVault, string? Folder) VaultDropFolder(TreeItem? target) => target switch
    {
        { Id: TreeItem.CredentialsGroupId } => (true, null),
        { Credential: { IsFolder: true } f } => (true, f.Id),
        { Credential: { } c } => (true, c.Parent),
        _ => (false, null),
    };

    /// <summary>BASTION_TRACE_DRAG=1: one line per credential drag decision in %TEMP%\bastion-drag.txt (UI tests read it).</summary>
    private static void TraceDrag(string line)
    {
        if (!TestHooks.TraceDrag) return;
        try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "bastion-drag.txt"), $"{DateTime.Now:HH:mm:ss.fff} {line}{Environment.NewLine}"); }
        catch (IOException) { } // a trace line lost is fine
    }

    private (DataPackageOperation Op, string? Caption) CredentialDropAction(CredentialTreeRowDto dragged, TreeItem? target)
    {
        var result = CredentialDropActionCore(dragged, target);
        TraceDrag($"over {(target is null ? "(no row)" : $"{target.Name} [{target.Id}] folder={target.IsFolder} group={target.IsGroup} mirror={target.IsMirror}")} -> {result.Op}");
        return result;
    }

    private (DataPackageOperation Op, string? Caption) CredentialDropActionCore(CredentialTreeRowDto dragged, TreeItem? target)
    {
        var (isVault, folder) = VaultDropFolder(target);
        if (isVault)
        {
            if (folder == dragged.Parent || folder == dragged.Id || (dragged.IsFolder && IsVaultInside(folder, dragged.Id))) return (DataPackageOperation.None, null);
            return (DataPackageOperation.Move, "Move into " + (folder is null ? "Credentials" : target!.Credential is { IsFolder: true } ? target.Name : "this folder"));
        }
        if (dragged.IsFolder || target is null or { IsGroup: true } or { IsMirror: true }) return (DataPackageOperation.None, null);
        // Move, not Link: the source offers Move first and a Link-only accept showed the no-drop cursor on library rows.
        return (DataPackageOperation.Move, $"{target.Name} uses {dragged.Name}");
    }

    /// <summary>Whether vault folder <paramref name="folder"/> lies inside (or is) <paramref name="ancestor"/>.</summary>
    private bool IsVaultInside(string? folder, string ancestor)
    {
        // A drag hover is passive: a locked vault has no folders to be inside, and stays locked.
        if (CredentialsIfOpen is not { } store) return false;
        var rows = store.Tree();
        for (var f = folder; f is not null; f = rows.FirstOrDefault(r => r.Id == f)?.Parent)
            if (f == ancestor) return true;
        return false;
    }

    private async Task DropCredentialAsync(CredentialTreeRowDto dragged, TreeItem? target)
    {
        if (CredentialDropAction(dragged, target).Op == DataPackageOperation.None) return;
        var (isVault, folder) = VaultDropFolder(target);
        if (isVault)
        {
            if (folder is not null) _credentialsExpanded.Add("cred:" + folder);
            await VaultChange(() =>
            {
                if (dragged.IsFolder) OpenCredentials().MoveFolder(dragged.Id, folder);
                else OpenCredentials().Move(dragged.Id, folder);
            }, "Could not move " + dragged.Name);
            return;
        }
        var node = TreeItem.Find(_roots, target!.Id) ?? target;
        if (node.IsFolder && !await ConfirmFolderLogin(dragged.Name, node.Name))
        {
            TraceDrag($"drop assign cancelled {dragged.Name} -> {node.Name}");
            return;
        }
        TraceDrag($"drop assign {dragged.Name} -> {node.Name} [{node.Id}]");
        await VaultChange(() => OpenCredentials().Assign(_library, node.Id, dragged.Id), "Could not assign " + dragged.Name, libraryToo: true);
        Announce(node.IsFolder ? $"{node.Name} and everything in it use {dragged.Name}" : $"{node.Name} uses {dragged.Name}");
    }

    /// <summary>
    /// A credential dropped on a library folder becomes the login of every connection under it that has none of its
    /// own, and those then sign in with it without asking: one drop, so it asks first. Same wording as Native Mac.
    /// </summary>
    private Task<bool> ConfirmFolderLogin(string credential, string folder)
    {
        var body = Ui.Text("Connections in this folder that have no login of their own will sign in with it without asking. "
            + "You can change this in the folder\u2019s Properties \u203a Credentials.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        return ShowModal($"Use \u201c{credential}\u201d for every connection in \u201c{folder}\u201d?", body,
            primary: "Use for Folder", cancel: "Cancel", focusCancel: true);
    }

    /// <summary>Snapshot/UI tests: the drop drag-and-drop performs, a vault row onto a named row (vault or library).</summary>
    internal Task DropCredentialForSnapshot(string credentialName, string targetName)
    {
        var rows = OpenCredentials().Tree();
        var dragged = rows.First(r => r.Name == credentialName);
        var target = targetName == "Credentials"
            ? new TreeItem { Id = TreeItem.CredentialsGroupId, Name = "Credentials", IsFolder = false, IsGroup = true, Glyph = "" }
            : rows.FirstOrDefault(r => r.Name == targetName) is { } row
                ? new TreeItem { Id = "cred:" + row.Id, Name = row.Name, IsFolder = false, IsGroup = true, Glyph = "", Credential = row }
                : LibraryItemForSnapshot(targetName);
        return DropCredentialAsync(dragged, target);
    }
}
