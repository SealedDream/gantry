using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

// The Credentials section pinned under the connection tree (CredentialsPane, Native Mac parity). Rows, menus, unlock and
// drag-and-drop are the ones the section had inside the tree (MainWindow.CredentialsTree.cs); this file only connects them.
public sealed partial class MainWindow
{
    private bool _credentialsPaneWired;

    /// <summary>Redraw the pinned section from the vault (or its locked state) and the current search.</summary>
    private void RefreshCredentialsPane()
    {
        if (_credentialsPane is not { } pane) return; // built after the first frame, then drawn (WIN-COLD-LIGHT)
        if (!_credentialsPaneWired) WireCredentialsPane(pane);
        pane.Show(CredentialsSection());
    }

    private void WireCredentialsPane(CredentialsPane pane)
    {
        _credentialsPaneWired = true;
        pane.MenuFor = target => CredentialMenuEntries(target is { Id: not LockedRowId } ? target : CredentialsHeading());
        pane.ExpandedChanged = (id, open) => { if (open) _credentialsExpanded.Add(id); else _credentialsExpanded.Remove(id); };
        pane.DragStart = StartCredentialDrag;
        pane.DragEnded = () => { _dragId = null; _dragCredential = null; };
        pane.DragOverRow = (target, e) =>
        {
            e.Handled = true;
            if (_dragCredential is not { } dragged) { e.AcceptedOperation = DataPackageOperation.None; return; }
            var (op, caption) = CredentialDropAction(dragged, target);
            e.AcceptedOperation = op;
            if (caption is not null) e.DragUIOverride.Caption = caption;
        };
        pane.DropOnRow = (target, e) =>
        {
            e.Handled = true;
            if (_dragCredential is not { } dragged) return;
            _dragCredential = null;
            _ = DropCredentialAsync(dragged, target);
        };
    }

    /// <summary>A vault row drags as it did in the tree: onto a vault folder it moves, onto a library row it is assigned.</summary>
    private bool StartCredentialDrag(TreeItem item, DragStartingEventArgs args)
    {
        TraceDrag($"start {item.Name} [{item.Id}] credential={item.Credential is not null} vaultOpen={_credentials is not null}");
        if (item.Credential is not { } cred || _credentials is null) return false;
        _dragCredential = cred;
        args.Data.SetData(DragFormat, item.Id);
        args.Data.RequestedOperation = DataPackageOperation.Move;
        args.AllowedOperations = DataPackageOperation.Move | DataPackageOperation.Link;
        return true;
    }

    private static TreeItem CredentialsHeading() => new() { Id = TreeItem.CredentialsGroupId, Name = "Credentials", IsFolder = false, IsGroup = true, Glyph = "" };
}
