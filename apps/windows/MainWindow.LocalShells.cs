using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

/// <summary>Saved local shells (PowerShell, cmd, WSL distributions) opened from the tree like any connection.</summary>
public sealed partial class MainWindow
{
    private static bool IsLocal(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "local", StringComparison.OrdinalIgnoreCase);

    /// <summary>The effective <c>local.shell</c> of a saved connection, null when it cannot be read.</summary>
    private static string? ShellOf(LibraryClient library, string id)
    {
        try { return library.PropertyValues(id).FirstOrDefault(v => v.Key == LocalShells.ShellKey)?.Effective; }
        catch (BastionException) { return null; }
    }

    /// <summary>
    /// Open a saved local shell. A WSL distribution is checked first so a missing WSL, a removed distribution or one
    /// being installed is explained in plain words; a stopped distribution simply starts.
    /// </summary>
    private void OpenLocalConnection(TreeItem item, LibraryClient? from)
    {
        if (_modal is not null || item.Connection is not { } c) return;
        var library = from ?? _library;
        if (LocalShells.DistroOf(ShellOf(library, c.Id)) is { } distro && LocalShells.Problem(distro) is { } problem)
        {
            // The launch fails before any process starts, so no tab may stay for it: also close a "disconnected" tab
            // that crash restore put back for this connection (its Reconnect could only fail the same way).
            foreach (var waiting in _tabs.Where(t => t.Waiting?.Connection == c.Id).ToList()) CloseTab(waiting);
            _ = ShowModal("Cannot open " + item.Name, ErrorText(problem), primary: "OK", cancel: null);
            return;
        }
        var view = OpenTerminal(item.Name, () => TerminalSession.OpenLocal(library, c.Id, 80, 24));
        // B4: the tab belongs to its saved connection, so Connect All counts it as open and Reconnect All and Disconnect
        // All find it, as for an SSH tab (Supervise). A Quick Connect library is never saved, so its tab stays untied.
        if (from is not null || view is null || _tabs.FirstOrDefault(t => ReferenceEquals(t.View, view)) is not { } tab) return;
        TieTab(tab, c.Id);
        RunHooks("after_connect", c.Id); // B5
        PaintTab(tab);
        RefreshInspectorFor(c.Id);
        SaveOpenSessions();
    }

    private void AddAllWsl_Click(object sender, RoutedEventArgs e) => _ = AddAllWslAsync();

    /// <summary>
    /// "Add all WSL distributions": one saved local shell per installed distribution not saved yet (docker-desktop helpers
    /// left out), in the current folder. Says so when there is nothing to add.
    /// </summary>
    internal async Task AddAllWslAsync()
    {
        if (_modal is not null) return;
        var distros = LocalShells.Distros();
        var saved = AllConnections(_roots).Where(i => IsLocal(i)).Select(i => ShellOf(_library, i.Connection!.Id)).OfType<string>();
        var missing = LocalShells.Missing(distros, saved);
        if (missing.Count == 0)
        {
            var why = distros.Count == 0
                ? $"No WSL distributions are installed on this PC. Install one with \"wsl --install\" (see {LocalShells.WslDocsUrl})."
                : "Every installed WSL distribution is already saved as a connection.";
            await ShowModal("Add WSL distributions", Ui.Text(why, "BodyTextBlockStyle"), primary: "OK", cancel: null);
            return;
        }
        var parent = CurrentParent();
        await Mutate(() =>
        {
            string? first = null;
            foreach (var d in missing)
            {
                var id = _library.AddConnection(parent?.Id, d.Name, "local", "", null, null);
                _library.SetProperty(id, LocalShells.ShellKey, LocalShells.WslPrefix + d.Name);
                first ??= id;
            }
            return first;
        }, "Could not add the WSL distributions");
    }

    private static IEnumerable<TreeItem> AllConnections(IEnumerable<TreeItem> items) =>
        items.SelectMany(i => i.Connection is not null ? [i] : AllConnections(i.Children));
}
