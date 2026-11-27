using Bastion.Shell.Interop;

namespace Bastion.Shell;

// Mosh transport and tmux attach (core remoteshell, C ABI 67), as Native Mac #279/#292 and Tauri #400. Both are ordinary
// connection properties the property editor already lists (Terminal › Transport, tmux, tmux session):
// - tmux "Attach or create" needs nothing here: bastion_terminal_connect runs `tmux new -A -s <session>` on the login and
//   on every reconnect.
// - Transport "Mosh" opens the local mosh client in the tab instead of Bastion's SSH client. The core refuses it through a
//   gateway or jump host, and says how to install mosh when it is missing.
public sealed partial class MainWindow
{
    internal const string TransportKey = "ssh.transport";

    /// <summary>Whether this SSH connection is set to open over Mosh (its effective <c>ssh.transport</c>).</summary>
    private static bool UsesMosh(LibraryClient library, string connectionId)
    {
        try { return library.PropertyValues(connectionId).FirstOrDefault(v => v.Key == TransportKey)?.Effective == "mosh"; }
        catch (BastionException) { return false; }
    }

    /// <summary>Open a Mosh connection in a terminal tab; returns false when the connection is plain SSH.</summary>
    private bool TryOpenMosh(TreeItem item, LibraryClient? from)
    {
        if (item.Connection is not { } c) return false;
        var library = from ?? _library;
        if (!UsesMosh(library, c.Id)) return false;
        if (_modal is not null) return true;
        OpenTerminal(item.Name, () => TerminalSession.OpenMosh(library, c.Id, 80, 24));
        return true;
    }
}
