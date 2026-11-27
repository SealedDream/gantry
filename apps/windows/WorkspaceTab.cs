using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>One open tab: its session, its content and its header controls (B12-W2a). It was a private class of
/// <see cref="MainWindow"/>; it is its own type so that a torn-off window (B12-W2b) can hold a tab too. No behaviour
/// changed in the move.</summary>
internal sealed class WorkspaceTab
{
    /// <summary>The name shown: the opening name, or for an unsaved terminal the program's title (OSC 0/2).</summary>
    public required string Title { get; set; }
    /// <summary>The name the tab opened with ("Local shell", "PowerShell", a distribution): what session restore stores.</summary>
    public string DefaultTitle { get; init; } = "";
    /// <summary>The name typed in Rename Tab, or null for the automatic name (TABBAR-WIN).</summary>
    public string? CustomTitle { get; set; }
    /// <summary>While renamed: the automatic name it would show now, restored when the name is cleared.</summary>
    public string? AutoTitle { get; set; }
    /// <summary>Speed marks: false until the tab was first activated (its opening is not a tab switch).</summary>
    public bool Shown { get; set; }
    public SupervisedSession? Link { get; set; }
    /// <summary>Points added to <c>terminal.font-size</c> by Ctrl+= / Ctrl+- in this tab only; never saved.</summary>
    public double Zoom { get; set; }
    /// <summary>The saved connection an SSH tab belongs to (null for local shells), for workspaces.</summary>
    public string? ConnectionId { get; set; }
    /// <summary>The tab's program ended (local shells; a supervised tab shows its link state instead).</summary>
    public bool Exited { get; set; }
    /// <summary>Ended by Disconnect and kept for its scrollback (PR-1289): a Files panel that opens late is discarded.</summary>
    public bool UserDisconnected { get; set; }
    public ulong LinkSeen { get; set; }
    /// <summary>The tab's supervised pane: the session the supervisor reconnects and a workspace restores. Null for a web tab.
    /// Starts as the first pane; when that pane closes, the next surviving pane takes over (PAR-7).</summary>
    public TerminalView? View { get; set; }
    /// <summary>How <see cref="Link"/> was started, so supervision can move to a surviving pane (PAR-7). Holds a vault
    /// credential id or key path only, never a password.</summary>
    public Func<TerminalSession, SupervisedSession>? Resupervise { get; set; }
    /// <summary>All of the tab's panes; split panes are extra shells beside <see cref="View"/>. Null for a web tab.</summary>
    public SplitPanes? Panes { get; init; }
    /// <summary>A web connection's page (WebView2); null for terminal tabs.</summary>
    public WebTabView? Web { get; init; }
    /// <summary>An RDP or VNC connection's remote desktop; null for other tabs.</summary>
    public RemoteDesktopView? Rdp { get; init; }
    /// <summary>PLUG-VIEW-WIN: a plugin's view; null for other tabs. Disposing it stops the plugin's helper.</summary>
    public PluginTabView? Plugin { get; init; }
    public IEnumerable<TerminalView> AllPanes => Panes?.Panes ?? [];
    public void FocusContent(FocusState how) { if (Panes is { } p) p.Focused.Focus(how); else if (Web is { } w) w.Focus(how); else if (Rdp is { } r) r.Focus(how); else if (Files is { } f) f.Focus(how); else if (Plugin is { } pl) pl.Focus(how); else Bar?.FocusReconnect(how); }
    /// <summary>The tab's content: the panes and, for SSH tabs, the optional Files panel beside them.</summary>
    public required Grid Body { get; init; }
    /// <summary>The open Files (SFTP) panel, on the tab's own connection; null when hidden.</summary>
    public SftpPanel? Files { get; set; }
    /// <summary>How a local tab starts its program again for a split (null for SSH, which opens a sibling channel).</summary>
    public Func<TerminalSession>? StartLocal { get; set; }
    public required Grid Header { get; init; }
    public required Button Select { get; init; }
    public required Button Close { get; init; }
    public required TextBlock Label { get; init; }
    /// <summary>WIN-TAB-STATUS-DOT: the link dot beside the name (green online, amber reconnecting, red offline); collapsed
    /// for local shells and other tabs with no connection.</summary>
    public required Microsoft.UI.Xaml.Shapes.Ellipse Dot { get; init; }
    /// <summary>The status words the dot stands for ("reconnecting 1/5", "disconnected"); in the tooltip and automation
    /// name, not in the label. Null when online or when the tab has no status.</summary>
    public string? Status { get; set; }
    /// <summary>TERM-MARKS: dot shown while a background tab has output the user has not seen; null for non-terminal tabs.</summary>
    public Microsoft.UI.Xaml.Shapes.Ellipse? UnreadDot { get; init; }
    public bool Unread { get; set; }
    /// <summary>TERM-MARKS: "Command failed, exit 3 (40 s)" for a long command that ended while the tab was in the
    /// background; cleared when the tab is shown.</summary>
    public string? Notice { get; set; }
    /// <summary>TERM-MARKS: the open "Save as connection" bar for an ssh line typed in this local tab, or null.</summary>
    public InfoBar? SshOffer { get; set; }
    /// <summary>Leading-edge bar in the tab's per-host colour (MainWindow.HostColors.cs); collapsed when it has none.</summary>
    public required Border HostBar { get; init; }
    private string? _hostColorId;
    /// <summary>The saved connection whose host colour paints this tab: <see cref="ConnectionId"/>, or the web/RDP connection it opened.</summary>
    public string? HostColorId { get => _hostColorId ?? ConnectionId; set => _hostColorId = value; }
    public bool Hover { get; set; }
    /// <summary>Broadcast Input to All Panes is on for this tab.</summary>
    public bool Broadcast { get; set; }
    /// <summary>The user confirmed this broadcast set's sensitive hosts.</summary>
    public bool BroadcastAcked { get; set; }
    /// <summary>The tab's id in the core tab strip (groups refer to it).</summary>
    public Guid StripId { get; } = Guid.NewGuid();
    /// <summary>The strip group this tab is in, or null.</summary>
    public string? Group { get; set; }
    /// <summary>Status/address/Reconnect/pin bar above a saved SSH connection's session (Codex Y06); null otherwise.</summary>
    public SessionBar? Bar { get; set; }
    /// <summary>Taken out of a folder group: folder grouping leaves it alone.</summary>
    public bool Detached { get; set; }
    /// <summary>A2-W26 (D15): the saved tab this one stands in for after a crash. It has no session and no content of
    /// its own; the session bar's Reconnect opens the connection (MainWindow.SessionRestore.cs). Null for every other tab.</summary>
    public OpenTabDto? Waiting { get; init; }
    /// <summary>B12-W2b: the torn-off window showing this tab's content, or null while it is in the main window's strip.</summary>
    public TabWindow? Window { get; set; }
}

/// <summary>B12-W1/W2a: the open tabs of every window, owned by the app rather than by one window (SessionStore.cs).
/// <see cref="MainWindow"/> reaches it as <c>TabStore</c>; the torn-off windows of B12-W2b use the same store.</summary>
internal static class AppTabs
{
    public static readonly SessionStore<WorkspaceTab> Store = new();
}
