using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// Segoe Fluent Icons / Segoe MDL2 Assets code points for the core's icon ids (core/src/icons.rs) and the registry's
/// action glyph names (core/src/actions.rs), the Windows counterpart of apps/macos Icons.swift. The same code points
/// exist in both fonts (SymbolFontFamily falls back to MDL2 on Windows 10). Folders draw with AppIcon instead.
/// W15: connection protocols use Material Design Icons from the bundled Nerd Font (SymbolFontFamily falls back to it
/// for these supplementary-plane code points): md-console_network (SSH), md-monitor_share (RDP), md-eye (VNC),
/// md-web, md-folder_network (file transfer), md-powershell, md-linux (WSL), md-serial_port, md-docker, md-server.
/// Only the five protocol glyphs that TreeItem used before were seen on Windows 10; the rest are unverified on a
/// Windows screen (FEATURE_MATRIX.md).
/// </summary>
internal static class FluentIcons
{
    private const string Pc = "";

    private static readonly Dictionary<string, string> Objects = new()
    {
        // The app's own pages (docs/design/icons/app-*.svg): Segoe Fluent line icons, drawn in the secondary text
        // colour so they never look like a connection's coloured tile.
        ["app-tasks"] = "\uE9D5", ["app-triggers"] = "\uE945", ["app-audit"] = "\uEA18", ["app-activity"] = "\uE81C", ["app-plugins"] = "\uEA86",
        ["ssh"] = "\U000F08A9", ["telnet"] = "\U000F07B7", ["serial"] = "\U000F065C", ["local-terminal"] = "\U000F018D",
        ["powershell"] = "\U000F0A0A", ["wsl"] = "\U000F033D",
        ["rdp"] = "\U000F1483", ["vnc"] = "\U000F0208", ["web"] = "\U000F059F",
        ["sftp"] = "\U000F0870", ["scp"] = "\U000F0870", ["ftp"] = "\U000F0870", ["ftps"] = "\U000F0870",
        ["esxi"] = "\U000F048B", ["vcenter"] = "", ["proxmox"] = "", ["hyperv"] = "",
        ["docker"] = "\U000F0868", ["kubernetes"] = "", ["cluster"] = "", ["datacenter"] = "",
        ["storage"] = "", ["network"] = "",
        ["vm-running"] = "", ["vm-stopped"] = "", ["vm-suspended"] = "", ["vm-unknown"] = "",
        // Item icons a user can pick (core model::ICONS); storage, network and container are above. Unverified on a Windows screen.
        ["server"] = "\U000F048B", ["desktop"] = "\U000F0379", ["terminal"] = "\U000F018D", ["database"] = "\U000F01BC",
        ["cloud"] = "\uE753", ["globe"] = "\uE774", ["shield"] = "\uEA18",
        ["container"] = "",
        ["credential"] = "", ["task"] = "", ["gateway"] = "", ["folder"] = "", ["favorite"] = "",
        ["keyboard"] = "\uE765", ["home"] = "\uE80F", ["workspace"] = "", ["settings"] = "", ["appearance"] = "", ["defaults"] = "",
        ["vault"] = "", ["security"] = "", ["update"] = "", ["about"] = "",
    };

    private static readonly Dictionary<string, string> Actions = new()
    {
        ["connect"] = "", ["tab"] = "", ["window"] = "", ["fullscreen"] = "",
        ["reconnect"] = "", ["disconnect"] = "", ["sftp"] = "",
        ["copy"] = "", ["add"] = "", ["folder-add"] = "", ["expand"] = "", ["collapse"] = "",
        ["sort"] = "", ["rename"] = "", ["duplicate"] = "", ["template"] = "", ["move"] = "", ["favorite"] = "",
        ["properties"] = "", ["trash"] = "", ["import"] = "", ["export"] = "", ["workspace"] = "",
        ["appearance"] = "", ["credential"] = "", ["gateway"] = "", ["task"] = "",
        ["console"] = "", ["ssh"] = "", ["rdp"] = "", ["vnc"] = "",
        ["power-start"] = "", ["power-shutdown"] = "", ["power-reboot"] = "", ["power-stop"] = "",
        ["power-reset"] = "", ["power-suspend"] = "", ["power-resume"] = "",
        ["monitor"] = "", ["snapshot"] = "", ["backup"] = "", ["refresh"] = "", ["options"] = "",
    };

    /// <summary>Glyph for a core icon id or a connection's protocol wire name.</summary>
    public static string Object(string id) => Objects.TryGetValue(id, out var g) ? g : Pc;

    /// <summary>Glyph for a registry action glyph name (<see cref="MenuItemDto.Glyph"/>); a few are icon ids.</summary>
    public static string Action(string glyph) => Actions.TryGetValue(glyph, out var g) ? g : Object(glyph);

    /// <summary>Core icon ids without a glyph here, for a startup check in debug builds.</summary>
    public static IEnumerable<string> Missing(IEnumerable<IconDto> core) => core.Select(i => i.Id).Where(id => !Objects.ContainsKey(id));
}
