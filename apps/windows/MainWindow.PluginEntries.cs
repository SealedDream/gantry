using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// PLUG-08-WIN (as Native Mac PLUG-PVE-01 / PLUG-08): library entries of plugin connection types. The core stores such an
// entry under "<plugin id>/<type id>" and marks it unavailable, because the core alone cannot open it; when an installed
// plugin offers the type, the entry opens that plugin's view in a normal tab. The vault login is read by the core and
// released to the owning plugin only; it never passes through this app.
public sealed partial class MainWindow
{
    public const string PostgresTypeId = "dev.gantry.postgres/postgres";
    /// <summary>The PostgreSQL type under its current id or its pre-rename one (dev.bastion.postgres, still installed).</summary>
    internal static bool IsPostgresType(string id) => id is PostgresTypeId or "dev.bastion.postgres/postgres";
    private IReadOnlyList<PluginTypeDto>? _pluginTypes;

    /// <summary>The installed plugins' connection types; read on first use and after an install or removal (never at start).</summary>
    private IReadOnlyList<PluginTypeDto> PluginTypes
    {
        get
        {
            if (_pluginTypes is not null) return _pluginTypes;
            try { _pluginTypes = PluginEntryClient.Types(SessionDataDir); }
            catch (BastionException) { _pluginTypes = []; } // no plugins folder or none loads: no plugin types
            return _pluginTypes;
        }
    }

    /// <summary>Before the tree builds: plugin entries an installed plugin opens lose the "needs a plugin" marker. The
    /// plugins folder is read only when the library holds an unavailable entry, so a library without any costs nothing.</summary>
    private void MarkOpenablePluginEntries(FolderDto tree)
    {
        if (_pluginTypes is null && !HasUnavailable(tree)) return;
        TreeItem.OpenablePluginTypes = PluginTypes.Select(t => t.Id).ToHashSet();
        TreeItem.PluginTypeNames = PluginTypes.GroupBy(t => t.Id).ToDictionary(g => g.Key, g => g.First().Name);
        TreeItem.SidebarTreeTypes = PluginTypes.Where(t => t.SidebarTree).Select(t => t.Id).ToHashSet();
    }

    private static bool HasUnavailable(FolderDto f) => f.Connections.Any(c => c.IsUnavailable) || f.Folders.Any(HasUnavailable);

    /// <summary>The installed type of <paramref name="c"/> when it is a plugin entry this app can open; else null.</summary>
    private PluginTypeDto? PluginTypeOf(ConnectionDto c) => c.IsUnavailable ? PluginTypes.FirstOrDefault(t => t.Id == c.Protocol) : null;

    /// <summary>Opens a plugin entry in its tab (selected if already open). False when <paramref name="c"/> is no such entry.</summary>
    /// <summary>PVE-AUTH: Test Connection's login step for plugin entry <paramref name="id"/>, run on the saved host and
    /// port only (an edited dialog is tested with TLS alone). A gateway entry is not tested here. Uses the vault only if
    /// it is already open: a test never prompts.</summary>
    private Func<ProbeStepDto>? PluginLoginTest(string id, PluginTypeDto type, string host, int port)
    {
        if (TreeItem.Find(_roots, id)?.Connection is not { } c) return null;
        if (!string.Equals(c.Host, host, StringComparison.OrdinalIgnoreCase) || (c.Port ?? type.DefaultPort ?? 443) != port) return null;
        try { if (PluginEntryClient.Gateway(_library, id) is not null) return PluginEntryClient.LoginNotTested; }
        catch (BastionException) { return null; }
        var lib = _library.NativeHandle;
        var vault = CredentialsIfOpen?.NativeHandle ?? IntPtr.Zero;
        var dir = SessionDataDir;
        var unverified = string.Equals(type.Tier, "unverified", StringComparison.OrdinalIgnoreCase);
        return () => PluginEntryClient.TestLogin(lib, vault, id, dir, unverified);
    }

    private async Task<bool> TryOpenPluginEntryAsync(ConnectionDto c)
    {
        if (PluginTypeOf(c) is not { } type)
        {
            AppLog.Info($"Plugin entry: no installed type for '{c.Protocol}' (types: {string.Join(", ", PluginTypes.Select(t => t.Id))})");
            return false;
        }
        AppLog.Info($"Plugin entry: opening {type.Id} (tier {type.Tier})");
        if (_pageKind.Length > 0) ClosePage();
        if (_tabs.FirstOrDefault(t => t.Plugin?.EntryId == c.Id) is { } open) { PickTab(open); return true; }
        var unverified = string.Equals(type.Tier, "unverified", StringComparison.OrdinalIgnoreCase);
        if (unverified)
        {
            if (_modal is not null) return true;
            var body = Ui.Text("Unverified plugin: no known publisher signature. It runs in the plugin sandbox.", "BodyTextStyle");
            body.TextWrapping = TextWrapping.Wrap;
            if (!await ShowModal("Open an unverified plugin?", body, primary: "Open", cancel: "Cancel", focusCancel: true)) return true;
        }
        // The saved login comes from the vault: open it (Windows Hello / password as for SSH) only when the entry has one.
        CredentialStore? vault = CredentialsIfOpen;
        if (vault is null && c.EffectiveCredentialId is not null && await ConfirmVaultOpenAsync())
        {
            try { vault = OpenCredentials(); }
            catch (BastionException) { vault = null; } // opens without a login; the plugin says the login is missing
        }
        // Through the entry's gateway (own or a folder's): a forward or SOCKS route first, as for RDP/VNC/web. The core
        // never sends a gateway entry direct, so without the route the open is refused with the core's words.
        GatewayRoute? route = null;
        try
        {
            if (PluginEntryClient.Gateway(_library, c.Id) is not null && TreeItem.Find(_roots, c.Id) is { } item)
            {
                var (proceed, r) = await OpenGatewayRouteAsync(item, c.Id);
                if (!proceed) return true;
                route = r;
            }
        }
        catch (BastionException ex)
        {
            if (_modal is null) await ShowModal("Cannot open " + c.Name, CodedErrorText("PLUG", ex.Message), primary: "OK", cancel: null);
            return true;
        }
        var view = new PluginTabView(type.PluginId) { EntryId = c.Id, Route = route, TrustCertificate = v => _ = TrustFromBannerAsync(c.Id, v) };
        WatchPluginOpens(view, c.Id);
        var glyph = IsPostgresType(type.Id) ? "GlyphDatabase" : "GlyphList";
        var tab = AddTab(c.Name, null, plugin: view, glyph: glyph, hostId: c.Id);
        tab.FocusContent(FocusState.Programmatic);
        AppLog.Info($"Plugin entry: tab added, active {ReferenceEquals(_active, tab)}, tabs {_tabs.Count}");
        var lib = _library.NativeHandle;
        var vh = vault?.NativeHandle ?? IntPtr.Zero;
        var dir = SessionDataDir;
        var id = c.Id;
        var (kind, port, target) = route is null ? (0, (ushort)0, (string?)null) : route.IsSocks ? (2, route.Port, null) : (1, route.Port, c.Host);
        AppLog.Info($"Plugin entry: view opening, route {kind}, vault {(vh == IntPtr.Zero ? "closed" : "open")}");
        _ = view.OpenWithAsync(() => PluginViewSession.OpenEntry(lib, vh, id, dir, unverified, kind, port, target));
        return true;
    }

    /// <summary>PVE-TLS: the dashboard banner's Trust Certificate…: the fingerprint check of Properties, then the tab opens
    /// again so the view connects under the new pin (a view reads the entry's TLS rule when it opens).</summary>
    private async Task TrustFromBannerAsync(string id, PluginTabView view)
    {
        if (TreeItem.Find(_roots, id)?.Connection is not { } c) return;
        if (!await ConfirmAndPinAsync(c)) return;
        if (_tabs.FirstOrDefault(t => ReferenceEquals(t.Plugin, view)) is { } tab) CloseTab(tab);
        await TryOpenPluginEntryAsync(c);
    }

    /// <summary>Creates a plugin entry from the New connection form: the type's default port unless one was typed.</summary>
    private string AddPluginConnection(string? parentId, AddConnectionForm form, PluginTypeDto type)
    {
        var id = PluginEntryClient.Add(_library, SessionDataDir, parentId, form.ConnectionName, form.Host, type.Id);
        if (form.PortValue is { } port) _library.SetProperty(id, "port", port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return id;
    }
}
