using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Connect All and Reconnect All on a folder (B4), as on macOS (apps/macos/Sources/Bastion/ConnectAll.swift). The core
// plans (C ABI 97; types the managed policy forbids come back as skippedBlocked since 109 and are only named): connections with a login of their own open one after another through the normal connect; a
// connection whose only login is offered (saved for another connection on the same host) or that has none is never
// opened with a login the app picked. It opens only when the user asks, one by one, with the sign-in sheet shown.
public sealed partial class MainWindow
{
    /// <summary>Names listed in the summary before "and N more".</summary>
    private const int BulkNamesShown = 8;

    private bool _bulkRunning;

    /// <summary>Connect All on <paramref name="folder"/> (null: the whole library).</summary>
    private Task ConnectAllAsync(TreeItem? folder) => RunBulkAsync(folder, reconnecting: null);

    /// <summary>Reconnect All: ends the folder's open sessions, then connects those same connections by Connect All's rules.</summary>
    private Task ReconnectAllAsync(TreeItem? folder)
    {
        var open = OpenConnectionIds().Intersect(ConnectionIdsUnder(folder)).ToHashSet();
        return open.Count == 0 ? Task.CompletedTask : RunBulkAsync(folder, open);
    }

    private HashSet<string> OpenConnectionIds() => _tabs.Select(t => t.ConnectionId).OfType<string>().ToHashSet();

    private async Task RunBulkAsync(TreeItem? folder, HashSet<string>? reconnecting)
    {
        if (_bulkRunning || !await ConfirmVaultOpenAsync()) return;
        ConnectAllPlanDto plan;
        try { plan = OpenCredentials().PlanConnectAll(_library, folder?.Id, reconnecting is null ? OpenConnectionIds() : []); }
        catch (BastionException ex) { Announce("Connect All: " + ex.Message); return; }
        bool Keep(string id) => reconnecting?.Contains(id) ?? true;
        var ready = plan.Ready.Where(Keep).ToList();
        var needsLogin = plan.NeedsLogin.Where(Keep).ToList();
        // B4-FU1: types the managed policy forbids are never requested, only named.
        var blocked = (plan.SkippedBlocked ?? []).Where(Keep).ToList();
        var blockedText = BlockedText(blocked);
        if (ready.Count + needsLogin.Count == 0) { Announce("Nothing to connect in this folder." + blockedText); return; }
        if (plan.NeedsConfirmation && !await ShowModal($"Connect {ready.Count + needsLogin.Count} connections?",
                Wrapped((needsLogin.Count == 0 ? "All of them open now." : $"{ready.Count} open now. {needsLogin.Count} need a login and wait until you open them.") + blockedText),
                primary: "Connect", cancel: "Cancel")) return;
        _bulkRunning = true;
        try
        {
            if (reconnecting is not null) CloseConnectionTabs(reconnecting); // replaced by the new ones, not kept disconnected
            // B5: one batch per run, so a folder's multi-host hook runs once, not once per host.
            var batch = new HookBatch();
            foreach (var id in ready.Concat(needsLogin)) _hookBatches[id] = batch;
            foreach (var id in ready)
                if (TreeItem.Find(_roots, id) is { } item) await ConnectAsync(item);
            Announce($"Connect All: opened {ready.Count}");
            if (needsLogin.Count == 0 && blocked.Count == 0) return;
            var opened = $"Opened {ready.Count}.";
            if (needsLogin.Count == 0)
            {
                await ShowModal("Connect All", Wrapped(opened + blockedText + " Your administrator's policy does not allow that type."), primary: "OK", cancel: null);
                return;
            }
            var text = $"{opened} {needsLogin.Count} {(needsLogin.Count == 1 ? "needs" : "need")} a login: {NameList(needsLogin)}.{blockedText}"
                + " They have no login of their own, so none was used without asking.";
            if (!await ShowModal("Connect All", Wrapped(text), primary: "Open One by One", cancel: "Not Now")) return;
            foreach (var id in needsLogin)
                if (TreeItem.Find(_roots, id) is { } item) await ConnectAsync(item, askLogin: true);
        }
        finally
        {
            _bulkRunning = false;
            // A connect that never reached after-connect leaves its entry; the next single connect must not reuse it.
            foreach (var id in ready.Concat(needsLogin)) _hookBatches.Remove(id);
        }
    }

    /// <summary>" 2 blocked by policy: a, b." or "" when none.</summary>
    private string BlockedText(IReadOnlyList<string> blocked) =>
        blocked.Count == 0 ? "" : $" {blocked.Count} blocked by policy: {NameList(blocked)}.";

    /// <summary>The first names, then "and N more".</summary>
    private string NameList(IReadOnlyList<string> ids)
    {
        var names = ids.Select(id => TreeItem.Find(_roots, id)?.Name ?? id).ToList();
        var more = names.Count > BulkNamesShown ? $", and {names.Count - BulkNamesShown} more" : "";
        return string.Join(", ", names.Take(BulkNamesShown)) + more;
    }

    private static TextBlock Wrapped(string text)
    {
        var t = Ui.Text(text, "BodyTextStyle");
        t.TextWrapping = TextWrapping.Wrap;
        t.MaxWidth = 420;
        return t;
    }
}
