using System.Text.Json.Nodes;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// PLUG-OPEN-WIN: a plugin's confirmed request to open SSH, RDP or VNC (the Windows port of the Mac's open path, #1371).
/// The core sends <c>open-go</c> only after its checks and the user's yes in the tab's open sheet. The connection then
/// goes through the normal Connect flow (sign-in, host key, certificate, policy and offline checks), as Quick Connect
/// does: an unsaved one-connection library, or, with "Save as a library entry", a new entry beside the plugin entry.
/// No credential is copied; the plugin entry's login is never reused.
/// </summary>
public sealed partial class MainWindow
{
    private void WatchPluginOpens(PluginTabView view, string entryId)
    {
        view.Model.OpenApproved += go => _ = OpenFromPluginAsync(view, entryId, go);
        view.Model.LibraryRequested += r => _ = SaveFromPluginAsync(view.Model, r);
        WatchPluginFiles(view.Model);
        WatchPluginExec(view.Model, entryId);
    }

    /// <summary>Plugin API 1.5: a declared command on the plugin entry, over its own SSH login and route, with the login
    /// an SSH tab would use without asking. The core built and checked the command; this only runs it.</summary>
    private void WatchPluginExec(PluginViewModel model, string entryId)
    {
        var running = new Dictionary<int, PluginExecCancel>();
        model.ExecCancelled += request => { lock (running) { if (running.Remove(request, out var c)) c.Cancel(); } };
        model.ExecRequested += (request, command, ms) => _ = RunPluginExecAsync(model, entryId, request, command, ms, running);
        model.ExecTerminalRequested += (request, command, label) => _ = OpenPluginExecTerminalAsync(model, entryId, request, command, label);
    }

    private async Task RunPluginExecAsync(PluginViewModel model, string entryId, int request, string command, ulong ms, Dictionary<int, PluginExecCancel> running)
    {
        var library = _library;
        var cancel = new PluginExecCancel();
        lock (running) running[request] = cancel;
        try
        {
            var logins = await SavedLoginsAsync(library, entryId, passwordsOnly: false);
            if (logins.FirstOrDefault(l => l.Login.AutoUse) is not { } saved)
            {
                model.AnswerExec(request, new JsonObject { ["exit"] = null, ["error"] = "No saved login for this entry: add one in its properties." });
                return;
            }
            Sessions.SetCredentials(OpenCredentials());
            var user = string.IsNullOrWhiteSpace(saved.Login.Username) ? null : saved.Login.Username;
            var sessions = Sessions;
            var result = await Task.Run(() => PluginExecClient.Run(sessions, library, entryId, user, SshLoginKind.Vault, saved.Credential.Id, command, ms, cancel));
            model.AnswerExec(request, result);
        }
        catch (BastionException ex)
        {
            model.AnswerExec(request, new JsonObject { ["exit"] = null, ["error"] = ex.Message });
        }
        catch (Exception ex)
        {
            CrashLog.Write(ex); // never swallowed: the plugin gets an answer either way
            model.AnswerExec(request, new JsonObject { ["exit"] = null, ["error"] = "The command did not run: " + ex.GetType().Name + "." });
        }
        finally
        {
            lock (running) running.Remove(request);
            cancel.Dispose();
        }
    }

    /// <summary>Opens the terminal tab, then tells the plugin whether it really opened. Every failure (the core refusing,
    /// the connect stopping early, an exception) reaches the plugin as "not opened" with the reason in the tab's message
    /// bar and the app log; nothing is swallowed. Mac: BastionApp.swift openExecTerminal.</summary>
    private async Task OpenPluginExecTerminalAsync(PluginViewModel model, string entryId, int request, string command, string label)
    {
        void Fail(string reason)
        {
            AppLog.Warn("Plugin exec terminal: not opened: " + reason);
            model.Message = reason;
            model.AnswerExecTerminal(request, false);
            model.Refresh();
        }
        try
        {
            var lib = PluginExecClient.TerminalLibrary(_library, entryId, command, label);
            var before = _tabs.ToHashSet();
            await ConnectQuickAsync(lib);
            if (_tabs.FirstOrDefault(t => !before.Contains(t)) is { } opened)
            {
                // The plugin's label names the tab, as on the Mac (a connect from another library is titled user@host).
                if (!string.IsNullOrWhiteSpace(label)) ShowTabTitle(opened, label.Trim());
                AppLog.Info("Plugin exec terminal: opened");
                model.AnswerExecTerminal(request, true);
            }
            else
            {
                Fail(_modal is not null ? "The terminal did not open: another dialog is open." : _connecting ? "The terminal did not open: another connection is starting." : "The terminal did not open.");
            }
        }
        catch (BastionException ex)
        {
            Fail(ex.Message);
        }
        catch (Exception ex)
        {
            CrashLog.Write(ex);
            Fail("The terminal did not open: " + ex.GetType().Name + ".");
        }
    }

    /// <summary>A plugin's Copy and Export (PG-LIVE): the clipboard text and the save picker. The core checks the grant and
    /// that the user just asked; the core writes the file to the path picked here.</summary>
    private void WatchPluginFiles(PluginViewModel model)
    {
        model.ClipboardText += text =>
        {
            var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
            data.SetText(text);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
        };
        model.SaveRequested += (request, name) => _ = SavePluginFileAsync(model, request, name);
    }

    private async Task SavePluginFileAsync(PluginViewModel model, int request, string name)
    {
        string? path = null;
        try
        {
            if (TestHooks.ExportPath is { } fixedPath) path = fixedPath;
            else
            {
                var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = Path.GetFileNameWithoutExtension(name) };
                var ext = Path.GetExtension(name);
                picker.FileTypeChoices.Add(ext.Length > 1 ? ext[1..].ToUpperInvariant() + " file" : "File", new List<string> { ext.Length > 1 ? ext : ".txt" });
                WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
                path = (await picker.PickSaveFileAsync())?.Path;
            }
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException or ArgumentException)
        {
            AppLog.Warn($"Plugin save: the picker failed ({ex.GetType().Name})");
        }
        model.AnswerSave(request, path);
    }

    private async Task OpenFromPluginAsync(PluginTabView view, string entryId, PluginViewModel.OpenGo go)
    {
        AppLog.Info($"Plugin open: {go.Protocol} go-ahead, route {(go.ViaEntryRoute ? "entry" : "direct")}, save {go.SaveAsEntry}");
        try
        {
            var host = go.Host;
            if (go.CheckResolved)
            {
                // A name on a direct route: resolve once, check every address, connect to the first (no second lookup).
                var (h, p, lo) = (go.Host, go.Port, go.LoopbackOk);
                var ips = await Task.Run(() => PluginEntryClient.OpenResolve(h, p, lo));
                if (ips.Count == 0) return;
                host = ips[0];
            }
            if (go.SaveAsEntry)
            {
                // Saved entries keep the name the user confirmed; a later connect resolves it like any entry.
                var id = PluginEntryClient.OpenSave(_library, entryId, go.Protocol, go.Host, go.Port, go.Label, go.ViaEntryRoute);
                ReloadThenSave(id);
                if (TreeItem.Find(_roots, id) is { } saved) await ConnectAsync(saved);
                return;
            }
            var lib = PluginEntryClient.OpenLibrary(_library, entryId, go.Protocol, host, go.Port, go.Label, go.ViaEntryRoute);
            await ConnectQuickAsync(lib);
        }
        catch (BastionException ex)
        {
            view.Model.Message = ex.Message;
            view.Model.Refresh();
        }
    }
}
