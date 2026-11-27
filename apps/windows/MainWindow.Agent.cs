using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// More options → SSH Agent… (as Native Mac's View → SSH Agent): Bastion's own agent on an owner-only named pipe
/// (C ABI 60/83). Keys are added from files for this app session only and never copied by Bastion; the core checks
/// each key and, with "Confirm each use", asks before every signature. While it runs, SSH_AUTH_SOCK points local
/// shells (Windows OpenSSH, git) at the pipe. The same dialog generates ed25519 keys (core key manager) and saves
/// them owner-only.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>How long a confirm prompt waits before the signature is refused.</summary>
    private static readonly TimeSpan AgentConfirmTimeout = TimeSpan.FromSeconds(60);

    private sealed record AgentEntry(string Path, string? Passphrase, KeyInfoDto Info);

    private readonly List<AgentEntry> _agentKeys = new();
    private SshAgent? _agent;
    private bool _agentConfirm;

    private static string AgentPipe => $@"\\.\pipe\bastion-agent-{Environment.UserName}";

    private void SshAgent_Click(object sender, RoutedEventArgs e) => _ = ShowAgentAsync();

    /// <summary>Restarts the core agent with the current key list (the core takes the list at start).</summary>
    private void RestartAgent()
    {
        _agent?.Dispose();
        _agent = null;
        Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", null);
        if (_agentKeys.Count == 0) return;
        var keys = _agentKeys.Select(k => new AgentKey(File.ReadAllText(k.Path), k.Passphrase)).ToList();
        _agent = SshAgent.Start(AgentPipe, keys, _agentConfirm ? ConfirmAgentUse : null);
        Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", _agent.Socket);
    }

    /// <summary>Runs on a core thread: asks on the UI thread and blocks until the answer, refusing on timeout.</summary>
    private bool ConfirmAgentUse(string comment, string fingerprint)
    {
        var answer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var queued = DispatcherQueue.TryEnqueue(async () =>
        {
            try
            {
                var who = comment.Length > 0 ? comment : "a key";
                var body = Ui.Text($"A program asks to sign with {who}.", "BodyTextBlockStyle");
                answer.TrySetResult(await ShowModal("Allow SSH agent use?", body, primary: "Allow", cancel: "Deny", caption: fingerprint, focusCancel: true));
            }
            catch (Exception) { answer.TrySetResult(false); }
        });
        return queued && answer.Task.Wait(AgentConfirmTimeout) && answer.Task.Result;
    }

    private async Task ShowAgentAsync()
    {
        var list = new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = Ui.Double("DialogWidth") / 2 };
        AutomationProperties.SetName(list, "Agent keys");
        var status = Ui.Text("", "CaptionTextStyle");
        AutomationProperties.SetAutomationId(status, "AgentStatus");
        var path = new TextBox { Header = "Key file", PlaceholderText = @"C:\Users\you\.ssh\id_ed25519" };
        AutomationProperties.SetName(path, "Key file path");
        var pass = new PasswordBox { Header = "Passphrase (if the key is encrypted)" };
        AutomationProperties.SetName(pass, "Key passphrase");
        var confirm = new CheckBox { Content = "Confirm each use", IsChecked = _agentConfirm };
        AutomationProperties.SetName(confirm, "Confirm each use");
        var add = AgentButton("Add key", "Add key");
        var remove = AgentButton("Remove", "Remove key");
        var removeAll = AgentButton("Remove all", "Remove all keys");
        var generate = AgentButton("Generate key…", "Generate key");
        var convert = AgentButton("Convert key…", "Convert key");

        void Reload(string? message = null)
        {
            list.Items.Clear();
            foreach (var k in _agentKeys)
            {
                var label = $"{k.Info.Comment}  {k.Info.Algorithm} {k.Info.Fingerprint}";
                var item = new ListViewItem { Content = label, Tag = k };
                AutomationProperties.SetName(item, label);
                list.Items.Add(item);
            }
            status.Text = message ?? (_agent is null
                ? "No keys. Add a key file to serve it to ssh, git and other tools."
                : $"Serving {_agentKeys.Count} key(s) on {_agent.Socket}. Local shells get SSH_AUTH_SOCK.");
            AutomationProperties.SetName(status, status.Text); // a TextBlock's UIA name does not follow later Text changes here
            remove.IsEnabled = removeAll.IsEnabled = _agentKeys.Count > 0;
        }
        void Apply(Action change, Action undo, string failure)
        {
            change();
            try { RestartAgent(); Reload(); }
            catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException)
            {
                undo();
                try { RestartAgent(); } catch (Exception again) when (again is BastionException or IOException or UnauthorizedAccessException) { _agent = null; }
                Reload($"{failure}: {ex.Message}");
            }
        }
        add.Click += (_, _) =>
        {
            var file = path.Text.Trim().Trim('"');
            if (file.Length == 0 || !File.Exists(file)) { Reload("Choose an existing private key file."); return; }
            var phrase = pass.Password.Length > 0 ? pass.Password : null;
            KeyInfoDto info;
            try { info = KeyManager.Inspect(File.ReadAllText(file), phrase); }
            catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException) { Reload(ex.Message); return; }
            if (_agentKeys.Any(k => k.Info.Fingerprint == info.Fingerprint)) { Reload("That key is already in the agent."); return; }
            var entry = new AgentEntry(file, phrase, info);
            Apply(() => _agentKeys.Add(entry), () => _agentKeys.Remove(entry), "The agent did not start");
            path.Text = ""; pass.Password = "";
        };
        remove.Click += (_, _) =>
        {
            if (list.SelectedItem is not ListViewItem { Tag: AgentEntry k }) { Reload("Choose a key to remove."); return; }
            var at = _agentKeys.IndexOf(k);
            Apply(() => _agentKeys.Remove(k), () => _agentKeys.Insert(at, k), "The agent did not restart");
        };
        removeAll.Click += (_, _) =>
        {
            var before = _agentKeys.ToList();
            Apply(() => _agentKeys.Clear(), () => _agentKeys.AddRange(before), "The agent did not stop");
        };
        confirm.Click += (_, _) =>
        {
            var was = _agentConfirm;
            Apply(() => _agentConfirm = confirm.IsChecked == true, () => { _agentConfirm = was; confirm.IsChecked = was; }, "The agent did not restart");
        };
        generate.Click += (_, _) => _ = GenerateKeyAsync();
        convert.Click += (_, _) => _ = ConvertKeyAsync(path.Text.Trim().Trim('"'));

        Reload();
        // Two short rows so the buttons stay inside a 640 px window.
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { add, remove, removeAll } };
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { list, status, path, pass, confirm, row,
            new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { generate, convert } } } };
        await ShowModal("SSH Agent", body, primary: "Done", cancel: null, focus: path, wide: true);
    }

    private static Button AgentButton(string text, string name)
    {
        var b = new Button { Content = text };
        AutomationProperties.SetName(b, name);
        return b;
    }

    /// <summary>Generates an ed25519 key in the core and saves it owner-only (private) plus a .pub beside it.</summary>
    private async Task GenerateKeyAsync()
    {
        var sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
        var file = new TextBox { Header = "Save as", Text = Path.Combine(sshDir, "id_ed25519_bastion") };
        AutomationProperties.SetName(file, "New key file");
        var comment = new TextBox { Header = "Comment", Text = $"{Environment.UserName}@{Environment.MachineName}" };
        AutomationProperties.SetName(comment, "New key comment");
        var pass = new PasswordBox { Header = "Passphrase (empty = unencrypted)" };
        AutomationProperties.SetName(pass, "New key passphrase");
        var error = Ui.Text("", "CaptionTextStyle");
        bool Validate()
        {
            var target = file.Text.Trim();
            if (target.Length == 0) { error.Text = "Enter a file name."; return false; }
            if (File.Exists(target) || File.Exists(target + ".pub")) { error.Text = "That file exists. Gantry never overwrites a key."; return false; }
            return true;
        }
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { file, comment, pass, error } };
        if (!await ShowModal("Generate SSH key", body, primary: "Generate", cancel: "Cancel", validate: Validate, focus: file)) return;
        try
        {
            var key = KeyManager.Generate(comment.Text.Trim(), pass.Password.Length > 0 ? pass.Password : null);
            var target = file.Text.Trim();
            WriteOwnerOnly(target, key.PrivateOpenssh ?? throw new BastionException("the key manager returned no private key"));
            File.WriteAllText(target + ".pub", key.PublicOpenssh + "\n");
            await ShowModal("Key generated", Ui.Text(key.PublicOpenssh, "BodyTextBlockStyle"), primary: "OK", cancel: null, caption: $"{key.Algorithm} {key.Fingerprint}");
        }
        catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException)
        {
            await ShowModal("Key not generated", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>Converts a PEM, PuTTY .ppk or OpenSSH key to OpenSSH in the core and saves it owner-only plus a .pub beside it.</summary>
    private async Task ConvertKeyAsync(string suggested)
    {
        var sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
        var source = new TextBox { Header = "Key file (PEM, PuTTY .ppk, OpenSSH)", Text = suggested };
        AutomationProperties.SetName(source, "Key to convert");
        var pass = new PasswordBox { Header = "Passphrase (if encrypted)" };
        AutomationProperties.SetName(pass, "Key to convert passphrase");
        var file = new TextBox { Header = "Save as", Text = Path.Combine(sshDir, "id_converted") };
        AutomationProperties.SetName(file, "Converted key file");
        var comment = new TextBox { Header = "Comment (empty = keep)" };
        AutomationProperties.SetName(comment, "Converted key comment");
        var newPass = new PasswordBox { Header = "New passphrase (empty = unencrypted)" };
        AutomationProperties.SetName(newPass, "Converted key passphrase");
        var error = Ui.Text("", "CaptionTextStyle");
        bool Validate()
        {
            var src = source.Text.Trim().Trim('"');
            var target = file.Text.Trim();
            if (src.Length == 0 || !File.Exists(src)) { error.Text = "Choose an existing private key file."; return false; }
            if (target.Length == 0) { error.Text = "Enter a file name."; return false; }
            if (File.Exists(target) || File.Exists(target + ".pub")) { error.Text = "That file exists. Gantry never overwrites a key."; return false; }
            return true;
        }
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { source, pass, file, comment, newPass, error } };
        if (!await ShowModal("Convert SSH key", body, primary: "Convert", cancel: "Cancel", validate: Validate, focus: source)) return;
        try
        {
            var key = KeyManager.Convert(File.ReadAllText(source.Text.Trim().Trim('"')), pass.Password.Length > 0 ? pass.Password : null,
                newPass.Password.Length > 0 ? newPass.Password : null, comment.Text.Trim());
            var target = file.Text.Trim();
            WriteOwnerOnly(target, key.PrivateOpenssh ?? throw new BastionException("the key manager returned no private key"));
            File.WriteAllText(target + ".pub", key.PublicOpenssh + "\n");
            await ShowModal("Key converted", Ui.Text(key.PublicOpenssh, "BodyTextBlockStyle"), primary: "OK", cancel: null, caption: $"{key.Algorithm} {key.Fingerprint}");
        }
        catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException)
        {
            await ShowModal("Key not converted", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>Creates <paramref name="path"/> readable only by the current user (as OpenSSH requires), never replacing a file.</summary>
    private static void WriteOwnerOnly(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var me = WindowsIdentity.GetCurrent().User ?? throw new UnauthorizedAccessException("no current user");
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, AccessControlType.Allow));
        using var stream = new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, acl);
        using var writer = new StreamWriter(stream);
        writer.Write(text);
    }
}
