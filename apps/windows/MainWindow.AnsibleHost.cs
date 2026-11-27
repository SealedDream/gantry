using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// Ansible without WSL problems: a check that says what is missing before a WSL run, and the "Control host" mode that
/// runs Ansible on a saved SSH connection. The control host is connected as usual (vault login, host-key rules); on its
/// SSH session SFTP makes the run folder and uploads the inventory and playbook, then the one-line command the core
/// planned (C ABI 90, <c>remote</c>) is typed into the terminal. It checks Ansible exists, runs it and removes the folder.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>How long one WSL check may take.</summary>
    private static readonly TimeSpan WslCheckTimeout = TimeSpan.FromSeconds(15);
    /// <summary>How long a pending control-host run waits for its connect (a login dialog left open).</summary>
    private static readonly TimeSpan ControlHostConnectWait = TimeSpan.FromMinutes(5);

    private readonly Dictionary<string, (DateTime Deadline, Action<TerminalSession> Run)> _afterConnect = new();

    private string ControlHostFile => Path.Combine(SessionDataDir, "ansible-control-host.txt");

    /// <summary>The control host last used with this library, or null.</summary>
    private string? RememberedControlHost()
    {
        try { return File.Exists(ControlHostFile) ? File.ReadAllText(ControlHostFile).Trim() : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private void RememberControlHost(string id)
    {
        try { File.WriteAllText(ControlHostFile, id); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { } // a preference; the run goes on
    }

    /// <summary>Why <paramref name="program"/> cannot run through WSL, as one line with the fix; null when it can.</summary>
    internal static async Task<string?> WslProblemAsync(string program)
    {
        var wsl = Path.Combine(Environment.SystemDirectory, "wsl.exe");
        // Windows 11 ships a wsl.exe stub even without WSL, and it may not answer; look for WSL itself first.
        if (!File.Exists(wsl) || !IsWslInstalled()) return "WSL has no Linux installed. Install: wsl --install";
        var list = await RunQuietAsync(wsl, ["-l", "-q"]);
        if (list is null) return "WSL did not answer. Try again, or run: wsl --status";
        var (code, output) = list.Value;
        var distros = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(l => l.Length > 0).ToList();
        if (code != 0 || distros.Count == 0) return "WSL has no Linux installed. Install: wsl --install";
        var which = await RunQuietAsync(wsl, ["-e", "sh", "-c", "command -v \"$0\"", program]);
        if (which is null) return "WSL did not answer. Try again, or run: wsl --status";
        return which.Value.Code == 0 ? null : $"{program} not found in WSL. Install there: sudo apt install ansible";
    }

    /// <summary>WSL from the Store (<c>Program Files\WSL</c>) or the inbox optional feature (<c>System32\lxss</c>).</summary>
    private static bool IsWslInstalled() =>
        File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WSL", "wsl.exe"))
        || File.Exists(Path.Combine(Environment.SystemDirectory, "lxss", "LxssManager.dll"));

    /// <summary>Run a short check program with no window; null when it times out.</summary>
    private static async Task<(int Code, string Output)?> RunQuietAsync(string exe, IReadOnlyList<string> args)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment["WSL_UTF8"] = "1"; // wsl.exe -l writes UTF-16 otherwise
        try
        {
            using var p = Process.Start(psi);
            if (p is null) return (-1, "");
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            var exited = p.WaitForExitAsync();
            if (await Task.WhenAny(exited, Task.Delay(WslCheckTimeout)) != exited)
            {
                try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                return null;
            }
            return (p.ExitCode, (await stdout + "\n" + await stderr).Replace("\0", ""));
        }
        catch (System.ComponentModel.Win32Exception ex) { return (-1, ex.Message); }
    }

    /// <summary>Connect <paramref name="host"/> and run <paramref name="input"/> there once its terminal is up.</summary>
    private async Task StartOnControlHostAsync(TreeItem host, AnsibleRunInput input, bool uploadFolder)
    {
        RememberControlHost(host.Id);
        var runId = Guid.NewGuid().ToString("N")[..16];
        _afterConnect[host.Id] = (DateTime.UtcNow + ControlHostConnectWait, session => _ = RunOnControlHostAsync(session, host.Name, input, runId, uploadFolder));
        await ConnectAsync(host);
    }

    /// <summary>Called first by the after-connect hooks: a pending control-host run for this connection.</summary>
    private void RunAfterConnect(string connectionId)
    {
        if (!_afterConnect.Remove(connectionId, out var pending) || pending.Deadline < DateTime.UtcNow) return;
        var tab = _tabs.LastOrDefault(t => t.HostColorId == connectionId && t.View is not null);
        if (tab is null || PaneOf(tab) is not { } view || view.Session.IsDisposed) return;
        pending.Run(view.Session);
    }

    private async Task RunOnControlHostAsync(TerminalSession session, string hostName, AnsibleRunInput input, string runId, bool uploadFolder)
    {
        var error = await Task.Run(() =>
        {
            SftpSession? sftp = null;
            string? made = null;
            try
            {
                sftp = SftpSession.Open(session);
                var plan = LibraryClient.AnsiblePlan(input with { Remote = new AnsibleRemoteSpec(sftp.Home(), runId, uploadFolder) });
                var remote = plan.Remote ?? throw new BastionException("the core returned no control-host plan");
                made = remote.Dir;
                foreach (var dir in remote.Dirs) sftp.Mkdir(dir);
                foreach (var u in remote.Uploads) sftp.Upload(u.Local, u.Remote);
                session.Write(remote.Command + "\r");
                return null;
            }
            catch (Exception ex) when (ex is BastionException or IOException or ObjectDisposedException)
            {
                if (made is not null) try { sftp?.Remove(made, isDir: true); } catch (Exception) { } // best effort; the error below matters
                return ex.Message;
            }
            finally { sftp?.Dispose(); }
        });
        if (error is null || _modal is not null) return;
        await ShowModal("Ansible on " + hostName, ErrorText(error), primary: "OK", cancel: null);
    }
}
