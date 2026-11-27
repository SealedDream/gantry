using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Check for Updates (core update::github over C ABI 24). The core checks the release's Ed25519-signed manifest (signature,
// expiry, channel, no downgrade, allowed hosts) and each file's size and SHA-256; this side only picks the Windows zip,
// unpacks it next to the download and hands over to a small script that waits for Gantry to exit, copies the new files over
// the install folder and starts it again. An installation made by the Inno setup (unins000.exe next to Gantry.exe) instead
// downloads the release's setup exe and runs it silently in the same install mode (/CURRENTUSER, or /ALLUSERS with an admin
// prompt), so Settings > Apps, shortcuts and the uninstaller stay right. The build is unsigned, so Windows may show
// SmartScreen on that first start.
public sealed partial class MainWindow
{
    private bool _updateBusy;

    private void CheckForUpdates_Click(object sender, RoutedEventArgs e) => _ = OverSettingsAsync(CheckForUpdatesAsync);

    /// <summary>The release file for this machine, e.g. <c>Gantry-windows-x64.zip</c>.</summary>
    internal static string UpdateAssetName() =>
        $"Gantry-windows-{RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}.zip";

    internal async Task CheckForUpdatesAsync()
    {
        if (_updateBusy) return;
        _updateBusy = true;
        try
        {
            // Offline mode (BASTION_OFFLINE=1): say so at once, without a trip into the core (the overnight run on
            // 9a6e126f6 showed no notice at all within 8 s). The core's own refusal below stays as the second guard.
            if (Offline.IsOn) { await ShowOfflineUpdateNotice(); return; }
            UpdateCheckDto info;
            try { info = await Task.Run(UpdateClient.Check); }
            catch (BastionException ex) when (Offline.IsOfflineError(ex.Message))
            {
                await ShowOfflineUpdateNotice(); // refused before any packet; not a failure to report
                return;
            }
            catch (BastionException ex) { await ShowModal("Could not check for updates", CodedErrorText("UPD", ex.Message), primary: "OK", cancel: null); return; }
            // Any other failure (unreadable reply) must still answer the user: this runs fire-and-forget, so an escaping
            // exception showed no dialog at all (manifestExpires arrived as a number, the DTO said string).
            catch (Exception ex) when (ex is System.Text.Json.JsonException or NotSupportedException or InvalidOperationException)
            {
                await ShowModal("Could not check for updates", ErrorText("The update information could not be read: " + ex.Message), primary: "OK", cancel: null);
                return;
            }
            if (!info.Available)
            {
                await ShowModal("Gantry is up to date", Ui.Text($"Installed: {info.Installed}\nLatest release: {info.Latest}", "BodyTextBlockStyle"), primary: "OK", cancel: null);
                return;
            }
            var install = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            var viaSetup = IsSetupInstall(install);
            var asset = viaSetup ? SetupAssetName(info.Latest) : UpdateAssetName();
            if (info.Files.All(f => f.Name != asset))
            {
                await ShowModal("No Windows download in this release",
                    ErrorText($"Gantry {info.Latest} is available, but its release has no {asset}. Download it from {info.Url ?? "the release page"}."), primary: "OK", cancel: null);
                return;
            }
            if (!await ShowModal($"Update to Gantry {info.Latest}?", UpdateBody(info), primary: "Download and restart", cancel: "Not now", wide: true)) return;
            string restartArgs;
            try { restartArgs = await Task.Run(() => viaSetup ? StageSetupUpdate(asset, install) : StageUpdate(asset)); }
            catch (Exception ex) when (ex is BastionException or IOException or InvalidDataException or UnauthorizedAccessException)
            {
                await ShowModal("Could not install the update", CodedErrorText("UPD", ex.Message), primary: "OK", cancel: null);
                return;
            }
            Process.Start(new ProcessStartInfo("cmd.exe", restartArgs) { CreateNoWindow = true, UseShellExecute = false });
            FlushLibrarySaves(); // the update restart must not drop a queued save
            Application.Current.Exit();
        }
        finally { _updateBusy = false; }
    }

    private Task<bool> ShowOfflineUpdateNotice() =>
        ShowModal(Offline.UpdateTitle, Ui.Text("Offline mode is on, so Gantry does not contact the update server.", "BodyTextBlockStyle"), primary: "OK", cancel: null);

    private static StackPanel UpdateBody(UpdateCheckDto info)
    {
        var body = new StackPanel { Spacing = Ui.Double("Space8") };
        body.Children.Add(LabelValue("Installed", info.Installed));
        body.Children.Add(LabelValue("New version", info.Latest));
        if (!string.IsNullOrWhiteSpace(info.Notes))
        {
            var notes = Ui.Text(info.Notes!, "BodyTextBlockStyle");
            notes.TextWrapping = TextWrapping.Wrap;
            notes.IsTextSelectionEnabled = true;
            body.Children.Add(new ScrollViewer { Content = notes, MaxHeight = Ui.Double("DialogWidth") / 2 });
        }
        var how = Ui.Text("Gantry downloads the signed release, checks it, closes and starts the new version. "
            + "This build is not code-signed: if Windows SmartScreen appears, choose More info → Run anyway.", "CaptionSecondaryTextStyle");
        how.TextWrapping = TextWrapping.Wrap;
        body.Children.Add(how);
        return body;
    }

    /// <summary>The Inno setup leaves its uninstaller next to Gantry.exe; the portable zip has none.</summary>
    internal static bool IsSetupInstall(string install) => File.Exists(Path.Combine(install, "unins000.exe"));

    /// <summary>The release's setup exe for <paramref name="version"/> (scripts/package-release.sh names it so).</summary>
    internal static string SetupAssetName(string version) => $"Gantry-{version}-windows-x64-setup.exe";

    /// <summary>A per-user install lives under %LOCALAPPDATA% (Inno {autopf} without admin); anything else is all users.</summary>
    internal static bool IsPerUserInstall(string install) =>
        install.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Download the verified setup exe and write a script that waits for this process, runs the setup silently into the same
    /// folder and install mode, and starts Gantry again (the old one when the setup failed, with the failure marker).
    /// </summary>
    private static string StageSetupUpdate(string asset, string install)
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Gantry-update-" + Guid.NewGuid().ToString("N"))).FullName;
        var setup = UpdateClient.Download(asset, root);
        // The verified exe waits in a user-writable folder until this process exits (SEC-REVIEW-01): pin its hash now and
        // have the script re-check it right before starting it, so a swapped file is never run (or elevated for /ALLUSERS).
        string sha;
        using (var fs = File.OpenRead(setup)) sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
        var gantry = Path.Combine(install, "Gantry.exe");
        var mode = IsPerUserInstall(install) ? "/CURRENTUSER" : "/ALLUSERS";
        var pid = Environment.ProcessId;
        var script = Path.Combine(root, "run-setup.cmd");
        // "backup" marks the folder as used, so the next start removes it (FinishPendingUpdate).
        Directory.CreateDirectory(Path.Combine(root, "backup"));
        File.WriteAllLines(script, new[]
        {
            "@echo off",
            ":wait",
            $"tasklist /FI \"PID eq {pid}\" /NH | find \"{pid}\" >nul && (timeout /t 1 /nobreak >nul & goto wait)",
            $"powershell.exe -NoProfile -NonInteractive -Command \"if ((Get-FileHash -Algorithm SHA256 -LiteralPath '{setup.Replace("'", "''")}').Hash -ne '{sha}') {{ exit 3 }}\"",
            $"if errorlevel 1 (> \"{UpdateFailureMarker}\" echo The update was not installed: the downloaded setup changed after it was verified. The previous version is still installed. & start \"\" \"{gantry}\" & exit /b 1)",
            $"\"{setup}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS {mode} /DIR=\"{install}\"",
            $"if errorlevel 1 > \"{UpdateFailureMarker}\" echo The update was not installed: the setup ended with code %errorlevel%. The previous version is still installed; the setup is kept in {root}.",
            $"start \"\" \"{gantry}\"",
        });
        return $"/c \"\"{script}\"\"";
    }

    /// <summary>The swap script shipped next to Gantry.exe (update-apply.cmd: backup, copy, roll back on failure).</summary>
    internal const string UpdateScriptName = "update-apply.cmd";

    /// <summary>Written by update-apply.cmd when the swap failed and the previous version was restored.</summary>
    internal static string UpdateFailureMarker => Path.Combine(Path.GetTempPath(), "Gantry-update-failed.txt");

    /// <summary>
    /// At startup (Codex W06): a Gantry that got this far launched, so earlier update folders (download, staging and
    /// the pre-update backup) are no longer needed; a failure marker from the last swap is shown once.
    /// </summary>
    private void FinishPendingUpdate()
    {
        foreach (var dir in Directory.EnumerateDirectories(Path.GetTempPath(), "Gantry-update-*"))
        {
            // Only folders a swap already used (it made a backup) or stale ones: another Gantry may be downloading.
            var swapped = Directory.Exists(Path.Combine(dir, "backup"));
            if (!swapped && Directory.GetCreationTimeUtc(dir) > DateTime.UtcNow.AddDays(-1)) continue;
            try { Directory.Delete(dir, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* in use: next start */ }
        }
        string message;
        try
        {
            if (!File.Exists(UpdateFailureMarker)) return;
            message = File.ReadAllText(UpdateFailureMarker).Trim();
            File.Delete(UpdateFailureMarker);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }
        DispatcherQueue.TryEnqueue(() => _ = ShowModal("The update was not installed", ErrorText(message), primary: "OK", cancel: null));
    }

    /// <summary>Download and unpack the update; returns the cmd.exe arguments that run the swap once this process exits.</summary>
    private static string StageUpdate(string asset)
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Gantry-update-" + Guid.NewGuid().ToString("N"))).FullName;
        var zip = UpdateClient.Download(asset, root);
        var staging = Path.Combine(root, "files");
        ZipFile.ExtractToDirectory(zip, staging); // refuses entries that would land outside staging
        // The zip may hold the files directly or inside one top folder.
        if (!File.Exists(Path.Combine(staging, "Gantry.exe")) && Directory.GetDirectories(staging) is [var only] && Directory.GetFiles(staging).Length == 0)
            staging = only;
        if (!File.Exists(Path.Combine(staging, "Gantry.exe"))) throw new InvalidDataException($"{asset} does not contain Gantry.exe");
        var install = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var pid = Environment.ProcessId;
        // Run a copy from %TEMP%: the swap overwrites the install folder, and cmd reads a script as it goes.
        var shipped = Path.Combine(install, UpdateScriptName);
        if (!File.Exists(shipped)) throw new InvalidDataException($"{UpdateScriptName} is missing from {install}; reinstall Gantry from the release page.");
        var script = Path.Combine(Path.GetTempPath(), $"Gantry-update-{pid}.cmd");
        File.Copy(shipped, script, overwrite: true);
        return $"/c \"\"{script}\" {pid} \"{staging}\" \"{install}\" \"{root}\" \"{UpdateFailureMarker}\"\"";
    }
}
