using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

// LOG-NATIVE-01 item 7 (Native Windows, as the Mac's Help › Export Diagnostics…): Windows has no menu bar, so the entry
// sits in the Bastion menu and on Settings › About. It asks where to save, writes the zip off the UI thread and says what
// is inside. Only counts leave the library; no transcript is ever read for it.
public sealed partial class MainWindow
{
    private string AppLogPath => Path.Combine(SessionDataDir, "bastion.log");

    /// <summary>Starts the app log next to the library (a test library keeps its own).</summary>
    private void StartAppLog()
    {
        AppLog.Path = AppLogPath;
        AppLog.Redactor = ErrorCodes.Redact;
        AppLog.Info($"Launched {AppVersion} on Windows {Environment.OSVersion.Version}");
        try { ApplyDetailedLog(); }
        catch (BastionException e) { AppLog.Warn("Detailed logging: setting not read: " + e.Message); }
    }

    private static string AppVersion => typeof(MainWindow).Assembly.GetName().Version?.ToString() ?? "dev";

    private DiagnosticsCounts LibraryCounts()
    {
        var folders = 0;
        var connections = 0;
        var byProtocol = new Dictionary<string, int>(StringComparer.Ordinal);
        void Walk(FolderDto f)
        {
            folders += f.Folders.Count;
            foreach (var c in f.Connections)
            {
                connections++;
                byProtocol[c.Protocol] = byProtocol.GetValueOrDefault(c.Protocol) + 1;
            }
            f.Folders.ForEach(Walk);
        }
        try { Walk(_library.Tree()); }
        catch (BastionException) { } // counts are a hint: an unreadable library gives zeros, the export still works
        return new DiagnosticsCounts(folders, connections, byProtocol);
    }

    private DiagnosticsBundle.Inputs DiagnosticsInputs() => new(
        Summary: DiagnosticsBundle.Summary(AppVersion, Environment.OSVersion.Version.ToString(), LibraryCounts(), DateTimeOffset.Now, AppLog.Detailed),
        SettingsPath: SettingsPath,
        Logs: new[] { AppLogPath + ".1", AppLogPath }.Where(File.Exists).ToList(),
        Crash: File.Exists(CrashLog.Path) ? CrashLog.Path : null,
        Home: Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        User: Environment.UserName,
        Machine: Environment.MachineName);

    private void ExportDiagnostics_Click(object sender, RoutedEventArgs e) => _ = ExportDiagnosticsAsync();

    internal async Task ExportDiagnosticsAsync()
    {
        // UI tests give the file (TestHooks.ExportPath, test builds only) instead of the save dialog.
        var path = TestHooks.ExportPath is { } fixedPath ? fixedPath : await PickDiagnosticsFile();
        if (path is null) return;
        var inputs = DiagnosticsInputs();
        string? problem = null;
        try { await Task.Run(() => DiagnosticsBundle.Write(inputs, path)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { problem = ex.Message; }
        if (problem is null)
        {
            AppLog.Info("Exported diagnostics");
            await ShowModal("Diagnostics saved", Ui.Text("Contains " + DiagnosticsBundle.Contents + ".", "BodyTextStyle"), primary: "OK", cancel: null, caption: path);
        }
        else
        {
            AppLog.Error("Diagnostics export failed");
            await ShowModal("Could not export diagnostics", ErrorText(problem), primary: "OK", cancel: null);
        }
    }

    private async Task<string?> PickDiagnosticsFile()
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = $"Gantry diagnostics {DateTime.Now:yyyy-MM-dd}" };
        picker.FileTypeChoices.Add("Zip", new List<string> { ".zip" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        return (await picker.PickSaveFileAsync())?.Path;
    }
}
