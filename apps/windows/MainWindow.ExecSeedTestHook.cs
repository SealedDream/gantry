#if BASTION_TEST_HOOKS
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// PLUG-EXEC-01 Windows suite seam (tests\plugexec-win-ui-test.ps1). Test-hooks builds only. With
/// BASTION_UITEST_EXEC_SEED = host:port:user and a test library, it installs the exec fixture (BASTION_UITEST_PLUGIN_PATH),
/// saves the lab SSH key from BASTION_UITEST_EXEC_KEY_FILE as the login, and adds the entry "exec-lab" with that login and
/// "Allow changes" off, or on with BASTION_UITEST_EXEC_ALLOW=1. Nothing is logged but the exception type.
/// </summary>
public sealed partial class MainWindow
{
    private void SeedExecForTest(string seed)
    {
        if (TestHooks.LibraryOverride is null || TestHooks.PluginInstallPath is not { } fixture || TestHooks.ExecKeyFile is not { } keyFile) return;
        var parts = seed.Split(':');
        if (parts.Length != 3 || !int.TryParse(parts[1], out var port)) return;
        try
        {
            if (Flatten(_roots).Any(i => i.Connection?.Name == "exec-lab")) return;
            PluginClient.InstallFile(SessionDataDir, fixture, allowUnverified: true);
            _pluginTypes = null;
            // BASTION_UITEST_EXEC_TYPE picks another fixture's type (the Docker suite: com.example.docker/host).
            var typeId = Environment.GetEnvironmentVariable("BASTION_UITEST_EXEC_TYPE") is { Length: > 0 } t0 ? t0 : "com.example.execfixture/host";
            var type = PluginTypes.First(t => t.Id == typeId);
            var credentialId = OpenCredentials().ImportKeyFile(null, "exec-lab key", null, parts[2], keyFile, ""); // the core reads the key file
            OpenCredentials().Save();
            var id = PluginEntryClient.Add(_library, SessionDataDir, null, "exec-lab", parts[0], type.Id);
            _library.SetProperty(id, "port", port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            _library.SetCredential(id, credentialId);
            if (Environment.GetEnvironmentVariable("BASTION_UITEST_EXEC_ALLOW") == "1") PluginEntryClient.SetField(_library, SessionDataDir, id, "allow-changes", "true");
            _library.Save();
            Reload(id);
        }
        catch (Exception ex)
        {
            CrashLog.Write(ex); // any failure, so the suite can show why the entry is missing
        }
    }
}
#endif
