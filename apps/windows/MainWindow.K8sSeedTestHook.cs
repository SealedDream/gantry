#if BASTION_TEST_HOOKS
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// PLUG-K8S-01 Windows suite seam (tests\k8s01-win-ui-test.ps1). Test-hooks builds only. With BASTION_UITEST_K8S_SEED=port
/// and a test library, it installs the Kubernetes fixture (BASTION_UITEST_PLUGIN_PATH), puts one synthetic bearer token in
/// the vault ("test-k8s", not a secret), and adds the entry "k8s-mock" at 127.0.0.1:port with that login and the mock
/// server's certificate pinned, so the suite needs no vault or trust UI.
/// </summary>
public sealed partial class MainWindow
{
    private void SeedK8sForTest(int port)
    {
        if (TestHooks.LibraryOverride is null || TestHooks.PluginInstallPath is not { } fixture) return; // never the user's own library
        try
        {
            if (Flatten(_roots).Any(i => i.Connection?.Name == "k8s-mock")) return;
            PluginClient.InstallFile(SessionDataDir, fixture, allowUnverified: true);
            _pluginTypes = null;
            var type = PluginTypes.First(t => t.Id.EndsWith("/k8s", StringComparison.Ordinal));
            var credentialId = OpenCredentials().SavePassword(null, "k8s test token", null, "token", "test-k8s");
            OpenCredentials().Save();
            var id = PluginEntryClient.Add(_library, SessionDataDir, null, "k8s-mock", "127.0.0.1", type.Id);
            _library.SetProperty(id, "port", port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            _library.SetCredential(id, credentialId);
            PluginEntryClient.SetTls(_library, id, "pinned", PluginEntryClient.ProbeCertificate("127.0.0.1", port));
            _library.Save();
            Reload(id);
        }
        catch (Exception ex) when (ex is BastionException or InvalidOperationException)
        {
            CrashLog.Write(ex);
        }
    }
}
#endif
