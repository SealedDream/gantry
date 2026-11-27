#if BASTION_TEST_HOOKS
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// PLUG-VMW-01 Windows suite seam (tests\vmw01-menus-win-ui-test.ps1). Test-hooks builds only. With BASTION_UITEST_VMW_SEED=port
/// and a test library, it installs the VMware fixture (BASTION_UITEST_PLUGIN_PATH), puts one synthetic login in the vault
/// ("test-vmw", not a secret, like the PVE seed), and adds the entry "vc-mock" at 127.0.0.1:port with that login and the
/// mock server's certificate pinned. With BASTION_UITEST_VMW_SEED_TYPE=esxi (VMW-ESXI) the entry is "esxi-mock" of the
/// standalone ESXi type, login user "root", for tests\vmw-esxi-win-ui-test.ps1 and tests\mock-esxi.ps1.
/// </summary>
public sealed partial class MainWindow
{
    private void SeedVmwForTest(int port)
    {
        if (TestHooks.LibraryOverride is null || TestHooks.PluginInstallPath is not { } fixture) return; // never the user's own library
        try
        {
            var esxi = TestHooks.VmwSeedEsxi;
            var (name, typeSuffix, user) = esxi ? ("esxi-mock", "/esxi", "root") : ("vc-mock", "/vcenter", "uitest@vsphere.local");
            if (Flatten(_roots).Any(i => i.Connection?.Name == name)) return;
            PluginClient.InstallFile(SessionDataDir, fixture, allowUnverified: true);
            _pluginTypes = null;
            var type = PluginTypes.First(t => t.Id.EndsWith(typeSuffix, StringComparison.Ordinal));
            var credentialId = OpenCredentials().SavePassword(null, "vmw test login", null, user, "test-vmw");
            OpenCredentials().Save();
            var id = PluginEntryClient.Add(_library, SessionDataDir, null, name, "127.0.0.1", type.Id);
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
