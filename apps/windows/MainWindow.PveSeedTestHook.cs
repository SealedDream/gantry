#if BASTION_TEST_HOOKS
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// PLUG-PVE-02 Windows suite seam (tests\pve02-win-ui-test.ps1). Test-hooks builds only. With BASTION_UITEST_PVE_SEED=port
/// and a test library, it installs the Proxmox fixture (BASTION_UITEST_PLUGIN_PATH), puts one synthetic API token in the
/// vault ("test-pve", not a secret, like the B13 seed), and adds the entry "pve-mock" at 127.0.0.1:port with that login
/// and the mock server's certificate pinned, so the suite needs no vault or trust UI.
/// </summary>
public sealed partial class MainWindow
{
    private void SeedPveForTest(int port)
    {
        if (TestHooks.LibraryOverride is null || TestHooks.PluginInstallPath is not { } fixture) return; // never the user's own library
        try
        {
            if (Flatten(_roots).Any(i => i.Connection?.Name == "pve-mock")) return;
            PluginClient.InstallFile(SessionDataDir, fixture, allowUnverified: true);
            _pluginTypes = null;
            var type = PluginTypes.First(t => t.Id.EndsWith("/pve", StringComparison.Ordinal));
            var credentialId = OpenCredentials().SavePassword(null, "pve test token", null, "uitest@pve!bastion", "test-pve");
            OpenCredentials().Save();
            var id = PluginEntryClient.Add(_library, SessionDataDir, null, "pve-mock", "127.0.0.1", type.Id);
            _library.SetProperty(id, "port", port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            _library.SetCredential(id, credentialId);
            // PVE-TLS (pve03-win): BASTION_UITEST_PVE_SYSTEM_TRUST=1 leaves the entry on system trust, as a new entry is.
            if (Environment.GetEnvironmentVariable("BASTION_UITEST_PVE_SYSTEM_TRUST") != "1")
                PluginEntryClient.SetTls(_library, id, "pinned", PluginEntryClient.ProbeCertificate("127.0.0.1", port));
            // PVE-AUTH (pve04-win): BASTION_UITEST_PVE_AUTH=1 adds "pve-badtoken" (token type, a user name with no token id:
            // the mock refuses it) and "pve-pass" (password type, user@realm + the synthetic password), both pinned.
            if (Environment.GetEnvironmentVariable("BASTION_UITEST_PVE_AUTH") == "1")
            {
                var userLogin = OpenCredentials().SavePassword(null, "pve test user", null, "uitest@pve", "test-pve");
                OpenCredentials().Save();
                var pin = PluginEntryClient.ProbeCertificate("127.0.0.1", port);
                foreach (var (name, typeSuffix) in new[] { ("pve-badtoken", "/pve"), ("pve-pass", "/pve-password") })
                {
                    var t = PluginTypes.First(x => x.Id.EndsWith(typeSuffix, StringComparison.Ordinal));
                    var e = PluginEntryClient.Add(_library, SessionDataDir, null, name, "127.0.0.1", t.Id);
                    _library.SetProperty(e, "port", port.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    _library.SetCredential(e, userLogin);
                    PluginEntryClient.SetTls(_library, e, "pinned", pin);
                }
            }
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
