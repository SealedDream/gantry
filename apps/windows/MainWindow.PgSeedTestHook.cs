#if BASTION_TEST_HOOKS
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// PG-LIVE Windows suite seam (tests\pg-live-win-ui-test.ps1). Test-hooks builds only. With BASTION_UITEST_PG_SEED =
/// host:port:database:user and a test library, it installs the signed PostgreSQL pack (BASTION_UITEST_PLUGIN_PATH, an
/// unverified pack is refused), saves the login with the password read from BASTION_UITEST_PG_PASSWORD_FILE, and adds the
/// entry "pg-live" with that login and the Database field, left on system trust as a new entry is. Nothing is logged but
/// the exception type.
/// </summary>
public sealed partial class MainWindow
{
    private void SeedPgForTest(string seed)
    {
        if (TestHooks.LibraryOverride is null || TestHooks.PluginInstallPath is not { } pack || TestHooks.PgPasswordFile is not { } pwFile) return;
        var parts = seed.Split(':');
        if (parts.Length != 4 || !int.TryParse(parts[1], out var port)) return;
        try
        {
            if (Flatten(_roots).Any(i => i.Connection?.Name == "pg-live")) return;
            // The signed pack (signature required); under the test rollout setting the unsigned fixture of a
            // version not signed yet (com.example.postgres).
            var unverified = Environment.GetEnvironmentVariable("BASTION_TEST_PLUGIN_ROLLOUT") == "unverified";
            PluginClient.InstallFile(SessionDataDir, pack, allowUnverified: unverified);
            _pluginTypes = null;
            var type = PluginTypes.First(t => IsPostgresType(t.Id) || (unverified && t.Id == "com.example.postgres/postgres"));
            var password = File.ReadAllText(pwFile).TrimEnd('\r', '\n');
            var credentialId = OpenCredentials().SavePassword(null, "pg-live login", null, parts[3], password);
            OpenCredentials().Save();
            var id = PluginEntryClient.Add(_library, SessionDataDir, null, "pg-live", parts[0], type.Id);
            _library.SetProperty(id, "port", port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            _library.SetCredential(id, credentialId);
            PluginEntryClient.SetField(_library, SessionDataDir, id, "database", parts[2]);
            _library.Save();
            Reload(id);
        }
        catch (Exception ex) when (ex is BastionException or InvalidOperationException or IOException)
        {
            CrashLog.Write(ex);
        }
    }
}
#endif
