#if BASTION_TEST_HOOKS
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// B13 web sign-in fill suite seam (tests\b13-web-autofill-ui-test.ps1). Compiled into test-hooks builds only
/// (WIN-UI-DRIVER-GATE); an owner build has neither this code nor the variable name. With BASTION_UITEST_WEBFILL=1 and a
/// test library, it puts one synthetic login in the vault and two web connections that use it, so the suite needs no
/// vault UI. The password is a fixed synthetic value, not a secret: "test-" + the connection name, as on the Mac.
/// </summary>
public sealed partial class MainWindow
{
    private const string WebFillTestUrl = "https://autofill.test/login.html";
    private const string WebFillTestUser = "ops";

    private void SeedWebFillForTest()
    {
        if (TestHooks.LibraryOverride is null) return; // never the user's own library
        try
        {
            if (Flatten(_roots).Any(i => i.Connection?.Name == "fill-on")) return;
            var credentialId = OpenCredentials().SavePassword(null, "web fill test", null, WebFillTestUser, "test-fill-on");
            OpenCredentials().Save();
            var on = _library.AddConnection(null, "fill-on", "web", WebFillTestUrl, null, WebFillTestUser);
            _library.SetCredential(on, credentialId);
            _library.SetProperty(on, "web_autofill", "true");
            var off = _library.AddConnection(null, "fill-off", "web", WebFillTestUrl, null, WebFillTestUser);
            _library.SetCredential(off, credentialId);
            _library.Save();
            Reload(on);
        }
        catch (BastionException ex)
        {
            CrashLog.Write(ex);
        }
    }
}
#endif
