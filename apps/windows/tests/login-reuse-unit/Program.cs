using System.Reflection;
using System.Runtime.InteropServices;
using Bastion.Shell;

// Unit tests for remembered-login reuse (SEC-03, Native Windows; the Mac half is apps/macos/tests/login-reuse).
// Part 1: LoginReuseTimes with a stand-in clock and rule. Part 2 (only with the path to bastion_cabi.dll): the same
// store driven by the core's exports, as MainWindow.DirectConnect.cs wires it.
// Prints one PASS or FAIL line per test and exits with the number of failures.

var passed = 0;
var failures = 0;
void Test(string name, Action body)
{
    try { body(); passed++; Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failures++; Console.WriteLine($"FAIL {name}: {ex.Message}"); }
}
void True(bool ok, string what) { if (!ok) throw new InvalidOperationException(what); }

ulong clock = 1_000;
static bool Rule(ulong at, ulong now, uint m) => m == 0 || (now >= at && now - at < (ulong)m * 60);
var asked = new List<uint>();
var t = new LoginReuseTimes(() => clock, (a, n, m) => { asked.Add(m); return Rule(a, n, m); });

Test("no time recorded: not usable, rule not asked", () => { True(!t.Usable("a", 0), "usable"); True(asked.Count == 0, "asked"); });
Test("4 min 59 s under 5: usable", () => { t.Started("a"); clock += 299; True(t.Usable("a", 5), "not usable"); True(asked[^1] == 5, "minutes"); });
Test("5 min 0 s under 5: not usable", () => { clock += 1; True(!t.Usable("a", 5), "usable"); });
Test("0 = until Lock or quit", () => { clock += 100_000; True(t.Usable("a", 0), "not usable"); });
Test("a successful sign-in restarts the time", () => { t.Started("b"); clock += 200; t.Started("b"); clock += 200; True(t.Usable("b", 5), "not usable"); });
Test("clock back under a limit: not usable", () => { t.Started("c"); clock -= 50; True(!t.Usable("c", 5), "usable"); });
Test("Forget and Clear drop the time", () => { t.Started("d"); t.Forget("d"); True(!t.Usable("d", 0), "d"); t.Clear(); True(!t.Usable("b", 0), "b"); });
Test("stored setting read as the core reads it", () =>
{
    True(LoginReuseTimes.UserMinutes("15") == 15 && LoginReuseTimes.UserMinutes("0") == 0, "valid");
    True(LoginReuseTimes.UserMinutes(null) == 0 && LoginReuseTimes.UserMinutes("x") == 0 && LoginReuseTimes.UserMinutes("1441") == 0 && LoginReuseTimes.UserMinutes("-1") == 0, "invalid");
});
Test("setting id and capability are the core's", () =>
{
    True(LoginReuseTimes.SettingId == "security.session-login-reuse-minutes", "id");
    True(LoginReuseTimes.Capability == "session-login-reuse", "capability");
});
Test("monotonic clock moves forward", () => { var a = LoginReuseTimes.MonotonicSeconds(); True(LoginReuseTimes.MonotonicSeconds() >= a, "back"); });

if (args.Length == 1 && File.Exists(args[0]))
{
    var dll = Path.GetFullPath(args[0]);
    NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), (name, _, _) => name == Cabi.Lib ? NativeLibrary.Load(dll) : IntPtr.Zero);
    Test("core: ABI has the exports (>= 105)", () => True(Cabi.bastion_abi_version() >= 105, "abi"));
    Test("core: user value in force without a managed policy", () => { True(Cabi.bastion_session_login_reuse_minutes(0) == 0, "0"); True(Cabi.bastion_session_login_reuse_minutes(7) == 7, "7"); });
    Test("core: store with the core rule", () =>
    {
        ulong c = 5_000;
        var core = new LoginReuseTimes(() => c, (a, n, m) => Cabi.bastion_remembered_login_usable(a, n, m) == 1);
        core.Started("x"); c += 299; True(core.Usable("x", 5), "4:59");
        c += 1; True(!core.Usable("x", 5), "5:00");
        True(core.Usable("x", 0), "0");
    });
}
else Console.WriteLine("SKIP core part: no bastion_cabi path given");

Console.WriteLine($"login-reuse-unit: {passed} passed, {failures} failed");
return failures;

static class Cabi
{
    internal const string Lib = "bastion_cabi";
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] internal static extern uint bastion_abi_version();
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] internal static extern uint bastion_session_login_reuse_minutes(uint userMinutes);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] internal static extern int bastion_remembered_login_usable(ulong rememberedAt, ulong now, uint minutes);
}
