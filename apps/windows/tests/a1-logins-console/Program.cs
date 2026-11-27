using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Bastion.Shell.Interop;

// A1-NW-01 (owner decision D1): a login saved for another connection on the same host is offered, never used
// without the user's pick. Part 1 and 2 are pure; part 3 asks the real core (bastion_cabi.dll on PATH).
// Usage: a1-logins-console --core <path to bastion_cabi.dll> | --no-core. Prints PASS/FAIL lines and "<n> passed, <m> failed"; exit 1 on a failure.
var results = new List<string>();
void Step(string name, bool ok, string detail = "") => results.Add($"{(ok ? "PASS" : "FAIL")} {name}{(detail.Length > 0 ? " (" + detail + ")" : "")}");
LoginCandidateDto Login(string id, string source, bool autoUse, string sourceName = "") => new(id, "cred-" + id, "ops", "password", source, null, sourceName, autoUse);

// ---- 1. The rule every sign-in path shares ----
var own = Login("a", "default", true);
var inherited = Login("b", "inherited", true, "Team");
var offered = Login("c", "same-host", false, "site-ssh");
Step("no login: nothing is used unasked", !LoginRule.MayUseUnasked([], null));
Step("no login: nothing is preferred", LoginRule.Preferred([], null) == -1);
Step("own login: used unasked", LoginRule.MayUseUnasked([own], null));
Step("inherited login: used unasked", LoginRule.MayUseUnasked([inherited], null));
Step("offered login only: never used unasked", !LoginRule.MayUseUnasked([offered], null));
Step("own first, offered second: the own one is used unasked", LoginRule.MayUseUnasked([own, offered], null) && LoginRule.Preferred([own, offered], null) == 0);
Step("offered login confirmed this run: used unasked", LoginRule.MayUseUnasked([offered], "c"));
Step("a confirmed login comes first", LoginRule.Preferred([own, offered], "c") == 1);
Step("a confirmed login the core no longer lists is ignored", LoginRule.Preferred([own], "c") == 0 && !LoginRule.MayUseUnasked([offered], "gone"));
Step("one own login: no picker", !LoginRule.ShowsPicker([own]));
Step("one offered login: the picker shows it with its label", LoginRule.ShowsPicker([offered]));
Step("two logins: picker", LoginRule.ShowsPicker([own, offered]));
Step("after a connect, only an offered login asks 'from now on'", LoginRule.AsksToKeep(offered, false) && !LoginRule.AsksToKeep(own, false) && !LoginRule.AsksToKeep(inherited, false) && !LoginRule.AsksToKeep(null, false));
Step("'from now on' is asked once per connection in a run (a No is not asked again)", !LoginRule.AsksToKeep(offered, true));
Step("after a No the pick stays confirmed for the run, and only while the core lists it", LoginRule.MayUseUnasked([offered], "c") && !LoginRule.MayUseUnasked([offered], "other") && !LoginRule.MayUseUnasked([], "c"));
Step("offered label names the other connection", offered.Label == "ops  ·  Saved for site-ssh", offered.Label);
Step("a named login has a label", Login("n", "named", true).Origin.Length > 0);

// ---- 2. The JSON the core sends (core-cabi/src/credtree.rs, field autoUse) ----
var json = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var parsed = JsonSerializer.Deserialize<List<LoginCandidateDto>>(
    """[{"credentialId":"1","name":"n","username":"u","kind":"password","source":"default","sourceId":null,"sourceName":"","autoUse":true},{"credentialId":"2","name":"n","username":"u","kind":"password","source":"same-host","sourceId":"x","sourceName":"other","autoUse":false},{"credentialId":"3","name":"n","username":"u","kind":"password","source":"default","sourceId":null,"sourceName":""}]""", json)!;
Step("autoUse true is read", parsed[0].AutoUse);
Step("autoUse false is read", !parsed[1].AutoUse);
Step("a missing autoUse means offered (fail closed)", !parsed[2].AutoUse && !LoginRule.MayUseUnasked([parsed[2]], null));

// ---- 2b. Screen lock (lock-reopen wave 4): which messages lock, and an unreadable setting fails closed ----
Step("screen lock, console switch and RDP disconnect leave the desktop", ScreenLockRule.LeavesDesktop(7) && ScreenLockRule.LeavesDesktop(2) && ScreenLockRule.LeavesDesktop(4));
Step("unlock and logon do not", !ScreenLockRule.LeavesDesktop(8) && !ScreenLockRule.LeavesDesktop(5) && !ScreenLockRule.LeavesDesktop(1));
Step("setting on: credentials lock", ScreenLockRule.LocksCredentials("true"));
Step("setting off: credentials stay open", !ScreenLockRule.LocksCredentials("false"));
Step("setting unreadable (empty or null): credentials lock", ScreenLockRule.LocksCredentials("") && ScreenLockRule.LocksCredentials(null));

// ---- 2c. PLUG-03a: the tree row's `unavailable` (core-cabi connection_json) ----
var rows = JsonSerializer.Deserialize<List<ConnectionDto>>(
    """[{"id":"a","name":"pg","protocol":"postgresql","host":"db","imported":false,"unavailable":"Needs a newer Bastion or a plugin"},{"id":"b","name":"web","protocol":"ssh","host":"w","imported":false,"unavailable":null},{"id":"c","name":"old","protocol":"ssh","host":"o","imported":false}]""", json)!;
Step("an unknown type's row is marked with the core's text", rows[0].IsUnavailable && rows[0].Unavailable == "Needs a newer Bastion or a plugin");
Step("a known type's row (null or missing field) is not marked", !rows[1].IsUnavailable && !rows[2].IsUnavailable);

// ---- 3. The real core ----
if (!args.Contains("--no-core"))
{
    // The interop sources load the core from the application's folder only. A test program is not that folder, so
    // the test names the exact file to load; nothing is searched for.
    var core = Array.IndexOf(args, "--core") is >= 0 and var at && at + 1 < args.Length ? Path.GetFullPath(args[at + 1]) : "";
    if (!File.Exists(core)) { Console.WriteLine("ERROR give --core <path to bastion_cabi.dll> or --no-core"); return 2; }
    NativeLibrary.SetDllImportResolver(typeof(LibraryClient).Assembly, (name, _, _) => name == "bastion_cabi" ? NativeLibrary.Load(core) : IntPtr.Zero);
    var dir = Path.Combine(Path.GetTempPath(), "bastion-a1-logins-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        using var lib = LibraryClient.Open(Path.Combine(dir, "library.json"));
        using var vault = CredentialStore.Open(Path.Combine(dir, "credentials.vault"));
        // Generated here, never printed, gone with the folder.
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
        var siteA = lib.AddFolder(null, "Site A");
        var ssh = lib.AddConnection(siteA, "a-ssh", "ssh", "10.9.8.7", null, "ops");
        var rdp = lib.AddConnection(siteA, "a-rdp", "rdp", "10.9.8.7", null, null);
        var siteB = lib.AddFolder(null, "Site B");
        var rdpB = lib.AddConnection(siteB, "b-rdp", "rdp", "10.9.8.7", null, null);
        var local = lib.AddFolder(null, "Local");
        var fwdA = lib.AddConnection(local, "fwd-a", "ssh", "127.0.0.1", 2201, "ops");
        var fwdB = lib.AddConnection(local, "fwd-b", "ssh", "127.0.0.1", 2202, "ops");
        var team = lib.AddFolder(null, "Team");
        var child = lib.AddConnection(team, "team-ssh", "ssh", "10.9.8.9", null, null);
        var opsLogin = vault.SavePassword(null, "ops-login", null, "ops", secret);
        var fwdLogin = vault.SavePassword(null, "fwd-login", null, "fwd", secret);
        var teamLogin = vault.SavePassword(null, "team-login", null, "svc", secret);
        lib.SetCredential(ssh, opsLogin);
        lib.SetCredential(fwdA, fwdLogin);
        vault.Assign(lib, team, teamLogin);

        var sshLogins = vault.Logins(lib, ssh, passwordsOnly: false);
        Step("core: a connection's own login is auto-use", sshLogins.Count == 1 && sshLogins[0] is { AutoUse: true, IsOwn: true } && LoginRule.MayUseUnasked(sshLogins, null), Describe(sshLogins));

        var rdpLogins = vault.Logins(lib, rdp, passwordsOnly: true);
        Step("core: RDP on the same host in the same top-level folder is offered the SSH login", rdpLogins.Count == 1 && rdpLogins[0].CredentialId == opsLogin && rdpLogins[0].Source == "same-host", Describe(rdpLogins));
        Step("core: that login is not auto-use, so the sheet opens", rdpLogins.Count == 1 && !rdpLogins[0].AutoUse && !LoginRule.MayUseUnasked(rdpLogins, null) && LoginRule.ShowsPicker(rdpLogins));
        Step("core: its label says where it was saved", rdpLogins.Count == 1 && rdpLogins[0].Label == "ops  ·  Saved for a-ssh", Describe(rdpLogins));

        Step("core: the same host in another top-level folder is not offered", vault.Logins(lib, rdpB, passwordsOnly: true).Count == 0, Describe(vault.Logins(lib, rdpB, true)));
        Step("core: 127.0.0.1 on another port is not offered", vault.Logins(lib, fwdB, passwordsOnly: false).Count == 0, Describe(vault.Logins(lib, fwdB, false)));

        var childLogins = vault.Logins(lib, child, passwordsOnly: false);
        Step("core: a folder's login is inherited and auto-use", childLogins.Count == 1 && childLogins[0] is { Source: "inherited", AutoUse: true } && childLogins[0].Label == "svc  ·  From Team", Describe(childLogins));

        var released = vault.ReleaseLogin(lib, rdp, opsLogin);
        Step("core: the offered login can be read for the connection it is offered to", released.User == "ops" && released.Password == secret);
        Step("core: it is refused for the other top-level folder", Refused(() => vault.ReleaseLogin(lib, rdpB, opsLogin)));
        Step("core: the loopback login is refused for the other port", Refused(() => vault.ReleaseLogin(lib, fwdB, fwdLogin)));

        // "Use this login for a-rdp from now on" answered Yes: the login becomes the connection's own.
        vault.AddLogin(lib, rdp, opsLogin);
        var kept = vault.Logins(lib, rdp, passwordsOnly: true);
        Step("core: after 'from now on' the login is the connection's own and auto-use", kept.Count == 1 && kept[0] is { AutoUse: true, IsOwn: true } && LoginRule.MayUseUnasked(kept, null) && !LoginRule.ShowsPicker(kept), Describe(kept));
        vault.RemoveLogin(lib, rdp, opsLogin);
        var back = vault.Logins(lib, rdp, passwordsOnly: true);
        Step("core: removing it again leaves the offer only", back.Count == 1 && !back[0].AutoUse, Describe(back));
    }
    catch (Exception e) { results.Add("ERROR core: " + e.GetType().Name + ": " + e.Message); }
    finally
    {
        try { Directory.Delete(dir, recursive: true); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { results.Add("INFO scratch folder not removed: " + dir); }
    }
}

foreach (var line in results) Console.WriteLine(line);
var failed = results.Count(r => r.StartsWith("FAIL") || r.StartsWith("ERROR"));
Console.WriteLine($"{results.Count(r => r.StartsWith("PASS"))} passed, {failed} failed");
return failed == 0 ? 0 : 1;

// Sources and flags only: no secret is ever in a candidate.
static string Describe(IReadOnlyList<LoginCandidateDto> logins) => logins.Count == 0 ? "none" : string.Join(" | ", logins.Select(l => $"{l.Label} [{l.Source}, autoUse={l.AutoUse}]"));
static bool Refused(Action read)
{
    try { read(); return false; }
    catch (BastionException) { return true; }
}
