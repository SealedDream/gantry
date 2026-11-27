using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Bastion.Shell.Interop;

// SEC-07, Native Windows: Test Connection never shows a waiting report as success and only ever sends a
// fingerprint the user confirmed. Prints PASS/FAIL per case and "N passed, M failed"; exit code 1 on a failure.
//   dotnet run -c Release                                                    logic cases, any machine
//   dotnet run -c Release -- --live <dir with bastion_cabi.dll> <host> <port>   plus 10 cases through the real DLL

var results = new List<(string Name, bool Ok, string Detail)>();
void Check(string name, bool ok, string detail = "") => results.Add((name, ok, detail));

const string Fp = "SHA256:ZPIj3qUKtwR+RYI1zYZqn+zcm7GlLmNn/+46IW7kWM4";
const string OtherFp = "SHA256:mwxnPXQQeKEs0JMCoXhSaUtXTbBYj3qBiEWkN69zHh0";
const string Placeholder = "console-test-not-a-real-password";

static ProbeStepDto Step(string kind, string status, string detail, ulong millis = 1) => new(kind, status, detail, null, millis);

// ---- The report: the host-key question is read before Ok ----
{
    // Exactly what the core returns for a new key and a typed password: ok is true, the login step is skipped.
    var json = "{\"ok\":true,\"cancelled\":false,\"steps\":[{\"kind\":\"host_key\",\"status\":\"warn\",\"detail\":\"NEW host key " + Fp + "\",\"fix\":\"x\",\"millis\":3},"
        + "{\"kind\":\"login\",\"status\":\"skipped\",\"detail\":\"Not tested: confirm the host key first\",\"fix\":null,\"millis\":0}],\"needs_host_key_confirmation\":\"" + Fp + "\"}";
    var report = ProbeWire.Report(json);
    Check("a waiting report parses with its fingerprint", report?.NeedsHostKeyConfirmation == Fp, report?.NeedsHostKeyConfirmation ?? "null");
    var verdict = ProbeVerdict.Of(report!);
    Check("a waiting report with ok=true is waiting, not passed", report!.Ok && verdict.State == ProbeState.WaitingForHostKey, verdict.State.ToString());
    Check("the waiting summary does not say it works", verdict.Summary == ProbeVerdict.Waiting && !verdict.Summary.Contains("works", StringComparison.OrdinalIgnoreCase), verdict.Summary);
    Check("the verdict carries the fingerprint to show", verdict.Fingerprint == Fp);
    var again = ProbeVerdict.Of(report, sentTrust: OtherFp);
    Check("a second question after a confirmed key says the key differs", again.State == ProbeState.WaitingForHostKey && again.Summary == ProbeVerdict.WaitingAgain && again.Fingerprint == Fp, again.Summary);
}
{
    var old = ProbeWire.Report("{\"ok\":true,\"cancelled\":false,\"steps\":[{\"kind\":\"login\",\"status\":\"ok\",\"detail\":\"Signed in\",\"fix\":null,\"millis\":40}]}");
    Check("a report without the field parses (older core JSON)", old is { NeedsHostKeyConfirmation: null });
    Check("a finished ok report passes", ProbeVerdict.Of(old!) is { State: ProbeState.Passed, Fingerprint: null, Summary: "Everything works (40 ms)." });
    var nulled = ProbeWire.Report("{\"ok\":true,\"cancelled\":false,\"steps\":[],\"needs_host_key_confirmation\":null}");
    Check("a null field is not a question", ProbeVerdict.Of(nulled!).State == ProbeState.Passed);
    var empty = new ProbeReportDto(true, false, [], "");
    Check("an empty field is not a question", ProbeVerdict.Of(empty).State == ProbeState.Passed);
    Check("a cancelled report is cancelled", ProbeVerdict.Of(new ProbeReportDto(false, true, [])).State == ProbeState.Cancelled);
    Check("text that is not a report gives null, not a pass", ProbeWire.Report("{\"ok\":true}") is null && ProbeWire.Report("not json") is null);
}
{
    var changed = new ProbeReportDto(false, false, [Step("host_key", "failed", "Host key CHANGED since last connect (known_hosts line 3)"), Step("login", "skipped", "Stopped: the host key changed", 0)]);
    var verdict = ProbeVerdict.Of(changed, sentTrust: Fp);
    Check("a changed key is a failure", verdict.State == ProbeState.Failed, verdict.State.ToString());
    Check("a changed key offers nothing to confirm", verdict.Fingerprint is null);
    Check("a changed key says it cannot be confirmed here", verdict.Summary.EndsWith(ProbeVerdict.ChangedKey, StringComparison.Ordinal), verdict.Summary);
    var kinded = ProbeWire.Report("{\"ok\":false,\"cancelled\":false,\"steps\":[{\"kind\":\"host_key\",\"status\":\"failed\",\"detail\":\"x\",\"fix\":null,\"millis\":1}],\"host_key_failure\":\"changed\"}");
    Check("FU1: host_key_failure parses", kinded?.HostKeyFailure == "changed", kinded?.HostKeyFailure ?? "null");
    Check("FU1: a changed kind gets the changed-key message", ProbeVerdict.Of(kinded!) is { State: ProbeState.Failed, Summary: ProbeVerdict.KeyChanged });
    var unreadable = kinded! with { HostKeyFailure = "known_hosts_unreadable" };
    Check("FU1: an unreadable known_hosts gets its own message", ProbeVerdict.Of(unreadable) is { State: ProbeState.Failed, Summary: ProbeVerdict.KnownHostsUnreadable });
    Check("FU1: the two messages differ", ProbeVerdict.KeyChanged != ProbeVerdict.KnownHostsUnreadable);
    Check("FU1: a kind without a failed host-key step changes nothing", ProbeVerdict.Of(new ProbeReportDto(true, false, [], null, "changed")).State == ProbeState.Passed);
    Check("FU1: an unknown kind falls back to the old reading", ProbeVerdict.Of(changed with { HostKeyFailure = "new_kind" }).Summary.EndsWith(ProbeVerdict.ChangedKey, StringComparison.Ordinal));
    var hop = new ProbeReportDto(false, false, [Step("jump_host", "failed", "Jump host gw.example.test:22: host key not trusted yet")]);
    Check("a failed jump host is named in the summary", ProbeVerdict.Of(hop).Summary == "Test failed: Jump host gw.example.test:22: host key not trusted yet");
    var refused = new ProbeReportDto(false, false, [Step("tcp", "failed", "Port 22 refused")]);
    Check("another failure has no changed-key sentence", ProbeVerdict.Of(refused).Summary == "Test failed: Port 22 refused");
}

// ---- The request: a fingerprint goes out only after the user's yes, and only for the host it was shown for ----
{
    string Text(string? trust) => Encoding.UTF8.GetString(ProbeWire.Request("ssh", "db-1.example.test", 22, "ops", new ProbeLogin(0, Placeholder, null), trust));
    Check("a plain test sends no trusted_fingerprint", !Text(null).Contains("trusted_fingerprint") && !Text("").Contains("trusted_fingerprint"));
    using var doc = JsonDocument.Parse(Text(Fp));
    var root = doc.RootElement;
    Check("a confirmed test sends exactly the confirmed string", root.GetProperty("trusted_fingerprint").GetString() == Fp);
    Check("the request keeps its fields", root.GetProperty("protocol").GetString() == "ssh" && root.GetProperty("host").GetString() == "db-1.example.test"
        && root.GetProperty("port").GetInt32() == 22 && root.GetProperty("username").GetString() == "ops"
        && root.GetProperty("login").GetProperty("kind").GetInt32() == 0 && root.GetProperty("jumps").GetArrayLength() == 0);

    var pending = new PendingHostKey("db-1.example.test", 22, Fp);
    Check("the question names host and port", pending.Target == "db-1.example.test:22");
    Check("yes for the same host and port gives the fingerprint", pending.TrustFor("db-1.example.test", 22) == Fp && pending.TrustFor(" DB-1.example.test ", 22) == Fp);
    Check("yes does not carry over to another host", pending.TrustFor("db-2.example.test", 22) is null);
    Check("yes does not carry over to another port", pending.TrustFor("db-1.example.test", 2222) is null);
}

// ---- A1-NW-JUMPS: the route. Keys split right (IPv6 too), hops keep their order, and nothing is dropped ----
{
    Check("route: a name key splits", ProbeRoute.SplitKey("gw.example.test:2222") == ("gw.example.test", 2222));
    Check("route: an IPv4 key splits", ProbeRoute.SplitKey("10.0.0.5:22") == ("10.0.0.5", 22));
    Check("route: a bracketed IPv6 key splits", ProbeRoute.SplitKey("[fe80::1]:22") == ("fe80::1", 22));
    Check("route: a core IPv6 key (host:port, no brackets) splits at the last colon", ProbeRoute.SplitKey("fe80::1:22") == ("fe80::1", 22));
    Check("route: a bare IPv6 address is not split into host and port", ProbeRoute.SplitKey("fe80::1") is null && ProbeRoute.SplitKey("2001:db8::1") is null && ProbeRoute.SplitKey("::1") is null);
    Check("route: no port, port 0, a big port or junk is not a key", ProbeRoute.SplitKey("gw") is null && ProbeRoute.SplitKey("gw:0") is null
        && ProbeRoute.SplitKey("gw:70000") is null && ProbeRoute.SplitKey("gw:+22") is null && ProbeRoute.SplitKey(":22") is null && ProbeRoute.SplitKey("[gw]:22") is null);

    var target = new ProbeLogin(2, "conn-1", null); // a vault login: the "secret" is the credential id
    var own = new ProbeLogin(0, Placeholder, null);
    var hops = ProbeRoute.Hops([new SavedHop("gw.example.test:22", "jump"), new SavedHop("[fd00::7]:2200", "", own)], "ops", target);
    Check("route: the saved chain is sent in connect order", hops is { Count: 2 } && hops[0] is { Host: "gw.example.test", Port: 22 } && hops[1] is { Host: "fd00::7", Port: 2200 });
    Check("route: a hop without its own login gets a copy of the target's", hops![0].Login == target && hops[0].Username == "jump");
    Check("route: a hop with its own login keeps it; an empty user is the target's", hops[1].Login == own && hops[1].Username == "ops");
    Check("route: a hop that cannot be read stops the test instead of dropping the hop", ProbeRoute.Hops([new SavedHop("gw:22", "j"), new SavedHop("fe80::1", "j")], "ops", target) is null);
    Check("route: a direct connection has no hops", ProbeRoute.Hops([], "ops", target) is { Count: 0 });

    using var doc = JsonDocument.Parse(ProbeWire.Request("ssh", "db-1.example.test", 22, "ops", target, null, "conn-1", hops));
    var jumps = doc.RootElement.GetProperty("jumps");
    Check("route: the request carries each hop with host, port, user and login", jumps.GetArrayLength() == 2
        && jumps[0].GetProperty("host").GetString() == "gw.example.test" && jumps[0].GetProperty("port").GetInt32() == 22
        && jumps[0].GetProperty("username").GetString() == "jump" && jumps[0].GetProperty("login").GetProperty("kind").GetInt32() == 2
        && jumps[1].GetProperty("host").GetString() == "fd00::7" && jumps[1].GetProperty("login").GetProperty("kind").GetInt32() == 0);
}

// ---- Optional: the real bastion_cabi.dll against an SSH server with an unknown key. No login is sent. ----
if (args.Length == 4 && args[0] == "--live")
{
    var (dllDir, host, port) = (args[1], args[2], int.Parse(args[3]));
    NativeLibrary.SetDllImportResolver(typeof(Live).Assembly, (name, _, _) => name == Live.Lib ? NativeLibrary.Load(Path.Combine(dllDir, "bastion_cabi.dll")) : IntPtr.Zero);
    var data = Directory.CreateTempSubdirectory("bastion-sec07-").FullName;
    try
    {
        // A user that does not exist and a placeholder password: even if a login were sent, it would name no account.
        var login = new ProbeLogin(0, Placeholder, null);
        var first = Live.Run(data, ProbeWire.Request("ssh", host, port, "bastion-sec07-nobody", login, null));
        var v1 = ProbeVerdict.Of(first);
        Check("live: a new key with a typed password waits", v1.State == ProbeState.WaitingForHostKey, v1.Summary);
        Check("live: the fingerprint is SHA256", v1.Fingerprint?.StartsWith("SHA256:", StringComparison.Ordinal) == true, v1.Fingerprint ?? "null");
        Check("live: the sign-in step was skipped", first.Steps.Any(s => s is { Kind: "login", Status: "skipped", Detail: "Not tested: confirm the host key first" }),
            string.Join(" | ", first.Steps.Select(s => $"{s.Kind} {s.Status}: {s.Detail}")));
        var wrong = Live.Run(data, ProbeWire.Request("ssh", host, port, "bastion-sec07-nobody", login, OtherFp));
        var v2 = ProbeVerdict.Of(wrong, OtherFp);
        Check("live: a fingerprint the server does not show still waits", v2.State == ProbeState.WaitingForHostKey && v2.Fingerprint == v1.Fingerprint, v2.Summary);
        Check("live: no login step ran", !wrong.Steps.Any(s => s.Kind == "login" && s.Status != "skipped"));
        Check("live: nothing was written to known_hosts", !File.Exists(Path.Combine(data, "known_hosts")));

        // A1-NW-JUMPS through the DLL: the jumps reach the core, and a saved login over a route is still refused.
        var viaHop = Live.Run(data, ProbeWire.Request("ssh", host, port, "bastion-sec07-nobody", login, null, null,
            [new ProbeHop(host, port, "bastion-sec07-nobody", login)]));
        Check("live: a test with a jump host dials the jump host first", viaHop.Steps.Any(s => s.Kind == "jump_host") && !viaHop.Steps.Any(s => s.Kind == "login" && s.Status == "ok"),
            string.Join(" | ", viaHop.Steps.Select(s => $"{s.Kind} {s.Status}: {s.Detail}")));
        var vault = new ProbeLogin(2, "bastion-no-such-credential", null);
        string? refused = null;
        try { Live.Run(data, ProbeWire.Request("ssh", host, port, "ops", vault, null, "bastion-no-such-connection", [new ProbeHop(host, port, "ops", vault)])); }
        catch (InvalidOperationException e) { refused = e.Message; }
        // No vault is attached here, so the core may refuse on that first; either way it refuses at the start call.
        Check("live: a saved login with a jump chain and no saved connection is refused before dialling", refused is not null
            && (refused.Contains("save the connection", StringComparison.OrdinalIgnoreCase) || refused.Contains("vault is not open", StringComparison.OrdinalIgnoreCase)), refused ?? "it started");
        Check("live: the refusal names no credential", refused?.Contains("bastion-no-such-credential", StringComparison.Ordinal) == false);
        Check("live: still nothing written to known_hosts", !File.Exists(Path.Combine(data, "known_hosts")));
    }
    catch (Exception e) { Check("live: the run completed", false, e.Message); }
    finally { Directory.Delete(data, recursive: true); }
}
else if (args.Length > 0)
{
    Console.Error.WriteLine("usage: probe-console [--live <dir with bastion_cabi.dll> <host> <port>]");
    return 2;
}

foreach (var (name, ok, detail) in results) Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}{(ok || detail.Length == 0 ? "" : $" ({detail})")}");
var failed = results.Count(r => !r.Ok);
Console.WriteLine($"{results.Count - failed} passed, {failed} failed");
return failed == 0 ? 0 : 1;

/// <summary>The probe calls of bastion_cabi.dll, as the app's ProbeNative makes them.</summary>
internal static class Live
{
    internal const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_session_manager_new([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bastion_session_manager_free(IntPtr manager);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_probe_start(IntPtr manager, IntPtr lib, byte[] inputJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_probe_wait_json(IntPtr probe, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bastion_probe_free(IntPtr probe);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bastion_string_free(IntPtr s);

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { bastion_string_free(s); }
    }

    internal static ProbeReportDto Run(string dataDir, byte[] request)
    {
        var manager = bastion_session_manager_new(dataDir, out var err);
        if (manager == IntPtr.Zero) throw new InvalidOperationException(Take(err) ?? "no session manager");
        try
        {
            var terminated = new byte[request.Length + 1]; // NUL-terminated for the C side
            request.CopyTo(terminated, 0);
            var probe = bastion_probe_start(manager, IntPtr.Zero, terminated, out err);
            Array.Clear(terminated);
            if (probe == IntPtr.Zero) throw new InvalidOperationException(Take(err) ?? "the test did not start");
            try
            {
                var text = Take(bastion_probe_wait_json(probe, out err)) ?? throw new InvalidOperationException(Take(err) ?? "no report");
                return ProbeWire.Report(text) ?? throw new InvalidOperationException("the report did not parse");
            }
            finally { bastion_probe_free(probe); }
        }
        finally { bastion_session_manager_free(manager); }
    }
}
