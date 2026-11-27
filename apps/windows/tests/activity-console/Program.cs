using System.Runtime.InteropServices;
using Bastion.Shell.Interop;

// LOG-NATIVE-01 (Windows): console checks of the Activity page's words, filter and export, and of the core's answers
// through bastion_cabi (C ABI 98). No window, no network, no secrets; the test makes and deletes its own folder.
// Usage: activity-console --core <path to bastion_cabi.dll or .dylib> | --no-core. Exit 1 on a failure.
var results = new List<string>();
void Step(string name, bool ok, string detail = "") => results.Add($"{(ok ? "PASS" : "FAIL")} {name}{(detail.Length > 0 ? " (" + detail + ")" : "")}");
ActivitySessionDto S(string reason, long? ms = 60_000, string name = "web-1", string host = "10.0.0.5", int? port = 22, string? user = "ops", bool open = false) =>
    new("s", "c", name, "ssh", host, port, user, 1_700_000_000_000, open, null, null, ms, reason, 0, null);

// ---- 1. Words ----
Step("closed by the user reads Closed and counts as OK", ActivityFormat.Result(S("closed_by_user")) == "Closed" && ActivityFormat.IsOk(S("closed_by_user")));
Step("a failed sign-in reads Sign-in failed, not OK", ActivityFormat.Result(S("auth_failed")) == "Sign-in failed" && !ActivityFormat.IsOk(S("auth_failed")));
Step("a dropped link reads Network lost", ActivityFormat.Result(S("network_lost")) == "Network lost");
Step("an open session reads Open", ActivityFormat.Result(S("", open: true)) == "Open");
Step("a reason from a newer build reads Unknown", ActivityFormat.Result(S("something_new")) == "Unknown");
Step("durations", ActivityFormat.Duration(45_000) == "45 s" && ActivityFormat.Duration(12 * 60_000) == "12 min"
    && ActivityFormat.Duration(3 * 3_600_000 + 5 * 60_000) == "3 h 05 min" && ActivityFormat.Duration(null) == "—",
    $"{ActivityFormat.Duration(45_000)}|{ActivityFormat.Duration(12 * 60_000)}|{ActivityFormat.Duration(3 * 3_600_000 + 5 * 60_000)}");
Step("target with and without a port", ActivityFormat.Target(S("failed")) == "10.0.0.5:22" && ActivityFormat.Target(S("failed", port: null)) == "10.0.0.5");

Step("History row of a connection", ActivityFormat.HistoryLine(S("closed_by_user", 12 * 60_000), false, "Today 14:05") == "Today 14:05 · ops · 12 min · Closed");
Step("History row of a folder names the connection; an open session has no duration",
    ActivityFormat.HistoryLine(S("", open: true, user: null), true, "Yesterday 09:12") == "web-1 · Yesterday 09:12 · Open");
Step("filter JSON for a connection's or folder's History", ActivityClient.FilterJson(new ActivityFilter(Folder: "f1")) == "{\"folder\":\"f1\"}");

// ---- 2. Filter ----
Step("free text matches name, host and user, any case", ActivityFormat.Matches(S("failed"), "WEB") && ActivityFormat.Matches(S("failed"), "0.0.5")
    && ActivityFormat.Matches(S("failed"), "OPS") && !ActivityFormat.Matches(S("failed"), "db") && ActivityFormat.Matches(S("failed"), ""));
var now = DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_000);
Step("ranges", ActivityFormat.RangeStart("week", now) == 1_700_000_000_000 - 7 * 86_400_000L && ActivityFormat.RangeStart("all", now) is null);
Step("filter JSON leaves unset fields out", ActivityClient.FilterJson(new ActivityFilter(Protocol: "rdp", From: 5)) == "{\"protocol\":\"rdp\",\"from\":5}",
    ActivityClient.FilterJson(new ActivityFilter(Protocol: "rdp", From: 5)));

// ---- 3. Export ----
var csv = ActivityFormat.Csv([S("closed_by_user"), S("failed", name: "=cmd|' /C calc'!A0", host: "a,b")]);
var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
Step("CSV: a header and one line per row shown", lines.Length == 3 && lines[0] == "Started,Connection,Protocol,Host,User,Duration,Result", lines[0]);
Step("CSV: a formula is defused and a comma is quoted", lines[2].Contains(",'=cmd|' /C calc'!A0,") && lines[2].Contains("\"a,b:22\""), lines[2]);
var json = ActivityFormat.JsonExport([S("closed_by_user")]);
Step("JSON: the shown columns only", json.Contains("\"connection\": \"web-1\"") && json.Contains("\"result\": \"Closed\"") && !json.Contains("sessionId"), json);
Step("parse the core's item shape", ActivityClient.Parse("""[{"sessionId":"x","connectionId":"c","connectionName":"n","folderPath":[],"protocol":"rdp","host":"h","port":null,"username":null,"route":[],"loginSource":"typed","startedAt":1,"app":"native-windows","appVersion":"1","deviceName":"d","open":true,"connectedAt":null,"endedAt":null,"durationMs":null,"endReason":null,"reconnects":null,"transcriptPath":null,"transcriptSha256":null}]""") is [{ Protocol: "rdp", Open: true }]);

// ---- Session log v2 state (C ABI 138, LOG-CORE-02) ----
Step("log state: stopped with reason", SessionLogState.Parse("{\"state\":\"stopped\",\"path\":null,\"reason\":\"disk full\"}") is { IsStopped: true, IsActive: false, Reason: "disk full" });
Step("log state: active with path", SessionLogState.Parse("{\"state\":\"active\",\"path\":\"C:\\\\l\\\\a.log\",\"reason\":null}") is { IsActive: true, Path: "C:\\l\\a.log" });
Step("log v2 capability is the core's", SessionLogV2.Capability == "session-log-v2");

// ---- Audit log page (C ABI 123) ----
Step("audit status", AuditFormat.Status(new(true, 3, null)) == "Log intact" && AuditFormat.Status(new(false, 3, 2)) == "Changed at record 2" && AuditFormat.Status(new(true, 0, null)) == "No records");
Step("audit category and outcome", AuditFormat.Category("credential_access") == "Credential access" && AuditFormat.Outcome("denied") == "Denied");
Step("audit details in key order", AuditFormat.Details(new Dictionary<string, string> { ["user"] = "ops", ["host"] = "lab" }) == "host=lab, user=ops" && AuditFormat.Details(null) == "");
var rec = AuditClient.ParsePage("{\"total\":1,\"records\":[{\"id\":\"x\",\"ts_unix_ms\":1,\"category\":\"connection\",\"action\":\"ssh.connect\",\"actor\":null,\"target\":\"lab\",\"outcome\":\"success\",\"correlation_id\":null,\"details\":{\"user\":\"ops\"},\"prev_hash\":\"00\"}]}");
Step("parse the core's audit page", rec is { Total: 1, Records: [{ Action: "ssh.connect", Target: "lab", Category: "connection" }] });
Step("audit filter", AuditFormat.Matches(rec.Records[0], "SSH") && AuditFormat.Matches(rec.Records[0], "user=ops") && !AuditFormat.Matches(rec.Records[0], "rdp"));
Step("parse the core's check", AuditClient.ParseCheck("{\"intact\":false,\"records\":4,\"changedAt\":3}") == new AuditCheckDto(false, 4, 3));

// ---- Transcript viewer and diagnostics (LOG-NATIVE-01 items 4 and 7) ----
Step("transcript: escape codes, CR and BEL go; tab stays", Bastion.Shell.TranscriptText.Strip("\u001b[1;32mok\u001b[0m\r\tx\u001b]0;title\u0007!") == "ok\tx!");
var tl = Bastion.Shell.TranscriptText.Split(System.Text.Encoding.UTF8.GetBytes("2026-11-15T10:00:00Z $ ls\n[10:00:01] secret\nplain\n"), 0);
Step("transcript: lines, numbers and the time column", tl.Count == 3 && tl[0].Time == "2026-11-15T10:00:00Z" && tl[0].Text == "$ ls" && tl[1].Time == "10:00:01" && tl[2].Time is null && tl[2].Number == 2);
Step("transcript: Show times off drops the column", tl[0].Display(false) == "$ ls" && tl[0].Display(true) == "2026-11-15T10:00:00Z  $ ls");
Step("transcript: has times", Bastion.Shell.TranscriptText.HasTimes(tl) && !Bastion.Shell.TranscriptText.HasTimes(tl.Skip(2)));
var hits = Bastion.Shell.TranscriptText.Find("S", tl);
Step("transcript: find is case-insensitive and in order", hits.SequenceEqual(new[] { 0, 1 }) && Bastion.Shell.TranscriptText.Find("  ", tl).Count == 0);
Step("transcript: find next and previous wrap", Bastion.Shell.TranscriptText.Step(hits, null, true) == 0 && Bastion.Shell.TranscriptText.Step(hits, 1, true) == 0
    && Bastion.Shell.TranscriptText.Step(hits, 0, false) == 1 && Bastion.Shell.TranscriptText.Step([], 0, true) is null);
Step("transcript: copy the selection, or everything", Bastion.Shell.TranscriptText.CopyText(tl, new HashSet<int> { 2 }, true) == "plain"
    && Bastion.Shell.TranscriptText.CopyText(tl, new HashSet<int>(), false) == "$ ls\r\nsecret\r\nplain");
var tdir = Path.Combine(Path.GetTempPath(), "bastion-transcript-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(tdir);
try
{
    var tfile = Path.Combine(tdir, "t.log");
    File.WriteAllText(tfile, string.Concat(Enumerable.Range(0, 5000).Select(i => $"line {i}\n")) + "last-no-newline");
    var pages = 0; var all = new List<Bastion.Shell.TranscriptLine>();
    Bastion.Shell.TranscriptText.Read(tfile, p => { pages++; all.AddRange(p); return true; }, pageBytes: 4096);
    Step("transcript: paged read keeps every line in order", pages > 5 && all.Count == 5001 && all[4999].Text == "line 4999" && all[^1].Text == "last-no-newline"
        && all.Select(l => l.Number).SequenceEqual(Enumerable.Range(0, 5001)), $"{pages} pages, {all.Count} lines");
    var stopped = 0;
    Bastion.Shell.TranscriptText.Read(tfile, _ => { stopped++; return false; }, pageBytes: 4096);
    Step("transcript: a closed viewer stops the read", stopped == 1);
    var before = File.ReadAllBytes(tfile);
    using (var writer = new FileStream(tfile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        Bastion.Shell.TranscriptText.Read(tfile, _ => true);
    Step("transcript: reads a log still open for writing, and never changes it", before.SequenceEqual(File.ReadAllBytes(tfile)));

    // Diagnostics: a settings file with names and a secret, a log with the profile path, a crash; the zip must have none.
    var settings = Path.Combine(tdir, "settings.json");
    File.WriteAllText(settings, """{"terminal":{"fontSize":13,"font":"Cascadia"},"lastHost":"db-prod.example","autoLock":true,"proxy":{"password":"hunter2-SECRET"},"list":["web-1"],"empty":""}""");
    var redacted = Bastion.Shell.DiagnosticsBundle.RedactSettings(File.ReadAllText(settings));
    Step("diagnostics: settings keep keys, numbers and true/false only", redacted.Contains("\"fontSize\": 13") && redacted.Contains("\"autoLock\": true")
        && !redacted.Contains("db-prod") && !redacted.Contains("hunter2") && !redacted.Contains("web-1") && !redacted.Contains("Cascadia") && redacted.Contains("\"(set)\""), redacted);
    Step("diagnostics: bad settings give {}", Bastion.Shell.DiagnosticsBundle.RedactSettings("not json") == "{}\n");
    var home = @"C:\Users\alice";
    Bastion.Shell.AppLog.Path = Path.Combine(tdir, "bastion.log");
    Bastion.Shell.AppLog.Info($@"Opened {home}\AppData\Roaming\Bastion on ALICE-PC as alice{"\n"}second");
    Step("app log: one line per call", File.ReadAllLines(Bastion.Shell.AppLog.Path).Length == 1);
    var crash = Path.Combine(tdir, "crash.log");
    File.WriteAllText(crash, $@"System.Exception at {home}\src\x.cs");
    var counts = new Bastion.Shell.DiagnosticsCounts(2, 3, new Dictionary<string, int> { ["ssh"] = 2, ["rdp"] = 1 });
    var inputs = new Bastion.Shell.DiagnosticsBundle.Inputs(Bastion.Shell.DiagnosticsBundle.Summary("1.2.3", "10.0.22631", counts, DateTimeOffset.UnixEpoch),
        settings, [Bastion.Shell.AppLog.Path], crash, home, "alice", "ALICE-PC");
    var zipPath = Path.Combine(tdir, "d.zip");
    Bastion.Shell.DiagnosticsBundle.Write(inputs, zipPath);
    using (var zip = System.IO.Compression.ZipFile.OpenRead(zipPath))
    {
        var names = zip.Entries.Select(e => e.FullName).OrderBy(n => n).ToList();
        var text = string.Concat(zip.Entries.Select(e => new StreamReader(e.Open()).ReadToEnd()));
        Step("diagnostics: the zip holds summary, settings, log and last crash", names.SequenceEqual(new[] { "Bastion diagnostics/bastion.log", "Bastion diagnostics/last-crash.log", "Bastion diagnostics/settings.json", "Bastion diagnostics/summary.txt" }), string.Join(",", names));
        Step("diagnostics: no secret, host, profile, account or computer name", !text.Contains("hunter2") && !text.Contains("db-prod") && !text.Contains("alice", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("ALICE-PC", StringComparison.OrdinalIgnoreCase) && text.Contains(@"~\AppData") && text.Contains("  ssh: 2") && text.Contains("Connections: 3"));
    }
    Step("diagnostics: no partial file left", !File.Exists(zipPath + ".partial"));
    Step("diagnostics: a folder that cannot be written throws, leaves nothing", Throws(() => Bastion.Shell.DiagnosticsBundle.Write(inputs, Path.Combine(tdir, "missing", "d.zip"))));
}
finally { Bastion.Shell.AppLog.Path = null; Directory.Delete(tdir, true); }
static bool Throws(Action a) { try { a(); return false; } catch (IOException) { return true; } catch (UnauthorizedAccessException) { return true; } }

// ---- 4. The real core ----
if (!args.Contains("--no-core"))
{
    var core = Array.IndexOf(args, "--core") is >= 0 and var at && at + 1 < args.Length ? Path.GetFullPath(args[at + 1]) : "";
    if (!File.Exists(core)) { Console.WriteLine("ERROR give --core <path to bastion_cabi> or --no-core"); return 2; }
    // The interop sources are compiled into this program, so one resolver covers them and the Test class below.
    NativeLibrary.SetDllImportResolver(typeof(LibraryClient).Assembly, (name, _, _) => name == "bastion_cabi" ? NativeLibrary.Load(core) : IntPtr.Zero);
    // --seed <data dir> <transcript file>: one ended SSH session with that transcript, for the transcript UI test.
    if (Array.IndexOf(args, "--seed") is >= 0 and var si && si + 2 < args.Length)
    {
        var seedDir = Path.GetFullPath(args[si + 1]);
        var seedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 120_000;
        var seedId = Test.Begin(seedDir, $$"""{"connectionId":"{{Guid.NewGuid()}}","connectionName":"transcript-fit","folderPath":[],"protocol":"ssh","host":"lab","loginSource":"typed","startedAt":{{seedAt}},"app":"native-windows","appVersion":"t","deviceName":"t"}""");
        Test.End(seedDir, seedId, System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object> { ["endReason"] = "closed_by_user", ["connectedAt"] = seedAt + 500, ["endedAt"] = seedAt + 60_000, ["transcriptPath"] = Path.GetFullPath(args[si + 2]) }));
        Console.WriteLine("SEEDED " + seedId);
        return 0;
    }
    var dir = Path.Combine(Path.GetTempPath(), "bastion-activity-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        string Begin(string name, string protocol, long when) => Test.Begin(dir, $$"""{"connectionId":"{{Guid.NewGuid()}}","connectionName":"{{name}}","folderPath":[],"protocol":"{{protocol}}","host":"lab","loginSource":"typed","startedAt":{{when}},"app":"native-windows","appVersion":"t","deviceName":"t"}""");
        var t0 = DateTimeOffset.Now.ToUnixTimeMilliseconds() - 120_000;
        var a = Begin("one", "ssh", t0); Test.End(dir, a, $$"""{"endReason":"auth_failed","endedAt":{{t0 + 1000}}}""");
        var b = Begin("two", "ssh", t0 + 2000); Test.End(dir, b, $$"""{"endReason":"closed_by_user","connectedAt":{{t0 + 2500}},"endedAt":{{t0 + 62_500}}}""");
        var c = Begin("three", "rdp", t0 + 3000); Test.End(dir, c, $$"""{"endReason":"network_lost","connectedAt":{{t0 + 3500}},"endedAt":{{t0 + 4500}}}""");
        var all = ActivityClient.Query(dir, new ActivityFilter(), 0);
        Step("core: three sessions, newest first", all.Count == 3 && all[0].ConnectionName == "three" && all[2].ConnectionName == "one", string.Join(",", all.Select(x => x.ConnectionName)));
        Step("core: results and durations", all.Count == 3 && ActivityFormat.Result(all[2]) == "Sign-in failed" && ActivityFormat.Result(all[1]) == "Closed"
            && ActivityFormat.Duration(all[1].DurationMs) == "1 min" && ActivityFormat.Result(all[0]) == "Network lost",
            string.Join(",", all.Select(x => ActivityFormat.Result(x) + "/" + ActivityFormat.Duration(x.DurationMs))));
        var rdp = ActivityClient.Query(dir, new ActivityFilter(Protocol: "rdp", From: ActivityFormat.RangeStart("week", DateTimeOffset.Now)), 0);
        Step("core: RDP in the last 7 days is only the RDP session", rdp is [{ ConnectionName: "three" }], string.Join(",", rdp.Select(x => x.ConnectionName)));
        Step("core: result filter failed", ActivityClient.Query(dir, new ActivityFilter(Result: "failed"), 0).Count == 2);
        Step("core: paging", ActivityClient.Query(dir, new ActivityFilter(), 1, 1) is [{ ConnectionName: "two" }]);
        var check0 = AuditClient.Verify(dir);
        Step("core: a folder with no audit log is empty and intact", check0 == new AuditCheckDto(true, 0, null) && AuditClient.Read(dir, 0).Total == 0);
        ActivityClient.Housekeep(dir);
        Step("core: housekeeping keeps recent history", ActivityClient.Query(dir, new ActivityFilter(), 0).Count == 3);
    }
    finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
}

// ---- 5. The app's own recorder for RDP, VNC and web (MainWindow.SessionActivity.cs) ----
const string sampleConnectionId = "5c1b7e0a-3f4d-4c8e-9a21-0b6d7e8f9a10", sampleFolderId = "7f1d2c3b-4a5e-4b6c-8d9e-1a2b3c4d5e6f";
var startSample = new ActivityClient.SessionStart(sampleConnectionId, "Web", [new(sampleFolderId, "Ops")], "web", "intranet", 8443, null, [], ActivityClient.LoginSourceFor("web", false), 5, "native-windows", "1", "pc");
var startJson = ActivityClient.StartJson(startSample);
Step("start JSON uses the core's names", startJson.Contains($"\"connectionId\":\"{sampleConnectionId}\"") && startJson.Contains($"\"folderPath\":[{{\"id\":\"{sampleFolderId}\",\"name\":\"Ops\"}}]")
    && startJson.Contains("\"loginSource\":\"typed\"") && !startJson.Contains("\"username\""), startJson);
Step("end JSON leaves connectedAt out for a failed connect", ActivityClient.EndJson(new(null, 9, "auth_failed")) == "{\"endedAt\":9,\"endReason\":\"auth_failed\"}",
    ActivityClient.EndJson(new(null, 9, "auth_failed")));
Step("the login source is never unknown (the core refuses it)", ActivityClient.LoginSourceFor("rdp", true) == "own" && ActivityClient.LoginSourceFor("rdp", false) == "typed" && ActivityClient.LoginSourceFor("vnc", true) == "typed" && ActivityClient.LoginSourceFor("web", false) == "typed");
Step("failure reasons map", ActivityClient.FailureReason("Authentication failed") == "auth_failed" && ActivityClient.FailureReason("Timed out") == "timeout" && ActivityClient.FailureReason("Refused") == "failed");
if (!args.Contains("--no-core"))
{
    var dir5 = Path.Combine(Path.GetTempPath(), "bastion-activity-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir5);
    try
    {
        var appNow = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 60_000;
        foreach (var (proto, reason, connected) in new[] { ("rdp", "remote_closed", true), ("vnc", "auth_failed", false), ("web", "closed_by_user", true) })
        {
            var id = ActivityClient.Begin(dir5, startSample with { ConnectionName = proto + "-1", Protocol = proto, StartedAt = appNow });
            ActivityClient.End(dir5, id, new(connected ? appNow + 500 : null, appNow + 30_000, reason));
        }
        var rows = ActivityClient.Query(dir5, new ActivityFilter(), 0);
        Step("core: RDP, VNC and web sessions recorded by the app", rows.Count == 3 && rows.Select(r => r.Protocol).OrderBy(x => x).SequenceEqual(["rdp", "vnc", "web"]),
            string.Join(",", rows.Select(r => r.Protocol + "/" + r.EndReason)));
        Step("core: the failed VNC connect has no connected time", rows.FirstOrDefault(r => r.Protocol == "vnc") is { ConnectedAt: null, EndReason: "auth_failed", Open: false });
        Step("core: the web session is closed by the user, 29.5 s", rows.FirstOrDefault(r => r.Protocol == "web") is { EndReason: "closed_by_user", DurationMs: 29_500 },
            rows.FirstOrDefault(r => r.Protocol == "web")?.DurationMs?.ToString() ?? "none");
    }
    catch (BastionException e) { Step("core: app recorder", false, e.Message); }
    finally { try { Directory.Delete(dir5, true); } catch (IOException) { } }
}

foreach (var r in results) Console.WriteLine(r);
var failed = results.Count(r => r.StartsWith("FAIL"));
Console.WriteLine($"{results.Count - failed} passed, {failed} failed");
return failed == 0 ? 0 : 1;

/// <summary>Writes test sessions; the app itself never begins SSH sessions (the core records those).</summary>
static class Test
{
    [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_activity_begin([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);

    [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
    private static extern int bastion_activity_end([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);

    public static string Begin(string dir, string json) => LibraryClient.TakeString(bastion_activity_begin(dir, json, out var err), err);

    public static void End(string dir, string id, string json)
    {
        if (bastion_activity_end(dir, id, json, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "end failed"));
    }
}

