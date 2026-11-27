using Bastion.Shell;

var failures = 0;
void Check(bool ok, string name)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (!ok) failures++;
}
string? V(string state, int? exit, string o = "", string e = "", string? err = null) => HookGate.StopReason("Gate", "web-1", state, exit, o, e, err);

Check(V("done", 0) is null, "done with exit 0 connects");
Check(V("done", 1, e: "no VPN\n") is { } a && a.Contains("exited with 1") && a.EndsWith("no VPN") && a.Contains("web-1"), "exit 1 stops and quotes stderr");
Check(V("done", 2, o: "stdout only") is { } b && b.EndsWith("stdout only"), "falls back to stdout");
Check(V("failed", null, err: "program not found") is { } c && c.Contains("failed") && c.EndsWith("program not found"), "start failure stops with the error");
Check(V("timed_out", null) is { } d && d.Contains("timed out"), "timeout stops");
Check(V("cancelled", null) is { } f && f.Contains("cancelled"), "cancel stops");
Check(V("done", 1, e: new string('x', 5000)) is { } g && g.Length < HookGate.QuotedOutputLimit + 200, "long output is cut to its tail");
Check(V("running", null) is not null, "a run still going never counts as success");

var batch = new HookBatch();
Check(batch.Claim("f", "t", "after_connect"), "first host of a Connect All runs the multi-host hook");
Check(!batch.Claim("f", "t", "after_connect"), "second host does not run it again");
Check(batch.Claim("f", "t", "before_connect"), "another moment is its own hook");
Check(batch.Claim("g", "t", "after_connect"), "another folder is its own hook");

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
