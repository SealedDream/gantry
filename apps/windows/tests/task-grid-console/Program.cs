using Bastion.Shell;

var failures = 0;
void Check(bool ok, string what) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {what}"); if (!ok) failures++; }

var a = new TaskGridRow("1", "web-01", "done", 0, " 10:00 up 3 days, load 0.1\n", Millis: 420);
var b = new TaskGridRow("2", "web-02", "done", 0, " 10:00 up 3 days, load 0.1\n", Millis: 380);
var c = new TaskGridRow("3", "db-01", "done", 2, "", "df: /x: No such file\n", Millis: 1500);
var d = new TaskGridRow("4", "db-02", "running");
var e = new TaskGridRow("5", "old", "failed", Error: "host key not trusted yet: connect once\nmore");

Check(a.Status == GridStatus.Ok && c.Status == GridStatus.Failed && d.Status == GridStatus.Running && e.Status == GridStatus.Failed, "status from state and exit code");
Check(new TaskGridRow("x", "x", "starting").Status == GridStatus.Waiting, "starting is waiting");
Check(a.Summary == "10:00 up 3 days, load 0.1", "summary is the last non-empty line");
Check(c.Summary == "df: /x: No such file", "failed with only stderr: first stderr line");
Check(e.Summary == "host key not trusted yet: connect once", "error: its first line");

var g = TaskGrid.Groups([a, c, b, d, new TaskGridRow("6", "db-03", "running")]);
Check(g.Count == 4, "identical output folds into one group; running rows stay alone");
Check(g[0].IsGroup && g[0].Rows.Select(r => r.Host).SequenceEqual(["web-01", "web-02"]) && g[0].Title == "2 hosts", "group keeps order and names");
Check(!g[1].IsGroup && g[1].Title == "db-01", "single row titled by host");
var a3 = a with { Exit = 1, State = "done" };
Check(TaskGrid.Groups([a, a3]).Count == 2, "same output, other exit code: not grouped");

var diff = TaskGrid.Diff("one\ntwo\nthree\n", "one\n2\nthree\nfour\n");
Check(diff.SequenceEqual([new DiffLine(DiffKind.Same, "one"), new DiffLine(DiffKind.Left, "two"), new DiffLine(DiffKind.Right, "2"),
    new DiffLine(DiffKind.Same, "three"), new DiffLine(DiffKind.Right, "four")]), "line diff marks changes");
Check(TaskGrid.Diff("", "").Count == 0, "empty diff");
var big = string.Join("\n", Enumerable.Range(0, 2500));
Check(TaskGrid.Diff(big, big).Count == 2500 + 500, "diff is bounded: lines past the cap shown as changed");

var all = TaskGrid.Labelled([a, c]);
Check(all.StartsWith("== web-01 (exit 0, 420 ms) ==\n 10:00 up", StringComparison.Ordinal), "labelled copy header");
Check(all.Contains("== db-01 (exit 2, 1.5 s) ==\ndf: /x", StringComparison.Ordinal), "labelled copy per host");
Check(TaskGrid.Duration(125_000) == "2 m 5 s", "minutes");

Check(TaskGrid.IsOvertime(d, 31, 30) && !TaskGrid.IsOvertime(a, 99, 30), "overtime only while running");
Check(TaskGrid.Tally([a, b, c, d]) == "2 ok · 1 failed · 1 running", "tally");
var t = a with { Stdout = "x\n[output truncated by Bastion]" };
Check(t.IsTruncated && !a.IsTruncated, "truncated flag");
// Windows extra: the overtime limit is the task's own, never under 30 s (Mac brief: max(task timeout, 30 s)).
Check(TaskGrid.OvertimeLimit(10) == 30 && TaskGrid.OvertimeLimit(120) == 120, "overtime limit is max(timeout, 30 s)");

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
