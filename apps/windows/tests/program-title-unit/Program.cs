using Bastion.Shell;

// Unit tests for ProgramTitle (terminal tab names from OSC 0/2). One PASS or FAIL line per test; exit code = failures.
var failures = 0;
void Test(string name, Func<bool> body)
{
    bool ok;
    try { ok = body(); } catch (Exception) { ok = false; }
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (!ok) failures++;
}

Test("SEC-7 program title marked", () => ProgramTitle.Marked("vim") == "\u203A vim");
Test("SEC-7 fake bell dropped", () => ProgramTitle.Marked("\U0001F514 Command finished") == "\u203A Command finished");
Test("SEC-7 no doubled mark", () => ProgramTitle.Marked("\u203A\u203A x") == "\u203A x");
Test("SEC-7 symbol only gives no name", () => ProgramTitle.Marked("\u25CF") is null);
Test("SEC-7 notice heading is the source", () => ProgramTitle.Notice("web1", "Gantry", "Vault locked") == ("web1 \u00B7 terminal", "Gantry: Vault locked"));
Test("SEC-7 notice body only", () => ProgramTitle.Notice("web1", "", "done") == ("web1 \u00B7 terminal", "done"));
Test("null and empty give no name", () => ProgramTitle.Clean(null) is null && ProgramTitle.Clean("") is null);
Test("white space only gives no name", () => ProgramTitle.Clean(" \t ") is null);
Test("plain title kept", () => ProgramTitle.Clean("user@web-01: ~") == "user@web-01: ~");
Test("leading and trailing space trimmed, inner runs collapsed", () => ProgramTitle.Clean("  a   b  ") == "a b");
Test("control characters removed", () => ProgramTitle.Clean("a\u001b[31mb\u0007c\nd") == "a[31mbcd");
Test("bidi overrides and marks removed", () => ProgramTitle.Clean("ab‮cd‏ef⁦g⁩") == "abcdefg");
Test("only control characters gives no name", () => ProgramTitle.Clean("\u0001‮") is null);
Test("60 characters kept as is", () => ProgramTitle.Clean(new string('x', 60)) == new string('x', 60));
Test("61 characters cut to 59 and an ellipsis", () => ProgramTitle.Clean(new string('x', 61)) == new string('x', 59) + "…");
Test("a long title is cut to 60 characters", () => ProgramTitle.Clean(new string('y', 500))!.Length == 60);
Test("a surrogate pair at the cut is not split",
    () => ProgramTitle.Clean(new string('x', 57) + "\U0001F600" + new string('x', 10)) is { } s && !char.IsHighSurrogate(s[^2]) && s.EndsWith('…'));

return failures;
