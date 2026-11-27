using Bastion.Shell;

// Unit tests for ItemExtrasEdits (the Icon and properties page). One PASS or FAIL line per test; exit code = failures.
var failures = 0;
void Test(string name, Action body)
{
    try { body(); Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failures++; Console.WriteLine($"FAIL {name}: {ex.Message}"); }
}
void Equal(string expected, string actual, string what)
{
    if (expected != actual) throw new InvalidOperationException($"{what}: expected [{expected}], got [{actual}]");
}
static CustomPropertyRow R(string n, string v) => new(n, v);
static string Show(IReadOnlyList<(string Name, string? Value)> calls) => string.Join("; ", calls.Select(c => c.Value is null ? $"-{c.Name}" : $"{c.Name}={c.Value}"));

Test("no change makes no calls", () =>
{
    var (calls, error) = ItemExtrasEdits.Changes([R("Rack", "R3")], [R("Rack", "R3")]);
    Equal("", Show(calls), "calls"); Equal("", error ?? "", "error");
});
Test("add, change and remove; removes come first", () =>
{
    var (calls, _) = ItemExtrasEdits.Changes([R("Rack", "R3"), R("Owner", "ops")], [R("Rack", "R4"), R("Asset tag", "A-1")]);
    Equal("-Owner; Rack=R4; Asset tag=A-1", Show(calls), "calls");
});
Test("names are trimmed; a renamed row removes the old name", () =>
{
    var (calls, _) = ItemExtrasEdits.Changes([R("Rack", "R3")], [R("  Shelf ", "R3")]);
    Equal("-Rack; Shelf=R3", Show(calls), "calls");
});
Test("an empty row is ignored", () =>
{
    var (calls, error) = ItemExtrasEdits.Changes([], [R(" ", "  ")]);
    Equal("", Show(calls), "calls"); Equal("", error ?? "", "error");
});
Test("a value without a name is refused and nothing is called", () =>
{
    var (calls, error) = ItemExtrasEdits.Changes([R("Rack", "R3")], [R("", "x")]);
    Equal("", Show(calls), "calls"); Equal("Enter a name for every custom property.", error ?? "", "error");
});
Test("two rows with one name (any case) are refused", () =>
{
    var (calls, error) = ItemExtrasEdits.Changes([], [R("Rack", "1"), R("rack", "2")]);
    Equal("", Show(calls), "calls"); Equal("\"rack\" is used twice.", error ?? "", "error");
});
Test("icon labels", () =>
{
    Equal("Database", ItemExtrasEdits.IconLabel("database"), "label"); Equal("", ItemExtrasEdits.IconLabel(""), "empty");
});
return failures;
