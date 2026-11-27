using Bastion.Shell;

// Unit tests for RowEdits (WIN-TREE-REBUILD). One PASS or FAIL line per test; exit code = failures.
var failures = 0;
void Test(string name, Func<bool> body)
{
    bool ok;
    try { ok = body(); } catch (Exception) { ok = false; }
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (!ok) failures++;
}

static List<Row> Rows(int n) => Enumerable.Range(0, n).Select(i => new Row("r" + i)).ToList();

// Applying the plan to a copy of the old rows gives exactly the new rows, object for object.
static bool Reaches(List<Row> old, List<Row> rows, int limit, out int edits)
{
    edits = -1;
    var plan = RowEdits.Plan(old, rows, limit);
    if (plan is null) return false;
    edits = plan.Count;
    var list = new List<Row>(old);
    RowEdits.Apply(list, plan);
    return list.Count == rows.Count && list.Zip(rows).All(p => ReferenceEquals(p.First, p.Second));
}

Test("same rows (identical objects): no edits", () =>
{
    var old = Rows(40);
    return Reaches(old, [.. old], 32, out var n) && n == 0;
});
Test("one row replaced in the middle: one Replace at its index", () =>
{
    var old = Rows(40);
    var rows = new List<Row>(old) { [17] = new Row("changed") };
    var plan = RowEdits.Plan(old, rows, 32);
    return plan is [{ Kind: RowEditKind.Replace, Index: 17 }] && Reaches(old, rows, 32, out _);
});
Test("changes spread over the list (top, middle, end): few edits, not a whole-list replace", () =>
{
    var old = Rows(200);
    var rows = new List<Row>(old);
    rows[3] = new Row("folder"); rows[120] = new Row("connection");
    rows.Insert(0, new Row("favorites")); rows.Insert(1, new Row("mirror"));
    rows[^1] = new Row("application");
    return Reaches(old, rows, 32, out var n) && n == 5;
});
Test("rows inserted and removed (a folder opened, a session row closed)", () =>
{
    var old = Rows(30);
    var rows = new List<Row>(old);
    rows.InsertRange(10, [new Row("a"), new Row("b"), new Row("c")]);
    rows.RemoveAt(25); rows.RemoveAt(25);
    return Reaches(old, rows, 32, out var n) && n == 5;
});
Test("from an empty list: inserts", () => { var rows = Rows(5); return Reaches([], rows, 32, out var n) && n == 5; });
Test("to an empty list: removes", () => { var old = Rows(5); return Reaches(old, [], 32, out var n) && n == 5; });
Test("a moved row: no plan (the list is replaced)", () =>
{
    var old = Rows(10);
    var rows = new List<Row>(old);
    var moved = rows[2]; rows.RemoveAt(2); rows.Insert(7, moved);
    return RowEdits.Plan(old, rows, 32) is null;
});
Test("more edits than the limit: no plan", () =>
{
    var old = Rows(100);
    var rows = old.Select((r, i) => i % 2 == 0 ? new Row("n" + i) : r).ToList();
    return RowEdits.Plan(old, rows, 32) is null;
});
Test("a size change larger than the limit: no plan, without walking the lists", () => RowEdits.Plan(Rows(10), Rows(100), 32) is null);
Test("the same row twice in a list: no plan", () =>
{
    var old = Rows(10);
    var rows = new List<Row>(old) { [5] = old[4] };
    return RowEdits.Plan(old, rows, 32) is null;
});
Test("all rows new (a search keystroke): no plan within the limit", () => RowEdits.Plan(Rows(60), Rows(60), 32) is null);
Test("random edits without moves always reach the new rows", () =>
{
    var random = new Random(1125);
    for (var round = 0; round < 2000; round++)
    {
        var old = Rows(random.Next(0, 60));
        var rows = new List<Row>();
        foreach (var r in old)
        {
            var roll = random.Next(10);
            if (roll == 0) continue;                                     // removed
            if (roll == 1) { rows.Add(new Row("x")); continue; }          // replaced
            if (roll == 2) rows.Add(new Row("y"));                        // inserted before
            rows.Add(r);
        }
        if (random.Next(3) == 0) rows.Add(new Row("tail"));
        if (!Reaches(old, rows, int.MaxValue, out var n)) return false;
        if (n > old.Count + rows.Count) return false;
    }
    return true;
});

return failures;

internal sealed class Row(string name)
{
    public string Name { get; } = name;
    public override string ToString() => Name;
}
