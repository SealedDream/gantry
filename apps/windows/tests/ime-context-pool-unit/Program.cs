using Bastion.Shell;

// Unit tests for ImeContextPool (spare TSF edit contexts per window). One PASS or FAIL line per test; exit code = failures.
var failures = 0;
void Test(string name, Func<bool> body)
{
    bool ok;
    try { ok = body(); } catch (Exception) { ok = false; }
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (!ok) failures++;
}

const ulong Main = 0x1001, TornOff = 0x2002;

Test("an empty pool has nothing to take", () => new ImeContextPool<object>().Take(Main) is null);

Test("a clean context handed back is taken by the next terminal of the same window", () =>
{
    var pool = new ImeContextPool<object>();
    var ctx = new object();
    return pool.Return(Main, ctx, clean: true) && ReferenceEquals(pool.Take(Main), ctx) && pool.Take(Main) is null;
});

Test("a context that delivered text or lost its focus is not kept (stuck pane, WIN-FORGOTTEN-01)", () =>
{
    var pool = new ImeContextPool<object>();
    return !pool.Return(Main, new object(), clean: false) && pool.Take(Main) is null && pool.SpareCount(Main) == 0;
});

Test("a context with no known window is not kept", () =>
{
    var pool = new ImeContextPool<object>();
    return !pool.Return(0, new object(), clean: true) && pool.Take(0) is null;
});

Test("contexts are kept per window and never cross to another window", () =>
{
    var pool = new ImeContextPool<object>();
    var a = new object();
    pool.Return(Main, a, clean: true);
    return pool.Take(TornOff) is null && ReferenceEquals(pool.Take(Main), a);
});

Test("the same context handed back twice is kept once", () =>
{
    var pool = new ImeContextPool<object>();
    var ctx = new object();
    pool.Return(Main, ctx, clean: true);
    pool.Return(Main, ctx, clean: true);
    return pool.SpareCount(Main) == 1;
});

Test("a closed window's spare contexts are dropped, other windows keep theirs", () =>
{
    var pool = new ImeContextPool<object>();
    pool.Return(Main, new object(), clean: true);
    pool.Return(TornOff, new object(), clean: true);
    pool.Forget(TornOff);
    return pool.SpareCount(TornOff) == 0 && pool.Take(TornOff) is null && pool.SpareCount(Main) == 1;
});

Test("a context handed back for a closed window is not kept (its tab moved back to the main window)", () =>
{
    var pool = new ImeContextPool<object>();
    pool.Forget(TornOff);
    return !pool.Return(TornOff, new object(), clean: true) && pool.SpareCount(TornOff) == 0;
});

Test("a window id asked for again is open again (window ids can be reused)", () =>
{
    var pool = new ImeContextPool<object>();
    pool.Forget(TornOff);
    _ = pool.Take(TornOff);
    var ctx = new object();
    return pool.Return(TornOff, ctx, clean: true) && ReferenceEquals(pool.Take(TornOff), ctx);
});

Test("open 10, close 10, many times: the pool never holds more than the most terminals open at once", () =>
{
    // The q-mem-long cycle: 10 terminals take a context each (from the pool, or new when it is empty), then all close.
    var pool = new ImeContextPool<object>();
    var made = 0;
    for (var cycle = 0; cycle < 150; cycle++)
    {
        var open = new List<object>();
        for (var i = 0; i < 10; i++) open.Add(pool.Take(Main) ?? new object[] { made++ });
        foreach (var ctx in open) pool.Return(Main, ctx, clean: true);
    }
    return made == 10 && pool.SpareCount(Main) == 10;
});

return failures;
