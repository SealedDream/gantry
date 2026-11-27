using System.Diagnostics;
using System.Runtime.InteropServices;
using Bastion.Shell;
using Bastion.Shell.Interop;

// PLUG-06c (Native Windows): console checks of the SQL editor's logic and of the core's tokenizer and completion
// exports (C ABI 136). No window, no network, no secrets.
// Usage: sql-editor-console --core <path to bastion_cabi.dll or .dylib> | --no-core. Exit 1 on a failure.
var results = new List<string>();
void Step(string name, bool ok, string detail = "") => results.Add($"{(ok ? "PASS" : "FAIL")} {name}{(detail.Length > 0 ? " (" + detail + ")" : "")}");

// A stand-in tokenizer: "/*" opens a comment state that runs until "*/"; every line is one token.
HighlightLine Fake(string line, string state)
{
    var inside = state == "c";
    var open = line.LastIndexOf("/*", StringComparison.Ordinal);
    var close = line.LastIndexOf("*/", StringComparison.Ordinal);
    if (open >= 0 && open > close) inside = true;
    else if (close >= 0) inside = false;
    return new([new(inside ? "comment" : "text", 0, line.Length)], inside ? "c" : "");
}

// ---- 1. Incremental colouring ----
{
    var m = new SqlEditorModel("postgresql", Fake);
    var lines = Enumerable.Range(0, 100).Select(i => $"select {i};").ToArray();
    m.Update(string.Join('\r', lines));
    Step("first update colours every line", m.LineCount == 100 && m.LastTokenized == 100, $"{m.LastTokenized}");
    lines[50] = "select 50 + 1;";
    var changed = m.Update(string.Join('\r', lines));
    Step("editing one line re-colours only it", changed.Count == 1 && changed[0] == 50 && m.LastTokenized == 1, string.Join(",", changed));
    lines[10] = "/* open";
    changed = m.Update(string.Join('\r', lines));
    Step("opening a block comment re-colours every line below", m.LastTokenized == 90 && m.EndState(99) == "c", $"{m.LastTokenized}");
    lines[10] = "select 10;";
    m.Update(string.Join('\r', lines));
    Step("closing it re-colours them back", m.LastTokenized == 90 && m.EndState(99) == "" && m.Tokens(99)[0].Kind == "text");
    var inserted = lines.Take(20).Append("select 'new';").Concat(lines.Skip(20)).ToArray();
    changed = m.Update(string.Join('\r', inserted));
    Step("inserting a line colours it alone", m.LineCount == 101 && changed.Count == 1 && changed[0] == 20, string.Join(",", changed));
    var removed = inserted.Take(30).Concat(inserted.Skip(35)).ToArray();
    m.Update(string.Join('\r', removed));
    Step("deleting lines re-colours one line", m.LineCount == 96 && m.LastTokenized == 1, $"{m.LastTokenized}");
    Step("line starts count one break per line", m.LineStart(2) == removed[0].Length + removed[1].Length + 2);
    var fresh = new SqlEditorModel("postgresql", Fake);
    fresh.Update(string.Join('\r', removed));
    var same = Enumerable.Range(0, m.LineCount).All(i => m.EndState(i) == fresh.EndState(i) && m.Tokens(i)[0].Kind == fresh.Tokens(i)[0].Kind);
    Step("after edits the states equal a fresh colouring", same);
    m.Update("a\nb\r\nc");
    Step("\\n and \\r\\n count as breaks", m.LineCount == 3 && m.LineText(2) == "c");
    m.Update("");
    Step("empty text is one empty line", m.LineCount == 1 && m.LineText(0) == "");
}

// ---- 2. Comment toggle (Ctrl+/) ----
{
    var r = SqlEditorModel.ToggleLineComment("select 1;\r  select 2;", 0, 12);
    Step("comment two lines, keeping indentation", r.Text == "-- select 1;\r  -- select 2;", r.Text);
    var back = SqlEditorModel.ToggleLineComment(r.Text, r.SelectionStart, r.SelectionLength);
    Step("toggle again uncomments", back.Text == "select 1;\r  select 2;", back.Text);
    var cursor = SqlEditorModel.ToggleLineComment("a\rbb\rc", 3, 0);
    Step("cursor only: its line", cursor.Text == "a\r-- bb\rc" && cursor.SelectionStart == 6, $"{cursor.Text}|{cursor.SelectionStart}");
    var mixed = SqlEditorModel.ToggleLineComment("-- a\rb", 0, 6);
    Step("a mix comments all lines", mixed.Text == "-- -- a\r-- b", mixed.Text);
    var endAtStart = SqlEditorModel.ToggleLineComment("a\rb", 0, 2);
    Step("a selection ending at a line start leaves that line", endAtStart.Text == "-- a\rb", endAtStart.Text);
    var noSpace = SqlEditorModel.ToggleLineComment("--x", 0, 0);
    Step("uncomment without a space", noSpace.Text == "x", noSpace.Text);
}

// ---- 3. Indent (Tab, Shift+Tab) ----
{
    var t = SqlEditorModel.Indent("ab", 1, 0, outdent: false);
    Step("Tab inserts four spaces at the cursor", t.Text == "a    b" && t.SelectionStart == 5);
    var block = SqlEditorModel.Indent("a\r\rb", 0, 4, outdent: false);
    Step("Tab on lines indents each, skipping empty ones", block.Text == "    a\r\r    b" && block.SelectionStart == 0 && block.SelectionLength == 12, $"{block.Text}|{block.SelectionLength}");
    var o = SqlEditorModel.Indent(block.Text, 0, block.Text.Length, outdent: true);
    Step("Shift+Tab outdents them back", o.Text == "a\r\rb", o.Text);
    var two = SqlEditorModel.Indent("  a", 3, 0, outdent: true);
    Step("Shift+Tab removes what indentation there is", two.Text == "a" && two.SelectionStart == 1, $"{two.Text}|{two.SelectionStart}");
}

// ---- 4. Completion insert ----
{
    var ctx = new CompletionContext(true, "sel", 7, 3, 10);
    var r = SqlEditorModel.ApplyCompletion("select sel", ctx, new("SELECT", "SELECT", "keyword"));
    Step("a choice replaces the typed prefix", r.Text == "select SELECT" && r.SelectionStart == 13, r.Text);
    var multi = SqlEditorModel.ApplyCompletion("x", new(true, "x", 0, 1, 1), new("snippet", "a\nb", ""));
    Step("a multi-line insert uses the editor's break", multi.Text == "a\rb" && multi.SelectionStart == 3);
    var empty = SqlEditorModel.ApplyCompletion("x", new(true, "x", 0, 1, 1), new("lbl", "", ""));
    Step("an empty insert inserts the label", empty.Text == "lbl");
    var wild = SqlEditorModel.ApplyCompletion("ab", new(true, "", 99, 99, 0), new("z", "z", ""));
    Step("a range past the end is clamped", wild.Text == "abz");
}

// ---- 5. Undo history ----
{
    var h = new EditHistory(new("", 0, 0));
    h.Record(new("s", 1, 0), join: false);
    h.Record(new("se", 2, 0), join: true);
    h.Record(new("sel", 3, 0), join: true);
    h.Record(new("sel ", 4, 0), join: false);
    Step("typed word is one undo step", h.Undo()?.Text == "sel" && h.Undo()?.Text == "" && !h.CanUndo);
    Step("redo walks forward", h.Redo()?.Text == "sel" && h.Redo()?.Text == "sel " && !h.CanRedo);
    h.Undo();
    h.Record(new("selx", 4, 0), join: false);
    Step("a new edit clears redo", !h.CanRedo);
    var big = new EditHistory(new("", 0, 0));
    for (var i = 0; i < EditHistory.MaxSteps + 50; i++) big.Record(new(i.ToString(), 0, 0), join: false);
    var n = 0;
    while (big.Undo() is not null) n++;
    Step("history keeps at most MaxSteps", n == EditHistory.MaxSteps, $"{n}");
    var heavy = new EditHistory(new("", 0, 0));
    var chunk = new string('x', 3 * 1024 * 1024);
    for (var i = 0; i < 5; i++) heavy.Record(new(chunk + i, 0, 0), join: false);
    n = 0;
    while (heavy.Undo() is not null) n++;
    Step("history is bounded by total characters", n <= 3, $"{n}");
}

// ---- 6. Palette ----
Step("plain text keeps the theme colour", SqlEditorPalette.Colour("text", false) is null && SqlEditorPalette.Colour("identifier", true) is null);
Step("every coloured kind has light and dark", new[] { "keyword", "type", "function", "string", "quoted-identifier", "number", "comment", "parameter", "operator", "punctuation", "error" }
    .All(k => SqlEditorPalette.Colour(k, false) is not null && SqlEditorPalette.Colour(k, true) is not null && SqlEditorPalette.Colour(k, false) != SqlEditorPalette.Colour(k, true)));

// ---- 7. The real core ----
if (!args.Contains("--no-core"))
{
    var core = Array.IndexOf(args, "--core") is >= 0 and var at && at + 1 < args.Length ? Path.GetFullPath(args[at + 1]) : "";
    if (!File.Exists(core)) { Console.WriteLine("ERROR give --core <path to bastion_cabi> or --no-core"); return 2; }
    NativeLibrary.SetDllImportResolver(typeof(HighlightClient).Assembly, (name, _, _) => name == "bastion_cabi" ? NativeLibrary.Load(core) : IntPtr.Zero);

    var line = HighlightClient.Line("postgresql", "SELECT 'a', 1 -- c", "");
    Step("core: keyword, string, number, comment", line.Tokens.Any(t => t.Kind == "keyword") && line.Tokens.Any(t => t.Kind == "string")
        && line.Tokens.Any(t => t.Kind == "number") && line.Tokens.Any(t => t.Kind == "comment"), string.Join(" ", line.Tokens.Select(t => t.Kind)));
    var emoji = "SELECT '😀é' AS x";
    var spans = HighlightClient.Line("postgresql", emoji, "").Tokens;
    var covers = spans.Count > 0 && spans[0].Start == 0 && spans.Zip(spans.Skip(1)).All(p => p.First.Start + p.First.Length == p.Second.Start)
        && spans[^1].Start + spans[^1].Length == emoji.Length;
    Step("core: UTF-16 spans cover a line with a four-byte character", covers, string.Join(" ", spans.Select(t => $"{t.Kind}@{t.Start}+{t.Length}")));
    Step("core: no span splits a surrogate pair", spans.All(t => !char.IsLowSurrogate(emoji[t.Start])));
    var open = HighlightClient.Line("postgresql", "/* open", "");
    var next = HighlightClient.Line("postgresql", "still", open.EndState);
    Step("core: a block comment carries to the next line", open.EndState != "" && next.Tokens.All(t => t.Kind == "comment"), open.EndState);
    var dollar = HighlightClient.Line("postgresql", "AS $fn$ BEGIN", "");
    Step("core: a dollar-quoted body carries", dollar.EndState.Length > 0, dollar.EndState);
    Step("core: an unknown language is plain text", HighlightClient.Line("cobol", "SELECT 1", "").Tokens.All(t => t.Kind == "text"));
    Step("core: a damaged state reads as normal", HighlightClient.Line("postgresql", "SELECT", "zz!!").Tokens.Any(t => t.Kind == "keyword"));
    Step("core: a NUL does not cut the line", HighlightClient.Line("postgresql", "SELECT\0 1", "").Tokens.Sum(t => t.Length) == 9);

    // The editor's model over the real tokenizer equals the whole-text helper.
    var text = "CREATE FUNCTION f() RETURNS int AS $$\rBEGIN /* x\r y */ RETURN 1;\rEND $$ LANGUAGE plpgsql;\rSELECT f()::text, $1;";
    var real = new SqlEditorModel("postgresql");
    real.Update(text);
    var whole = HighlightClient.Text("postgresql", text.Replace('\r', '\n')).Tokens;
    var byLine = Enumerable.Range(0, real.LineCount).SelectMany(i => real.Tokens(i).Select(t => (t.Kind, Start: t.Start + real.LineStart(i), t.Length)))
        .Where(t => t.Length > 0).ToList();
    var wholeList = whole.Select(t => (t.Kind, t.Start, t.Length)).Where(t => t.Length > 0 && !(t.Kind == "text" && t.Length == 1 && text[t.Start] == '\r')).ToList();
    var equal = byLine.Where(t => t.Kind != "text").SequenceEqual(wholeList.Where(t => t.Kind != "text"));
    Step("core: line by line equals whole text", equal, $"{byLine.Count} vs {wholeList.Count}");

    var ctx = HighlightClient.Context("postgresql", "SELECT na", 9);
    Step("core: completion context at a word", ctx.Ask && ctx.Prefix == "na" && ctx.ReplaceStart == 7 && ctx.ReplaceLength == 2, $"{ctx}");
    var inString = HighlightClient.Context("postgresql", "SELECT 'na", 10);
    Step("core: no completions inside a string", !inString.Ask);
    var ranked = HighlightClient.Rank([new("NOW", "now()", "function"), new("name", "name", "column"), new("other", "", ""), new("rename", "rename", "")], "na");
    Step("core: ranking filters and orders", ranked.Count == 2 && ranked[0].Label == "name" && ranked[1].Label == "rename", string.Join(",", ranked.Select(r => r.Label)));
    var weird = HighlightClient.Rank([new("a\"b\\c", "x\ny", "d")], "");
    Step("core: quotes and breaks survive the JSON round trip", weird.Count == 1 && weird[0].Label == "a\"b\\c" && weird[0].Insert == "x\ny");

    // Speed: the editor's per-keystroke work is one line plus the walk; a 1 MiB file is coloured once at open.
    var big = string.Join('\r', Enumerable.Range(0, 20000).Select(i => $"SELECT col_{i}, 'text {i}' FROM t WHERE id = {i};"));
    var sw = Stopwatch.StartNew();
    var model = new SqlEditorModel("postgresql");
    model.Update(big);
    var openMs = sw.ElapsedMilliseconds;
    var lines2 = SqlEditorModel.SplitLines(big);
    lines2[10000] = "SELECT 1;";
    sw.Restart();
    model.Update(string.Join('\r', lines2));
    var keyMs = sw.Elapsed.TotalMilliseconds;
    Step("core: one-line edit in a ~1 MiB text re-colours one line", model.LastTokenized == 1, $"open {openMs} ms for {big.Length} chars, edit {keyMs:F1} ms");
}

foreach (var r in results) Console.WriteLine(r);
var failed = results.Count(r => r.StartsWith("FAIL", StringComparison.Ordinal));
Console.WriteLine($"{results.Count - failed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
