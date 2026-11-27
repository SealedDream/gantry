using System.Text.Json.Nodes;
using Bastion.Shell;

// PLUG-VIEW-WIN: checks PluginViewModel against the update and event JSON of core-ffi's plugin view (the same
// shapes Native Mac's PluginViewModel handles). Exit code = number of failures.
var failures = 0;
void Check(string name, bool ok)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (!ok) failures++;
}

var sent = new List<JsonObject>();
var m = new PluginViewModel("com.example.pg", json => sent.Add((JsonObject)JsonNode.Parse(json)!));
var changed = 0;
m.Changed += () => changed++;

// set-view: nodes parsed, other views ignored
m.ApplyText("""{"type":"set-view","view":1,"nodes":[{"id":1,"component":{"kind":"stack","value":"vertical"}},{"id":2,"parent":1,"component":{"kind":"label","value":"Hello"}},{"id":3,"parent":1,"component":{"kind":"button","value":{"label":"Go","enabled":true}}}]}""");
Check("set-view parses three nodes", m.Nodes.Count == 3 && m.Nodes[1].Kind == "label" && m.Nodes[1].Parent == 1);
Check("kids of the root stack", PluginViewModel.Kids(1, m.Nodes).Select(n => n.Id).SequenceEqual([2, 3]));
m.ApplyText("""{"type":"set-view","view":2,"nodes":[]}""");
Check("set-view of another view ignored", m.Nodes.Count == 3);
Check("bad JSON ignored", !m.ApplyText("{") && m.Nodes.Count == 3);
Check("node without component dropped", PluginViewModel.Parse(JsonNode.Parse("""[{"id":9}]""")).Count == 0);

// patch-view: replace, remove, add at the end
m.ApplyText("""{"type":"patch-view","view":1,"upsert":[{"id":2,"parent":1,"component":{"kind":"label","value":"Bye"}},{"id":4,"parent":1,"component":{"kind":"toggle","value":{"label":"On","value":true}}}],"remove":[3]}""");
Check("patch-view replaces, removes, appends", m.Nodes.Select(n => n.Id).SequenceEqual([1, 2, 4]) && m.Nodes[1].Value!.GetValue<string>() == "Bye");

// events
m.Pressed(3);
Check("pressed event", sent[^1].ToJsonString() == """{"type":"ui","view":1,"node":3,"input":{"kind":"pressed"}}""");
m.TextInput(5, "abc");
Check("text event", sent[^1]["input"]!["kind"]!.GetValue<string>() == "text" && sent[^1]["input"]!["value"]!.GetValue<string>() == "abc");
m.ToggleInput(4, false);
Check("toggled event", sent[^1]["input"]!["kind"]!.GetValue<string>() == "toggled" && !sent[^1]["input"]!["value"]!.GetValue<bool>());
m.ChoiceInput(6, 2);
Check("choice event", sent[^1]["input"]!["value"]!.GetValue<int>() == 2);
m.RunInput(7, "select 1");
Check("run event", sent[^1]["input"]!["kind"]!.GetValue<string>() == "run" && sent[^1]["input"]!["value"]!.GetValue<string>() == "select 1");

// dialogs
m.ApplyText("""{"type":"dialog","dialog":5,"title":"Edit","nodes":[{"id":1,"component":{"kind":"label","value":"x"}}]}""");
m.ApplyText("""{"type":"dialog","dialog":6,"title":"More","nodes":[]}""");
Check("two dialogs stacked", m.Dialogs.Count == 2 && m.Dialogs[^1].Title == "More");
m.ApplyText("""{"type":"close-dialog","dialog":5}""");
Check("close-dialog removes that dialog", m.Dialogs.Count == 1 && m.Dialogs[0].Id == 6);
m.DismissTopDialog();
Check("dismiss sends cancel", m.Dialogs.Count == 0 && sent[^1].ToJsonString() == """{"type":"cancel","view":1}""");

// confirm
m.ApplyText("""{"type":"confirm","request":11,"kind":"write","text":"Drop table t?","entry":{"name":"prod-db","environment":"production"}}""");
Check("confirm parsed with entry", m.PendingConfirm is { Id: 11, Kind: "write", Entry: "prod-db · production" });
m.Answer(m.PendingConfirm!, false);
Check("confirm answered no", m.PendingConfirm is null && sent[^1].ToJsonString() == """{"type":"confirm","request":11,"confirmed":false}""");

// refuse
m.ApplyText("""{"type":"refuse","message":"Not allowed"}""");
Check("refuse shows a message", m.Message == "Not allowed");

// rows: ask, answer appended, total
m.AskRows(8, 0);
var rowsAsk = sent[^1]["ask"]!.GetValue<int>();
Check("rows ask", sent[^1]["type"]!.GetValue<string>() == "rows" && sent[^1]["count"]!.GetValue<int>() == PluginViewModel.PageRows);
m.ApplyText($$"""{"type":"provide-rows","args":[{{rowsAsk}},[{"cells":[{"kind":"int","value":1},{"kind":"null"}]}],250]}""");
Check("rows stored with NULL and total", m.Rows[8].Count == 1 && m.Rows[8][0][1] is null && PluginViewModel.CellText(m.Rows[8][0][0]) == "1" && m.Totals[8] == 250);
m.ApplyText($$"""{"type":"provide-rows","args":[{{rowsAsk}},[{"cells":[]}],250]}""");
Check("answer to a used ask ignored", m.Rows[8].Count == 1);

// PLUG-08-WIN (Mac #1367): one row ask per table at a time; a table sent again is a new result; a refused row ask
// shows in its table, not as the view's message.
var rowsBefore = sent.Count;
m.AskRows(9, 0);
m.AskRows(9, 0);
Check("one row ask per table at a time", sent.Count == rowsBefore + 1);
var firstAsk = sent[^1]["ask"]!.GetValue<int>();
m.ApplyText("""{"type":"patch-view","view":1,"upsert":[{"id":8,"parent":null,"component":{"kind":"table","value":{"columns":[{"title":"a"}]}}}],"remove":[]}""");
Check("a table sent again drops its old rows and total", !m.Rows.ContainsKey(8) && !m.Totals.ContainsKey(8));
m.ApplyText("""{"type":"patch-view","view":1,"upsert":[{"id":9,"parent":null,"component":{"kind":"table","value":{"columns":[{"title":"a"}]}}}],"remove":[]}""");
m.ApplyText($$"""{"type":"provide-rows","args":[{{firstAsk}},[{"cells":[{"kind":"int","value":7}]}],1]}""");
Check("rows for an ask dropped by a new result are ignored", !m.Rows.ContainsKey(9));
m.AskRows(9, 0);
var refusedAsk = sent[^1]["ask"]!.GetValue<int>();
m.Message = null;
m.ApplyText($$"""{"type":"refuse","ask":{{refusedAsk}},"message":"There are no rows yet."}""");
Check("a refused row ask shows in its table, not as the view message", m.TableMessages.GetValueOrDefault(9) == "There are no rows yet." && m.Message is null);
m.AskRows(9, 0);
var againAsk = sent[^1]["ask"]!.GetValue<int>();
m.ApplyText($$"""{"type":"provide-rows","args":[{{againAsk}},[{"cells":[{"kind":"int","value":3}]}],1]}""");
Check("rows clear the table's message", !m.TableMessages.ContainsKey(9) && m.Rows[9].Count == 1);

// children
m.AskChildren(9, "schema");
var childAsk = sent[^1]["ask"]!.GetValue<int>();
Check("children ask carries parent", sent[^1]["parent"]!.GetValue<string>() == "schema");
var before = m.ChildrenVersion;
m.ApplyText($$"""{"type":"provide-children","args":[{{childAsk}},[{"key":"t1","label":"users","has-children":false}]]}""");
Check("children stored under node/parent", m.Children(9, "schema")?.Count == 1 && m.Children(9, null) is null && m.ChildrenVersion > before);
// PLUG-08-WIN: a pending branch is asked once, and a refused branch is left empty (a redraw must not re-ask it).
var sentBefore = sent.Count;
m.AskChildren(9, "tables");
m.AskChildren(9, "tables");
Check("a pending branch is asked once", sent.Count == sentBefore + 1);
var refusedBranch = sent[^1]["ask"]!.GetValue<int>();
m.ApplyText($$"""{"type":"refuse","ask":{{refusedBranch}},"message":"not connected"}""");
Check("a refused branch is empty, not re-asked", m.Children(9, "tables")?.Count == 0 && m.Message == "not connected");
m.Message = null;

// completions: answer, stale answer, timeout
var t1 = m.AskCompletions(10, "sel", 3);
var ask1 = sent[^1]["ask"]!.GetValue<int>();
Check("completions ask", sent[^1]["type"]!.GetValue<string>() == "completions" && sent[^1]["offset"]!.GetValue<long>() == 3 && sent[^1]["text"]!.GetValue<string>() == "sel");
var t2 = m.AskCompletions(10, "sele", 4);
var ask2 = sent[^1]["ask"]!.GetValue<int>();
Check("a newer ask ends the older with none", t1.IsCompleted && t1.Result.Count == 0);
m.ApplyText($$"""{"type":"provide-completions","args":[{{ask1}},[{"label":"old"}]]}""");
m.ApplyText($$"""{"type":"provide-completions","args":[{{ask2}},[{"label":"select","insert":"SELECT ","detail":"keyword"},{"label":"users"},{"insert":"no label"}]]}""");
var items = await t2;
Check("completion items parsed", items.Count == 2 && items[0].Insert == "SELECT " && items[0].Detail == "keyword" && items[1].Insert == "users");
var sw = System.Diagnostics.Stopwatch.StartNew();
var t3 = await m.AskCompletions(10, "x", 1);
Check("unanswered ask gives none after the wait", t3.Count == 0 && sw.Elapsed >= PluginViewModel.CompletionWait - TimeSpan.FromMilliseconds(50));

// ended
var t4 = m.AskCompletions(10, "y", 1);
Check("ended is the last update", m.ApplyText("""{"type":"ended","reason":"crash"}"""));
Check("ended text and pending asks released", m.Ended == "Plugin stopped: it crashed" && t4.IsCompleted && t4.Result.Count == 0);
Check("asks after ended answer none at once", m.AskCompletions(10, "z", 1).IsCompleted);
Check("unknown reason worded", PluginViewModel.EndedText("odd") == "Plugin stopped (odd)" && PluginViewModel.EndedText("tab-closed") == "Plugin stopped");

var m2 = new PluginViewModel("p", _ => { });
m2.OpenFailed("policy: forbidden");
Check("open failure shown", m2.Ended == "Plugin not opened: policy: forbidden");
Check("Changed raised", changed > 5);

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures;
