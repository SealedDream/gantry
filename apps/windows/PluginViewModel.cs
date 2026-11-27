using System.Text.Json.Nodes;
using Bastion.Shell.Interop; // CompletionItemDto

namespace Bastion.Shell;

/// <summary>
/// PLUG-VIEW-WIN: the state of one open plugin view, the Windows port of Native Mac's PluginViewModel (#1351). It
/// applies the core's updates (set-view, patch-view, dialog, close-dialog, confirm, refuse, provide-rows,
/// provide-children, provide-completions, ended) and builds the events the user's actions send. The core checks every
/// node list before it arrives; this only keeps what it gets. No WinUI here: the console test drives it with JSON.
/// Every method runs on the UI thread; <see cref="Changed"/> tells the renderer to redraw.
/// </summary>
public sealed class PluginViewModel
{
    public sealed record Node(int Id, int? Parent, string Kind, JsonNode? Value);
    public sealed record Dialog(int Id, string Title, IReadOnlyList<Node> Nodes);
    public sealed record Confirm(int Id, string Kind, string Text, string? Entry)
    {
        /// <summary>The card's title: never the raw WIT kind (plugin.wit <c>confirm-kind</c>). Mac: PluginViewModel.Confirm.title.</summary>
        public string Title => Kind switch
        {
            "drop" => "Confirm Drop",
            "truncate" => "Confirm Truncate",
            "delete-rows" => "Confirm Delete Rows",
            "end-session" => "Confirm End Session",
            "run-statements" => "Confirm Run Statements",
            _ => "Confirm",
        };
    }
    /// <summary>PLUG-OPEN-WIN: a plugin asks to open SSH, RDP or VNC (the core checked it). The sheet's words come from
    /// here, not from the plugin; <see cref="Label"/> is shown as the plugin's text.</summary>
    public sealed record OpenRequest(int Id, string Plugin, string EntryName, string Protocol, string Host, int Port, string Label,
        bool Reported, string Route, string EntryRoute);
    /// <summary>Plugin API 1.6: one connection a plugin proposes for the library (the core checked it).</summary>
    public sealed record LibraryProposal(string Label, string? Host, bool Reported, string Protocol, string? OsHint);
    /// <summary>Plugin API 1.6 Save as Connection: the window shows the core-worded modal and answers with <see cref="AnswerLibrary"/>.</summary>
    public sealed record LibraryRequest(int Id, string Plugin, string EntryName, IReadOnlyList<LibraryProposal> Items);
    /// <summary>The core's go-ahead after a yes: the app connects through its normal path.</summary>
    public sealed record OpenGo(string Protocol, string Host, int Port, string Label, bool ViaEntryRoute, bool CheckResolved,
        bool LoopbackOk, bool SaveAsEntry);

    public const int FirstView = 1;
    public const int PageRows = 100;
    /// <summary>How long the editor waits for a plugin's completion answer before showing none.</summary>
    public static readonly TimeSpan CompletionWait = TimeSpan.FromSeconds(2);

    private readonly Action<string> _send;
    private readonly Dictionary<int, (int Node, string? Parent)> _askTarget = [];
    private readonly Dictionary<int, TaskCompletionSource<IReadOnlyList<CompletionItemDto>>> _completionAsks = [];
    private int _nextAsk = 1;

    /// <param name="send">Hands one event (JSON) to the session; the caller moves it off the UI thread.</param>
    public PluginViewModel(string pluginId, Action<string> send)
    {
        PluginId = pluginId;
        _send = send;
    }

    public string PluginId { get; }
    public IReadOnlyList<Node> Nodes { get; private set; } = [];

    /// <summary>When the plugin last set a loaded view: no busy mark (a progress node without a value) and no error banner ("Updated hh:mm" beside Refresh).</summary>
    public DateTime? UpdatedAt { get; private set; }
    public IReadOnlyList<Dialog> Dialogs { get; private set; } = [];
    public Confirm? PendingConfirm { get; private set; }
    public OpenRequest? PendingOpen { get; private set; }
    /// <summary>Raised on <c>open-go</c>; the window connects (MainWindow.PluginOpen.cs).</summary>
    public event Action<OpenGo>? OpenApproved;
    /// <summary>Plugin API 1.5: the core's <c>exec-go</c> (request, command, timeout ms). Answer with <see cref="AnswerExec"/>.</summary>
    public event Action<int, string, ulong>? ExecRequested;
    /// <summary>Plugin API 1.5: the core's <c>exec-cancel</c> (request).</summary>
    public event Action<int>? ExecCancelled;
    /// <summary>Plugin API 1.5: the core's <c>exec-terminal</c> (request, command, label). Answer with <see cref="AnswerExecTerminal"/>.</summary>
    public event Action<int, string, string>? ExecTerminalRequested;
    /// <summary>Raised on <c>clipboard</c>: the core sends it only right after the user pressed Copy (view_files.rs).</summary>
    public event Action<string>? ClipboardText;
    /// <summary>Raised on <c>save-request</c> (request, suggested file name): the window shows its save picker and answers
    /// with <see cref="AnswerSave"/>; the core writes the file.</summary>
    public event Action<int, string>? SaveRequested;
    /// <summary>Raised on <c>library-propose</c>; the window shows Save as Connection (MainWindow.PluginSave.cs).</summary>
    public event Action<LibraryRequest>? LibraryRequested;
    private readonly Dictionary<int, bool> _saveChoice = [];
    private readonly Dictionary<int, IReadOnlyList<string>> _rowKeys = [];
    /// <summary>Each table row's key, in the order of <see cref="Rows"/>.</summary>
    public IReadOnlyDictionary<int, IReadOnlyList<string>> RowKeys => _rowKeys;
    public string? Ended { get; private set; }
    public string? Message { get; set; }
    public IReadOnlyDictionary<int, IReadOnlyList<IReadOnlyList<JsonNode?>>> Rows => _rows;
    public IReadOnlyDictionary<int, int> Totals => _totals;
    private readonly Dictionary<int, IReadOnlyList<IReadOnlyList<JsonNode?>>> _rows = [];
    private readonly Dictionary<int, int> _totals = [];
    // Row asks still waiting, by ask id → table node; one per table at a time (no doubled pages, as Mac #1367).
    private readonly Dictionary<int, int> _rowAsks = [];
    private readonly Dictionary<int, string> _tableMessages = [];
    /// <summary>A refusal of a table's row ask, shown in that table until rows arrive.</summary>
    public IReadOnlyDictionary<int, string> TableMessages => _tableMessages;
    private readonly Dictionary<string, IReadOnlyList<JsonObject>> _children = [];

    /// <summary>Raised after any update changed what is shown.</summary>
    public event Action? Changed;

    /// <summary>The view could not open (the core's reason).</summary>
    public void OpenFailed(string reason)
    {
        Ended = "Plugin not opened: " + reason;
        Changed?.Invoke();
    }

    /// <summary>Applies one update; true when it was the last (<c>ended</c>).</summary>
    public bool ApplyText(string text)
    {
        JsonObject? u;
        try { u = JsonNode.Parse(text) as JsonObject; }
        catch (System.Text.Json.JsonException) { return false; }
        if (u is null) return false;
        Apply(u);
        return Str(u, "type") == "ended";
    }

    public void Apply(JsonObject u)
    {
        switch (Str(u, "type"))
        {
            case "set-view":
                if (Int(u, "view") != FirstView) return;
                Nodes = Parse(u["nodes"]);
                ResetTables(Nodes);
                if (!Nodes.Any(n => (n.Kind == "progress" && n.Value is not JsonValue) || (n.Kind == "banner" && n.Value is JsonObject b && Str(b, "level") == "error")))
                    UpdatedAt = DateTime.Now;
                break;
            case "patch-view":
                if (Int(u, "view") != FirstView) return;
                var upsert = Parse(u["upsert"]);
                Nodes = Patched(Nodes, upsert, (u["remove"] as JsonArray ?? []).Select(n => IntOf(n)).OfType<int>().ToHashSet());
                ResetTables(upsert);
                ResetTrees(upsert);
                break;
            case "dialog":
                if (Int(u, "dialog") is not { } did) return;
                Dialogs = [.. Dialogs, new Dialog(did, Str(u, "title") ?? "", Parse(u["nodes"]))];
                break;
            case "close-dialog":
                var cid = Int(u, "dialog");
                Dialogs = Dialogs.Where(d => d.Id != cid).ToList();
                break;
            case "confirm":
                if (Int(u, "request") is not { } req) return;
                var e = u["entry"] as JsonObject;
                var entry = e is not null && Str(e, "name") is { } n ? string.Join(" · ", new[] { n, Str(e, "environment") }.OfType<string>().Where(x => x.Length > 0 && x != "unclassified")) : null;
                PendingConfirm = new Confirm(req, Str(u, "kind") ?? "other", Str(u, "text") ?? "", entry);
                break;
            case "open-request":
                if (Int(u, "request") is not { } oreq || Str(u, "host") is not { } ohost || Int(u, "port") is not { } oport) return;
                PendingOpen = new OpenRequest(oreq, Str(u, "plugin") ?? PluginId, (u["entry"] as JsonObject) is { } oe ? Str(oe, "name") ?? "" : "",
                    Str(u, "protocol") ?? "", ohost, oport, Str(u, "label") ?? "", Bool(u, "reported") ?? false, Str(u, "route") ?? "entry",
                    Str(u, "entry_route") ?? "direct");
                break;
            case "library-propose":
                if (Int(u, "request") is not { } lreq || u["items"] is not JsonArray litems) return;
                var items = litems.OfType<JsonObject>().Select(i => new LibraryProposal(Str(i, "label") ?? "", Str(i, "host"), Bool(i, "reported") ?? false,
                    Str(i, "protocol") ?? "ssh", Str(i, "os_hint"))).ToList();
                LibraryRequested?.Invoke(new LibraryRequest(lreq, Str(u, "plugin") ?? PluginId, (u["entry"] as JsonObject) is { } le ? Str(le, "name") ?? "" : "", items));
                return;
            case "open-go":
                if (Int(u, "request") is not { } greq || Str(u, "host") is not { } ghost || Int(u, "port") is not { } gport) return;
                _saveChoice.Remove(greq, out var save);
                OpenApproved?.Invoke(new OpenGo(Str(u, "protocol") ?? "", ghost, gport, Str(u, "label") ?? ghost, Str(u, "route") == "entry",
                    Bool(u, "check_resolved") ?? true, Bool(u, "loopback_ok") ?? false, save));
                return;
            case "exec-go":
                if (Int(u, "request") is not { } xreq || Str(u, "command") is not { } xcmd) return;
                ExecRequested?.Invoke(xreq, xcmd, (ulong)(Int(u, "timeout_ms") ?? 30_000));
                return;
            case "exec-cancel":
                if (Int(u, "request") is { } creq) ExecCancelled?.Invoke(creq);
                return;
            case "exec-terminal":
                if (Int(u, "request") is not { } treq || Str(u, "command") is not { } tcmd) return;
                ExecTerminalRequested?.Invoke(treq, tcmd, Str(u, "label") ?? "");
                return;
            case "clipboard":
                if (Str(u, "text") is { } clip) ClipboardText?.Invoke(clip);
                return;
            case "save-request":
                if (Int(u, "request") is { } sreq) SaveRequested?.Invoke(sreq, Str(u, "name") ?? "export");
                return;
            case "open-refused":
                if (Int(u, "request") is { } rreq) _saveChoice.Remove(rreq);
                Message = Str(u, "reason");
                AppLog.Info($"Plugin view: open refused: {Message}");
                break;
            case "refuse":
                // A refused row ask belongs to its table (shown there, cleared when rows arrive), not to the whole view.
                if (Int(u, "ask") is { } refused && _rowAsks.Remove(refused, out var table))
                {
                    _askTarget.Remove(refused);
                    _tableMessages[table] = Str(u, "message") ?? "";
                }
                else
                {
                    // A refused children ask leaves that branch empty: a redraw must not ask again, or each refusal
                    // redraws and re-asks without end (PLUG-08-WIN: the entry view hung and the core stopped the helper).
                    if (Int(u, "ask") is { } ask && !_completionAsks.ContainsKey(ask) && _askTarget.Remove(ask, out var t))
                    {
                        _childAsks.Remove(ChildKey(t.Node, t.Parent));
                        _children[ChildKey(t.Node, t.Parent)] = [];
                        ChildrenVersion++;
                    }
                    Message = Str(u, "message");
                }
                break;
            case "provide-rows":
                ProvideRows(u["args"] as JsonArray ?? []);
                break;
            case "provide-children":
                ProvideChildren(u["args"] as JsonArray ?? []);
                break;
            case "provide-completions":
                ProvideCompletions(u["args"] as JsonArray ?? []);
                return; // the waiting editor shows them; nothing else to redraw
            case "ended":
                Ended = EndedText(Str(u, "reason") ?? "");
                foreach (var t in _completionAsks.Values) t.TrySetResult([]);
                _completionAsks.Clear();
                break;
            default:
                return;
        }
        Changed?.Invoke();
    }

    /// <summary>A table node sent again is a new result: its rows, total, message and waiting asks go, so the next draw
    /// asks from the first row (a second query never shows or appends the previous rows; Mac #1367).</summary>
    /// <summary>A tree sent again is the plugin's "reload" (PostgreSQL: Refresh, a new plan): its cached children and
    /// refusals are dropped, so the tree asks again.</summary>
    private void ResetTrees(IEnumerable<Node> sent)
    {
        var trees = sent.Where(n => n.Kind == "tree").Select(n => $"{n.Id}/").ToList();
        if (trees.Count == 0) return;
        foreach (var k in _children.Keys.Where(k => trees.Any(t => k.StartsWith(t, StringComparison.Ordinal))).ToList()) _children.Remove(k);
        ChildrenVersion++;
    }

    private void ResetTables(IEnumerable<Node> sent)
    {
        foreach (var n in sent.Where(n => n.Kind == "table"))
        {
            _rows.Remove(n.Id);
            _rowKeys.Remove(n.Id);
            _totals.Remove(n.Id);
            _tableMessages.Remove(n.Id);
            foreach (var a in _rowAsks.Where(kv => kv.Value == n.Id).Select(kv => kv.Key).ToList())
            {
                _rowAsks.Remove(a);
                _askTarget.Remove(a);
            }
        }
    }

    public static IReadOnlyList<Node> Parse(JsonNode? any) =>
        (any as JsonArray ?? []).OfType<JsonObject>().Select(n =>
            Int(n, "id") is { } id && n["component"] is JsonObject c && Str(c, "kind") is { } kind
                ? new Node(id, Int(n, "parent"), kind, c["value"]?.DeepClone())
                : null).OfType<Node>().ToList();

    /// <summary>A new list: <paramref name="remove"/> dropped, <paramref name="upsert"/> replacing nodes by id or added at the end.</summary>
    public static IReadOnlyList<Node> Patched(IReadOnlyList<Node> list, IReadOnlyList<Node> upsert, IReadOnlySet<int> remove)
    {
        var byId = new Dictionary<int, Node>();
        foreach (var n in upsert) byId[n.Id] = n;
        var kept = list.Where(n => !remove.Contains(n.Id)).Select(n => byId.GetValueOrDefault(n.Id, n)).ToList();
        var known = kept.Select(n => n.Id).ToHashSet();
        return [.. kept, .. upsert.Where(n => !known.Contains(n.Id))];
    }

    public static IEnumerable<Node> Kids(int? id, IReadOnlyList<Node> list) => list.Where(n => n.Parent == id);

    // ---- events ----

    private void Send(JsonObject e) => _send(e.ToJsonString());

    /// <summary>The result of an <c>exec-go</c>: the core's <c>{exit, stdout, stderr, error}</c> object.</summary>
    public void AnswerExec(int request, JsonObject result)
    {
        result["type"] = "exec";
        result["request"] = request;
        Send(result);
    }

    /// <summary>Whether the <c>exec-terminal</c> tab opened.</summary>
    public void AnswerExecTerminal(int request, bool opened) =>
        Send(new JsonObject { ["type"] = "exec", ["request"] = request, ["opened"] = opened });

    public void Input(int node, JsonObject input) =>
        Send(new JsonObject { ["type"] = "ui", ["view"] = FirstView, ["node"] = node, ["input"] = input });

    public void Pressed(int node) => Input(node, new JsonObject { ["kind"] = "pressed" });
    public void TextInput(int node, string value) => Input(node, new JsonObject { ["kind"] = "text", ["value"] = value });
    public void NumberInput(int node, double value) => Input(node, new JsonObject { ["kind"] = "number", ["value"] = value });
    public void ChoiceInput(int node, int value) => Input(node, new JsonObject { ["kind"] = "choice", ["value"] = value });
    public void ToggleInput(int node, bool value) => Input(node, new JsonObject { ["kind"] = "toggled", ["value"] = value });
    public void RunInput(int node, string text) => Input(node, new JsonObject { ["kind"] = "run", ["value"] = text });
    /// <summary>A tree item's menu entry (power, snapshot, connect); the plugin confirms risky ones through the core.</summary>
    public void MenuInput(int node, string key, string item) => Input(node, new JsonObject { ["kind"] = "menu", ["key"] = key, ["item"] = item });

    /// <summary>The user clicked a tree item: its key goes to the plugin as the tree's selection.</summary>
    public void SelectTreeItem(int node, string key)
    {
        if (key.Length == 0) return;
        Input(node, new JsonObject { ["kind"] = "selected", ["keys"] = new JsonArray(key) });
    }

    /// <summary>Esc or the dialog's Close: drop the top dialog here and tell the plugin (<c>cancel</c>).</summary>
    public void DismissTopDialog()
    {
        if (Dialogs.Count == 0) return;
        Dialogs = Dialogs.Take(Dialogs.Count - 1).ToList();
        Send(new JsonObject { ["type"] = "cancel", ["view"] = FirstView });
        Changed?.Invoke();
    }

    /// <summary>Redraws after a change made from outside an update (a message set by the window).</summary>
    public void Refresh() => Changed?.Invoke();

    /// <summary>The user's answer to the open sheet. <paramref name="route"/> is <c>entry</c> or <c>direct</c>.</summary>
    public void AnswerOpen(OpenRequest r, bool accept, string route, bool saveAsEntry)
    {
        PendingOpen = null;
        if (accept) _saveChoice[r.Id] = saveAsEntry;
        Send(new JsonObject { ["type"] = "open", ["request"] = r.Id, ["accept"] = accept, ["route"] = route, ["credential_chosen"] = false, ["save_as_entry"] = accept && saveAsEntry });
        Changed?.Invoke();
    }

    /// <summary>The user's answer to Save as Connection: how many were saved, or null when cancelled.</summary>
    public void AnswerLibrary(LibraryRequest r, int? saved, bool credentialLinked) =>
        Send(new JsonObject { ["type"] = "library", ["request"] = r.Id, ["saved"] = saved, ["credential_linked"] = saved is not null && credentialLinked });

    /// <summary>The user selected table rows (by index): their keys go to the plugin.</summary>
    public void SelectRows(int node, IEnumerable<int> indexes)
    {
        var keys = _rowKeys.GetValueOrDefault(node) ?? [];
        var picked = new JsonArray();
        foreach (var i in indexes.Order()) if (i >= 0 && i < keys.Count && keys[i].Length > 0) picked.Add((JsonNode)JsonValue.Create(keys[i]));
        Input(node, new JsonObject { ["kind"] = "selected", ["keys"] = picked });
    }

    /// <summary>The user's answer to a save picker: the chosen path, or null when cancelled.</summary>
    public void AnswerSave(int request, string? path) =>
        Send(new JsonObject { ["type"] = "save", ["request"] = request, ["path"] = path });

    public void Answer(Confirm c, bool confirmed)
    {
        PendingConfirm = null;
        Send(new JsonObject { ["type"] = "confirm", ["request"] = c.Id, ["confirmed"] = confirmed });
        Changed?.Invoke();
    }

    public void AskRows(int node, int offset)
    {
        if (_rowAsks.ContainsValue(node)) return; // one ask per table at a time
        var ask = TakeAsk(node, null);
        _rowAsks[ask] = node;
        Send(new JsonObject { ["type"] = "rows", ["ask"] = ask, ["view"] = FirstView, ["node"] = node, ["offset"] = offset, ["count"] = PageRows });
    }

    public void AskChildren(int node, string? parent)
    {
        // One ask per branch while it is pending: every redraw draws the tree again, and asking each time floods the plugin.
        if (!_childAsks.Add(ChildKey(node, parent))) return;
        var ask = TakeAsk(node, parent);
        var e = new JsonObject { ["type"] = "children", ["ask"] = ask, ["view"] = FirstView, ["node"] = node };
        if (parent is not null) e["parent"] = parent;
        Send(e);
    }

    /// <summary>Asks the plugin for completions at <paramref name="offset"/> (characters) in <paramref name="text"/>.
    /// Completes with the plugin's items (the core ranks them in the editor), or none after <see cref="CompletionWait"/>,
    /// when a newer ask for the same node replaces it, or when the view ends.</summary>
    public Task<IReadOnlyList<CompletionItemDto>> AskCompletions(int node, string text, long offset)
    {
        if (Ended is not null) return Task.FromResult<IReadOnlyList<CompletionItemDto>>([]);
        foreach (var (a, t) in _askTarget.Where(kv => kv.Value.Node == node && _completionAsks.ContainsKey(kv.Key)).ToList())
        {
            _completionAsks[a].TrySetResult([]);
            _completionAsks.Remove(a);
            _askTarget.Remove(a);
        }
        var ask = TakeAsk(node, null);
        var tcs = new TaskCompletionSource<IReadOnlyList<CompletionItemDto>>();
        _completionAsks[ask] = tcs;
        Send(new JsonObject { ["type"] = "completions", ["ask"] = ask, ["view"] = FirstView, ["node"] = node, ["text"] = text, ["offset"] = offset });
        return WithTimeout(ask, tcs.Task);
    }

    private async Task<IReadOnlyList<CompletionItemDto>> WithTimeout(int ask, Task<IReadOnlyList<CompletionItemDto>> t)
    {
        if (await Task.WhenAny(t, Task.Delay(CompletionWait)) == t) return await t;
        _completionAsks.Remove(ask);
        _askTarget.Remove(ask);
        return [];
    }

    private int TakeAsk(int node, string? parent)
    {
        var a = _nextAsk++;
        _askTarget[a] = (node, parent);
        return a;
    }

    private void ProvideRows(JsonArray args)
    {
        if (args.Count == 0 || IntOf(args[0]) is not { } ask || !_askTarget.Remove(ask, out var t)) return;
        if (!_rowAsks.Remove(ask)) return; // an answer to an ask dropped by a newer result
        _tableMessages.Remove(t.Node);
        var list = (args.Count > 1 ? args[1] as JsonArray : null) ?? [];
        var cells = list.OfType<JsonObject>().Select(r => (IReadOnlyList<JsonNode?>)(r["cells"] as JsonArray ?? []).Select(c => Cell(c as JsonObject)).ToList()).ToList();
        _rows[t.Node] = [.. _rows.GetValueOrDefault(t.Node) ?? [], .. cells];
        _rowKeys[t.Node] = [.. _rowKeys.GetValueOrDefault(t.Node) ?? [], .. list.OfType<JsonObject>().Select(r => Str(r, "key") ?? "")];
        if (args.Count > 2 && IntOf(args[2]) is { } total) _totals[t.Node] = total;
    }

    private void ProvideChildren(JsonArray args)
    {
        if (args.Count == 0 || IntOf(args[0]) is not { } ask || !_askTarget.Remove(ask, out var t)) return;
        ChildrenVersion++;
        _childAsks.Remove(ChildKey(t.Node, t.Parent));
        _children[ChildKey(t.Node, t.Parent)] = ((args.Count > 1 ? args[1] as JsonArray : null) ?? []).OfType<JsonObject>().ToList();
    }

    private void ProvideCompletions(JsonArray args)
    {
        if (args.Count == 0 || IntOf(args[0]) is not { } ask) return;
        _askTarget.Remove(ask);
        if (!_completionAsks.Remove(ask, out var tcs)) return; // an older ask, already replaced or timed out
        tcs.TrySetResult(CompletionItems(args.Count > 1 ? args[1] : null));
    }

    public static IReadOnlyList<CompletionItemDto> CompletionItems(JsonNode? any) =>
        (any as JsonArray ?? []).OfType<JsonObject>().Select(i => Str(i, "label") is { } label
            ? new CompletionItemDto(label, Str(i, "insert") ?? label, Str(i, "detail") ?? "") : null).OfType<CompletionItemDto>().ToList();

    /// <summary>Changes when tree children arrive or a branch opens, so a kept tree redraws.</summary>
    public int ChildrenVersion { get; private set; }

    /// <summary>A branch opened or closed in the renderer: redraw the trees.</summary>
    public void TouchChildren()
    {
        ChildrenVersion++;
        Changed?.Invoke();
    }

    public IReadOnlyList<JsonObject>? Children(int node, string? parent) => _children.GetValueOrDefault(ChildKey(node, parent));

    private readonly HashSet<string> _childAsks = [];

    public static string ChildKey(int node, string? parent) => $"{node}/{parent ?? ""}";

    /// <summary>A table cell: null for SQL NULL, else its value.</summary>
    public static JsonNode? Cell(JsonObject? c) => c is null || Str(c, "kind") is null or "null" ? null : c["value"]?.DeepClone();

    /// <summary>A cell as text ("NULL" for none). Whole numbers show without ".0" (the core sends
    /// every number as f64, so a guest ID 301 arrives as 301.0). A status or meter cell (API 1.6)
    /// shows its text.</summary>
    public static string CellText(JsonNode? c) => c switch
    {
        null => "NULL",
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        JsonValue v when v.TryGetValue<double>(out var d) => NumberText(d),
        JsonObject o when Str(o, "text") is { } t => t,
        _ => c.ToJsonString(),
    };

    /// <summary>A number as the Mac shows it: integers without a fraction, others as written.</summary>
    public static string NumberText(double d) =>
        Math.Abs(d) < 1e15 && Math.Floor(d) == d
            ? ((long)d).ToString(System.Globalization.CultureInfo.InvariantCulture)
            : d.ToString("R", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>A status cell's tone (API 1.6), or null for any other cell.</summary>
    public static string? CellTone(JsonNode? c) => c is JsonObject o ? Str(o, "tone") : null;

    /// <summary>A meter cell's fraction (API 1.6), or null for any other cell.</summary>
    public static double? CellFraction(JsonNode? c) =>
        c is JsonObject o && o["fraction"] is JsonValue f && f.TryGetValue<double>(out var d) ? Math.Clamp(d, 0, 1) : null;

    /// <summary>A row whose status cell is "off" (a stopped guest) is drawn dimmed.</summary>
    public static bool IsDimmed(IReadOnlyList<JsonNode?> row) => row.Any(c => CellTone(c) == "off");

    /// <summary>Why a plugin view ended (the core's reason), in the Mac's words.</summary>
    public static string EndedText(string reason) => reason switch
    {
        "cancel" or "tab-closed" => "Plugin stopped",
        "limit" => "Plugin stopped: over its memory or time limit",
        "hang" => "Plugin stopped: not responding",
        "crash" => "Plugin stopped: it crashed",
        "document-locked" or "credentials-locked-policy" => "Plugin stopped: credentials locked",
        "revoked" => "Plugin stopped: revoked",
        "policy" => "Plugin stopped: policy changed",
        "turned-off" => "Plugin stopped: turned off",
        "removed" => "Plugin stopped: removed",
        "safe-mode" => "Plugin stopped: Safe mode",
        _ => $"Plugin stopped ({reason})",
    };

    // ---- JSON helpers ----

    public static string? Str(JsonObject o, string key) => o[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    public static int? Int(JsonObject o, string key) => IntOf(o[key]);
    public static bool? Bool(JsonObject o, string key) => o[key] is JsonValue v && v.TryGetValue<bool>(out var b) ? b : null;
    public static double? Num(JsonObject o, string key) => o[key] is JsonValue v && v.TryGetValue<double>(out var d) ? d : null;

    public static int? IntOf(JsonNode? n)
    {
        if (n is not JsonValue v) return null;
        if (v.TryGetValue<int>(out var i)) return i;
        if (v.TryGetValue<long>(out var l) && l is >= int.MinValue and <= int.MaxValue) return (int)l;
        if (v.TryGetValue<double>(out var d) && d == Math.Floor(d) && d is >= int.MinValue and <= int.MaxValue) return (int)d;
        return null;
    }
}
