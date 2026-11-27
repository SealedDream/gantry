using System;
using System.Collections.Generic;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>A text edit's result: the new text and the selection after it (UTF-16 offsets).</summary>
public readonly record struct EditResult(string Text, int SelectionStart, int SelectionLength);

/// <summary>
/// PLUG-06c (Native Windows): the code editor's logic, without WinUI, so the console test checks it.
/// Lines are split on '\r' (RichEditBox's line break; "\r\n" and "\n" are accepted too). Each line keeps the end state
/// the core's tokenizer returned; after an edit the lines are re-coloured from the first changed line down, and the
/// walk stops at the first line past the edit whose start state and text are unchanged (PLUG-06c1's design).
/// </summary>
public sealed class SqlEditorModel
{
    /// <summary>The length of the "-- " a comment toggle inserts.</summary>
    public const int CommentPrefixLength = 3; // "-- "
    private const string LineComment = "--";
    private const string IndentUnit = "    ";

    private readonly Func<string, string, HighlightLine> _tokenize;
    private readonly List<string> _lines = [""];
    private readonly List<string> _endStates = [""];
    private readonly List<IReadOnlyList<HighlightToken>> _tokens = [Array.Empty<HighlightToken>()];

    /// <param name="language">postgresql or sql; any other name is plain text.</param>
    /// <param name="tokenize">(line, start state) → tokens and end state; the app passes the core's.</param>
    public SqlEditorModel(string language, Func<string, string, HighlightLine>? tokenize = null)
    {
        Language = language;
        _tokenize = tokenize ?? ((line, state) => HighlightClient.Line(Language, line, state));
    }

    public string Language { get; }
    public int LineCount => _lines.Count;
    public string LineText(int i) => _lines[i];
    public string EndState(int i) => _endStates[i];
    public IReadOnlyList<HighlightToken> Tokens(int i) => _tokens[i];

    /// <summary>How many lines the last <see cref="Update"/> tokenized (tests check the walk stops early).</summary>
    public int LastTokenized { get; private set; }

    /// <summary>The offset of line <paramref name="i"/> in the text (lines joined by one break character).</summary>
    public int LineStart(int i)
    {
        var at = 0;
        for (var k = 0; k < i; k++) at += _lines[k].Length + 1;
        return at;
    }

    public static string[] SplitLines(string text) =>
        text.Replace("\r\n", "\r", StringComparison.Ordinal).Replace('\n', '\r').Split('\r');

    /// <summary>Takes the editor's whole text and returns the lines whose colours changed (indexes into the new
    /// lines). Unchanged lines at the top and bottom are found by comparison, so the caller needs no edit record.</summary>
    public IReadOnlyList<int> Update(string text)
    {
        var next = SplitLines(text);
        var top = 0;
        while (top < next.Length && top < _lines.Count && next[top] == _lines[top]) top++;
        var tail = 0;
        while (tail < next.Length - top && tail < _lines.Count - top && next[^(tail + 1)] == _lines[^(tail + 1)]) tail++;
        // The changed block is next[top .. next.Length - tail) in place of _lines[top .. _lines.Count - tail).
        var removed = _lines.Count - tail - top;
        var added = next.Length - tail - top;
        // The state the first unchanged line below the block started from: when the block's last line ends in it
        // again, nothing below changes.
        var carry = removed > 0 ? _endStates[top + removed - 1] : top > 0 ? _endStates[top - 1] : "";
        _lines.RemoveRange(top, removed);
        _endStates.RemoveRange(top, removed);
        _tokens.RemoveRange(top, removed);
        for (var k = 0; k < added; k++)
        {
            _lines.Insert(top + k, next[top + k]);
            // Inside the block, a value the core never returns forces the walk through every new line.
            _endStates.Insert(top + k, k == added - 1 ? carry : "\u0001");
            _tokens.Insert(top + k, Array.Empty<HighlightToken>());
        }
        var changed = new List<int>();
        LastTokenized = 0;
        for (var i = top; i < _lines.Count; i++)
        {
            var start = i == 0 ? "" : _endStates[i - 1];
            var old = _endStates[i];
            var spans = _tokenize(_lines[i], start);
            LastTokenized++;
            _tokens[i] = spans.Tokens;
            _endStates[i] = spans.EndState;
            changed.Add(i);
            // Changed lines carry a marker as old state, so this stops only past the edit, at the first line whose
            // end state came out as before: every line below it starts from the same state and keeps its colours.
            if (spans.EndState == old) break;
        }
        return changed;
    }

    /// <summary>The first and last line touched by a selection.</summary>
    private static (int First, int Last, int[] Starts) LineSpan(string[] lines, int selStart, int selLength)
    {
        var starts = new int[lines.Length];
        for (int k = 1; k < lines.Length; k++) starts[k] = starts[k - 1] + lines[k - 1].Length + 1;
        int LineAt(int offset)
        {
            var l = 0;
            while (l + 1 < lines.Length && starts[l + 1] <= offset) l++;
            return l;
        }
        var first = LineAt(selStart);
        var endOffset = selStart + selLength;
        var last = LineAt(endOffset);
        // A selection that ends at the very start of a line does not include that line.
        if (selLength > 0 && last > first && starts[last] == endOffset) last--;
        return (first, last, starts);
    }

    /// <summary>Ctrl+/: comments the selected lines with "-- ", or uncomments them when every non-blank one already
    /// starts with "--" (after its indentation). The break character is '\r'.</summary>
    public static EditResult ToggleLineComment(string text, int selStart, int selLength)
    {
        var lines = SplitLines(text);
        var (first, last, starts) = LineSpan(lines, selStart, selLength);
        var uncomment = true;
        for (var l = first; l <= last; l++)
        {
            var t = lines[l].TrimStart();
            if (t.Length > 0 && !t.StartsWith(LineComment, StringComparison.Ordinal)) { uncomment = false; break; }
        }
        var newStart = selStart;
        var newEnd = selStart + selLength;
        for (var l = first; l <= last; l++)
        {
            var line = lines[l];
            var indent = line.Length - line.TrimStart().Length;
            var lineStart = starts[l];
            int delta;
            int at = lineStart + indent;
            if (uncomment)
            {
                if (line.TrimStart().Length == 0) continue;
                var cut = line.Length > indent + 2 && line[indent + 2] == ' ' ? 3 : 2;
                lines[l] = line.Remove(indent, cut);
                delta = -cut;
            }
            else
            {
                if (line.Trim().Length == 0 && first != last) continue;
                lines[l] = line.Insert(indent, LineComment + " ");
                delta = CommentPrefixLength;
            }
            newStart = Shift(newStart, at, delta);
            newEnd = Shift(newEnd, at, delta);
            for (var k = l + 1; k < starts.Length; k++) starts[k] += delta;
        }
        return new(string.Join('\r', lines), newStart, Math.Max(0, newEnd - newStart));
    }

    private static int Shift(int offset, int at, int delta)
    {
        if (offset <= at) return offset;
        return delta < 0 ? Math.Max(at, offset + delta) : offset + delta;
    }

    /// <summary>Tab with a multi-line selection (or Shift+Tab): indents or outdents every selected line by four spaces.
    /// Tab with no line-spanning selection inserts four spaces at the cursor.</summary>
    public static EditResult Indent(string text, int selStart, int selLength, bool outdent)
    {
        var lines = SplitLines(text);
        var (first, last, starts) = LineSpan(lines, selStart, selLength);
        if (!outdent && first == last)
        {
            var t = text.Remove(selStart, selLength).Insert(selStart, IndentUnit);
            return new(t.Replace("\r\n", "\r", StringComparison.Ordinal).Replace('\n', '\r'), selStart + IndentUnit.Length, 0);
        }
        var newStart = selStart;
        var newEnd = selStart + selLength;
        for (var l = first; l <= last; l++)
        {
            var line = lines[l];
            int delta;
            if (outdent)
            {
                var n = 0;
                while (n < IndentUnit.Length && n < line.Length && line[n] == ' ') n++;
                if (n == 0 && line.StartsWith('\t')) n = 1;
                if (n == 0) continue;
                lines[l] = line[n..];
                delta = -n;
            }
            else
            {
                if (line.Length == 0) continue;
                lines[l] = IndentUnit + line;
                delta = IndentUnit.Length;
            }
            newStart = Shift(newStart, starts[l], delta);
            newEnd = Shift(newEnd, starts[l], delta);
            for (var k = l + 1; k < starts.Length; k++) starts[k] += delta;
        }
        return new(string.Join('\r', lines), newStart, Math.Max(0, newEnd - newStart));
    }

    /// <summary>A chosen completion replaces the range the core named; the cursor goes after the inserted text.
    /// A plugin's insert may hold '\n'; it becomes the editor's break.</summary>
    public static EditResult ApplyCompletion(string text, CompletionContext ctx, CompletionItemDto item)
    {
        var start = Math.Clamp(ctx.ReplaceStart, 0, text.Length);
        var len = Math.Clamp(ctx.ReplaceLength, 0, text.Length - start);
        var insert = (item.Insert.Length > 0 ? item.Insert : item.Label).Replace("\r\n", "\r", StringComparison.Ordinal).Replace('\n', '\r');
        return new(text.Remove(start, len).Insert(start, insert), start + insert.Length, 0);
    }
}

/// <summary>Token colours, light and dark (ARGB). Restrained: keywords and strings carry the most colour, comments are
/// quiet, plain text keeps the theme's own foreground (null).</summary>
public static class SqlEditorPalette
{
    public static uint? Colour(string kind, bool dark) => kind switch
    {
        "keyword" => dark ? 0xFF569CD6u : 0xFF0033B3u,
        "type" => dark ? 0xFF4EC9B0u : 0xFF267F99u,
        "function" => dark ? 0xFFDCDCAAu : 0xFF795E26u,
        "string" or "quoted-identifier" => dark ? 0xFFCE9178u : 0xFFA31515u,
        "number" => dark ? 0xFFB5CEA8u : 0xFF098658u,
        "comment" => dark ? 0xFF6A9955u : 0xFF6A737Du,
        "parameter" => dark ? 0xFF9CDCFEu : 0xFF001080u,
        "operator" or "punctuation" => dark ? 0xFFD4D4D4u : 0xFF383A42u,
        "error" => dark ? 0xFFF14C4Cu : 0xFFCD3131u,
        _ => null,
    };

    /// <summary>Comments are set in italic, errors underlined; nothing else changes weight.</summary>
    public static bool Italic(string kind) => kind == "comment";
    public static bool Underline(string kind) => kind == "error";
}

/// <summary>The editor's own undo and redo. RichEditBox's built-in undo would also record the colouring, so it is
/// turned off and edits are kept here as (text, selection) snapshots. Typing within one word joins one step. Bounded by
/// count and by total characters, oldest dropped first.</summary>
public sealed class EditHistory
{
    public const int MaxSteps = 200;
    public const long MaxChars = 8L * 1024 * 1024;

    private readonly LinkedList<EditResult> _undo = new();
    private readonly Stack<EditResult> _redo = new();
    private long _chars;
    private EditResult _current;

    public EditHistory(EditResult initial) => _current = initial;

    public EditResult Current => _current;
    public bool CanUndo => _undo.Count > 0;
    public bool CanRedo => _redo.Count > 0;

    /// <summary>Records the state after an edit. <paramref name="join"/>: the edit continues the last one (typing a
    /// word), so the state before it stays the undo point.</summary>
    public void Record(EditResult after, bool join)
    {
        if (after.Text == _current.Text) { _current = after; return; }
        if (!join || _undo.Count == 0)
        {
            _undo.AddLast(_current);
            _chars += _current.Text.Length;
            while (_undo.Count > MaxSteps || (_chars > MaxChars && _undo.Count > 1))
            {
                _chars -= _undo.First!.Value.Text.Length;
                _undo.RemoveFirst();
            }
        }
        _redo.Clear();
        _current = after;
    }

    public EditResult? Undo()
    {
        if (_undo.Count == 0) return null;
        _redo.Push(_current);
        _current = _undo.Last!.Value;
        _chars -= _current.Text.Length;
        _undo.RemoveLast();
        return _current;
    }

    public EditResult? Redo()
    {
        if (_redo.Count == 0) return null;
        _undo.AddLast(_current);
        _chars += _current.Text.Length;
        _current = _redo.Pop();
        return _current;
    }
}
