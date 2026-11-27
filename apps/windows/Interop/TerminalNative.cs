using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>One installed WSL distribution. <c>Version</c> is 1, 2 or 0 (unknown); <c>State</c> is running, stopped, busy or unknown;
/// <c>Hidden</c> marks helper distributions (docker-desktop*) that pickers leave out unless asked.</summary>
public sealed record WslDistro(string Name, int Version, bool IsDefault, string State, bool Hidden);

/// <summary><c>Kind</c>: ready, wsl_missing, removed or busy; <c>Installed</c> lists the distributions there are when removed.</summary>
public sealed record WslAvailability(string Kind, string? State, List<string>? Installed);

/// <summary>Mirrors <c>BastionCell</c> in core-cabi/src/terminal.rs (16 bytes).</summary>
[StructLayout(LayoutKind.Sequential)]
public struct NativeCell
{
    public uint Fg;
    public uint Bg;
    public uint ChOffset;
    public ushort ChLen;
    public byte Flags;
    public byte Reserved;

    public const byte Bold = 1, Italic = 2, Underline = 4, Selected = 8, Matched = 16;
}

/// <summary>Mirrors <c>BastionScreen</c> (56 bytes on x64).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeScreen
{
    public ushort Cols, Rows, CursorRow, CursorCol;
    public byte CursorVisible, AppCursor, Alive, Reserved;
    public ulong Generation;
    public IntPtr Cells;
    public uint CellCount;
    public uint TextLen;
    public IntPtr Text;
    public IntPtr Title;
}

internal static class TerminalNative
{
    internal const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_local_shell(ushort cols, ushort rows, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_open_sibling(IntPtr t, ushort cols, ushort rows, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_spawn([MarshalAs(UnmanagedType.LPUTF8Str)] string program, [MarshalAs(UnmanagedType.LPUTF8Str)] string? argsJson, ushort cols, ushort rows, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_wsl([MarshalAs(UnmanagedType.LPUTF8Str)] string distro, ushort cols, ushort rows, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_wsl_distros_json(out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_wsl_distros_detail_json(out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_wsl_availability_json([MarshalAs(UnmanagedType.LPUTF8Str)] string distro, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_open_local(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, ushort cols, ushort rows, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_open_mosh(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, ushort cols, ushort rows, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_free(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern ulong bastion_terminal_generation(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern ulong bastion_terminal_wait_change(IntPtr t, ulong after, uint timeoutMs);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_is_alive(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_screen(IntPtr t, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_screen_free(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int bastion_terminal_write(IntPtr t, byte* bytes, nuint len, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_paste(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string text, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_bracketed_paste(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_set_clipboard_policy(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string policy, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_take_clipboard_json(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_resize(IntPtr t, ushort cols, ushort rows, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_scroll(IntPtr t, int lines);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_select_start(IntPtr t, ushort row, ushort col, byte clicks);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_select_extend(IntPtr t, ushort row, ushort col);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_clear_selection(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_search(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string pattern, int forward, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_find_json(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string query, int forward, int matchCase, int regex, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_clear_search(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_take_bell(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_foreground_json(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_carry_over(IntPtr t, IntPtr old);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_take_events_json(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_jump_prompt(IntPtr t, int forward);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_tags_is_production([MarshalAs(UnmanagedType.LPUTF8Str)] string tagsJson);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_mouse_reporting(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_mouse(IntPtr t, uint button, uint action, ushort row, ushort col, uint mods, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_clear_scrollback(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_set_scrollback(IntPtr t, uint lines, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_select_all(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_selection_text(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_close(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_set_theme(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_set_theme_in(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bastion_terminal_background(IntPtr t);
}

/// <summary>A copied snapshot of the terminal grid (no native memory referenced after construction).</summary>
public sealed class TerminalScreen
{
    public required int Cols { get; init; }
    public required int Rows { get; init; }
    public required NativeCell[] Cells { get; init; }
    public required string[] CellText { get; init; }
    public int CursorRow { get; init; }
    public int CursorCol { get; init; }
    public bool CursorVisible { get; init; }
    public bool AppCursor { get; init; }
    public bool Alive { get; init; }
    public ulong Generation { get; init; }
    public string? Title { get; init; }
}

/// <summary>
/// One terminal session in core-cabi. Use from the UI thread; <see cref="Dispose"/> ends the program and frees
/// the native handle exactly once.
/// </summary>
public sealed partial class TerminalSession : IDisposable
{
    private IntPtr _handle;

    static TerminalSession()
    {
        // The P/Invoke structs must match core-cabi's #[repr(C)] layout; fail loudly rather than read garbage.
        if (Marshal.SizeOf<NativeCell>() != 16 || (IntPtr.Size == 8 && Marshal.SizeOf<NativeScreen>() != 56))
            throw new BastionException($"terminal struct layout mismatch ({Marshal.SizeOf<NativeCell>()}/{Marshal.SizeOf<NativeScreen>()})");
    }

    private TerminalSession(IntPtr handle)
    {
        _handle = handle;
        LeakProbe.SessionOpened();
        LeakProbe.Track(this, "TerminalSession");
    }

    /// <summary>The user's default shell (%COMSPEC% on Windows).</summary>
    public static TerminalSession LocalShell(int cols, int rows) =>
        Wrap(TerminalNative.bastion_terminal_local_shell((ushort)cols, (ushort)rows, out var err), err);

    /// <summary>A specific program started directly (no shell), e.g. powershell.exe or wsl.exe.</summary>
    public static TerminalSession Spawn(string program, IReadOnlyList<string> args, int cols, int rows) =>
        Wrap(TerminalNative.bastion_terminal_spawn(program, AotJson.Write<IReadOnlyList<string>>(args, AotJson.Options), (ushort)cols, (ushort)rows, out var err), err);

    /// <summary>A WSL distribution (<c>wsl.exe -d name</c>); the core refuses names WSL would not accept.</summary>
    public static TerminalSession Wsl(string distro, int cols, int rows) =>
        Wrap(TerminalNative.bastion_terminal_wsl(distro, (ushort)cols, (ushort)rows, out var err), err);

    /// <summary>A saved local terminal connection: the shell, arguments and start folder from its properties.</summary>
    public static TerminalSession OpenLocal(LibraryClient library, string connectionId, int cols, int rows) =>
        Wrap(TerminalNative.bastion_terminal_open_local(library.Handle, connectionId, (ushort)cols, (ushort)rows, out var err), err);

    /// <summary>
    /// A saved SSH connection whose transport is Mosh (C ABI 67): the local mosh client in a PTY, attaching the
    /// connection's tmux session when that is on. Throws with the core's reason when mosh.exe is not on PATH or the
    /// connection needs a gateway or jump host (only Bastion's own SSH client can do those).
    /// </summary>
    public static TerminalSession OpenMosh(LibraryClient library, string connectionId, int cols, int rows) =>
        Wrap(TerminalNative.bastion_terminal_open_mosh(library.Handle, connectionId, (ushort)cols, (ushort)rows, out var err), err);

    /// <summary>
    /// A new shell beside this one, for a split pane: a second channel on the same SSH connection (no new login),
    /// or a new local shell when this one is local. It is independent of this session and ends with the connection.
    /// </summary>
    public TerminalSession OpenSibling(int cols, int rows) =>
        Wrap(TerminalNative.bastion_terminal_open_sibling(H, (ushort)Math.Clamp(cols, 1, 1000), (ushort)Math.Clamp(rows, 1, 1000), out var err), err);

    /// <summary>Installed WSL distributions, default first; empty when WSL is not installed.</summary>
    public static IReadOnlyList<string> WslDistros()
    {
        var json = TerminalNative.bastion_wsl_distros_json(out var err);
        if (json == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not list WSL distributions");
        return JsonSerializer.Deserialize(Take(json) ?? "[]", AotJson.Options.Info<List<string>>()) ?? [];
    }

    /// <summary>Installed WSL distributions with version and state, default first; empty when WSL is not installed.</summary>
    public static IReadOnlyList<WslDistro> WslDistroDetails()
    {
        var json = TerminalNative.bastion_wsl_distros_detail_json(out var err);
        if (json == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not list WSL distributions");
        return JsonSerializer.Deserialize(Take(json) ?? "[]", WslJson.Info<List<WslDistro>>()) ?? [];
    }

    /// <summary>What opening a saved connection to <paramref name="distro"/> would find on this PC.</summary>
    public static WslAvailability WslAvailabilityOf(string distro)
    {
        var json = TerminalNative.bastion_wsl_availability_json(distro, out var err);
        if (json == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not check the WSL distribution");
        return JsonSerializer.Deserialize(Take(json) ?? "{}", WslJson.Info<WslAvailability>()) ?? new WslAvailability("removed", null, []);
    }

    private static readonly JsonSerializerOptions WslJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    /// <summary>
    /// Take ownership of a terminal handle opened elsewhere in the interop layer (an SSH shell from
    /// <see cref="SessionManagerClient.ConnectSsh"/>). The handle must be live and not owned already.
    /// </summary>
    internal static TerminalSession Adopt(IntPtr handle)
    {
        if (handle == IntPtr.Zero) throw new BastionException("the core returned no terminal");
        return new TerminalSession(handle);
    }

    private static TerminalSession Wrap(IntPtr h, IntPtr err)
    {
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not start the terminal");
        return new TerminalSession(h);
    }

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(TerminalSession));

    /// <summary>The raw handle, for other interop calls that borrow this terminal (the session supervisor).</summary>
    internal IntPtr NativeHandle => H;

    public bool IsDisposed => _handle == IntPtr.Zero;
    public ulong Generation => _handle == IntPtr.Zero ? 0 : TerminalNative.bastion_terminal_generation(_handle);

    /// <summary>Held by a wait in flight; <see cref="Dispose"/> takes it too, so the handle is never freed under a wait.</summary>
    private readonly object _waitGate = new();

    /// <summary>
    /// Off the UI thread: block until the screen generation differs from <paramref name="after"/> or the timeout passes
    /// (TerminalWake). Returns <paramref name="after"/> once the session is disposed.
    /// </summary>
    public ulong WaitChange(ulong after, uint timeoutMs)
    {
        lock (_waitGate)
        {
            var h = _handle;
            return h == IntPtr.Zero ? after : TerminalNative.bastion_terminal_wait_change(h, after, timeoutMs);
        }
    }
    public bool IsAlive => _handle != IntPtr.Zero && TerminalNative.bastion_terminal_is_alive(_handle) == 1;

    /// <summary>
    /// End the program or connection but keep the screen: the session then reports not alive (the view fires Exited) and
    /// stays readable until disposed. Disconnect uses it so the tab stays, as on the Mac (MAC-RECONNECT-PANE).
    /// </summary>
    public void Close()
    {
        if (_handle != IntPtr.Zero) TerminalNative.bastion_terminal_close(_handle);
    }
    public bool BracketedPaste => _handle != IntPtr.Zero && TerminalNative.bastion_terminal_bracketed_paste(_handle) == 1;

    /// <summary>The theme background as 0xRRGGBB (0 once disposed).</summary>
    public uint Background => _handle == IntPtr.Zero ? 0 : TerminalNative.bastion_terminal_background(_handle);

    /// <summary>OSC 52 copy requests: "off", "ask" or "allow" (C ABI 25).</summary>
    public void SetClipboardPolicy(string policy)
    {
        if (TerminalNative.bastion_terminal_set_clipboard_policy(H, policy, out var err) != 0) throw new BastionException(Take(err) ?? "could not set the clipboard policy");
    }

    /// <summary>The program's latest OSC 52 copy, taken once; null when there is none or the policy is "off".</summary>
    public ClipboardRequest? TakeClipboardRequest()
    {
        if (_handle == IntPtr.Zero || Take(TerminalNative.bastion_terminal_take_clipboard_json(_handle)) is not { } json) return null;
        return JsonSerializer.Deserialize(json, CaseInsensitiveJson.Info<ClipboardRequest>());
    }

    /// <summary>
    /// Find-bar search (bastion_terminal_find_json): highlight the next match of <paramref name="text"/> above (<paramref name="forward"/>
    /// false) or below the last one, scrolling it into view. Plain text unless <paramref name="regex"/>; case is ignored
    /// unless <paramref name="matchCase"/>. Throws on an invalid regex.
    /// </summary>
    /// <summary>Generated metadata only (an options object without a resolver throws under Native AOT).</summary>
    private static readonly System.Text.Json.JsonSerializerOptions CaseInsensitiveJson = new() { PropertyNameCaseInsensitive = true, TypeInfoResolver = AotJson.Resolver };

    public TerminalFindResult Find(string text, bool forward, bool matchCase, bool regex)
    {
        var p = TerminalNative.bastion_terminal_find_json(H, text, forward ? 1 : 0, matchCase ? 1 : 0, regex ? 1 : 0, out var err);
        if (Take(p) is not { } json) throw new BastionException(Take(err) ?? "could not search the terminal");
        return JsonSerializer.Deserialize(json, CaseInsensitiveJson.Info<TerminalFindResult>())
            ?? new TerminalFindResult(0, 0, false);
    }

    public void ClearSearch() { if (_handle != IntPtr.Zero) TerminalNative.bastion_terminal_clear_search(_handle); }

    /// <summary>Whether the program turned on mouse reporting (DECSET 1000/1002/1003; C ABI 79).</summary>
    public bool MouseReporting => _handle != IntPtr.Zero && TerminalNative.bastion_terminal_mouse_reporting(_handle) == 1;

    /// <summary>Send a mouse event when the program's mode wants it; true when sent (C ABI 79).</summary>
    public bool Mouse(TermMouseButton button, TermMouseAction action, int row, int col, TermMouseMods mods)
    {
        if (_handle == IntPtr.Zero) return false;
        var r = TerminalNative.bastion_terminal_mouse(_handle, (uint)button, (uint)action, (ushort)Math.Clamp(row, 0, ushort.MaxValue), (ushort)Math.Clamp(col, 0, ushort.MaxValue), (uint)mods, out var err);
        if (r < 0) throw new BastionException(Take(err) ?? "mouse report failed");
        return r == 1;
    }

    /// <summary>Whether the program rang the bell since the last call (C ABI 27).</summary>
    public bool TakeBell() => _handle != IntPtr.Zero && TerminalNative.bastion_terminal_take_bell(_handle) == 1;

    /// <summary>Unread output, a long command's finish, a program notification and a typed ssh target since the last
    /// call, each taken once (C ABI 132). Remote text is already cleaned and capped by the core.</summary>
    public TerminalEvents TakeEvents()
    {
        if (_handle == IntPtr.Zero) return TerminalEvents.None;
        var json = LibraryClient.TakeString(TerminalNative.bastion_terminal_take_events_json(_handle), IntPtr.Zero);
        return string.IsNullOrEmpty(json) ? TerminalEvents.None : JsonSerializer.Deserialize(json, CaseInsensitiveJson.Info<TerminalEvents>()) ?? TerminalEvents.None;
    }

    /// <summary>Reconnect: keep <paramref name="old"/>'s text above this terminal's new prompt (C ABI 134).</summary>
    public void CarryOver(TerminalSession old)
    {
        if (_handle == IntPtr.Zero || old._handle == IntPtr.Zero || ReferenceEquals(old, this)) return;
        TerminalNative.bastion_terminal_carry_over(_handle, old._handle);
    }

    /// <summary>Whether a local terminal runs a program besides its shell (C ABI 133): true or false; null when that
    /// cannot be told (SSH, Telnet, serial, exited). On Windows the shell is busy while it has a child process.</summary>
    public bool? ForegroundBusy()
    {
        if (_handle == IntPtr.Zero) return null;
        // NULL means "cannot be told" (SSH, Telnet, serial, exited; C ABI 133), not an error: TakeString would throw and the
        // close of every live SSH tab failed silently (q-logv2w7).
        var p = TerminalNative.bastion_terminal_foreground_json(_handle);
        if (p == IntPtr.Zero) return null;
        var json = LibraryClient.TakeString(p, IntPtr.Zero);
        if (string.IsNullOrEmpty(json)) return null;
        return JsonNode.Parse(json)?["busy"]?.GetValue<bool>();
    }

    /// <summary>Scroll to the previous or next shell prompt (OSC 133 marks); false when there is none (C ABI 132).</summary>
    public bool JumpPrompt(bool forward) => _handle != IntPtr.Zero && TerminalNative.bastion_terminal_jump_prompt(_handle, forward ? 1 : 0) == 1;

    /// <summary>Tags naming a production connection (<c>production</c> or <c>prod</c>, any case), by the core's rule (C ABI 132).</summary>
    public static bool IsProduction(IReadOnlyList<string>? tags) =>
        tags is { Count: > 0 } && TerminalNative.bastion_tags_is_production(JsonSerializer.Serialize(tags, CaseInsensitiveJson.Info<IReadOnlyList<string>>())) == 1;

    /// <summary>Drop the scrollback; the visible screen stays (C ABI 27).</summary>
    public void ClearScrollback() { if (_handle != IntPtr.Zero) TerminalNative.bastion_terminal_clear_scrollback(_handle); }

    /// <summary>Lines of history kept (<c>terminal.scrollback</c>, ABI 74); shrinking drops the oldest.</summary>
    public void SetScrollback(int lines)
    {
        if (_handle == IntPtr.Zero || lines < 1) return;
        if (TerminalNative.bastion_terminal_set_scrollback(_handle, (uint)lines, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not change the scrollback"));
    }

    /// <summary>Switch to a built-in colour theme by id (see <see cref="TerminalThemes"/>); the next screen uses it.</summary>
    public void SetTheme(string id)
    {
        IntPtr err;
        var rc = TermThemes.DataDir is { } dir
            ? TerminalNative.bastion_terminal_set_theme_in(H, dir, id, out err)
            : TerminalNative.bastion_terminal_set_theme(H, id, out err);
        if (rc != 0) throw new BastionException(Take(err) ?? "could not set the terminal theme");
    }

    public TerminalScreen Screen()
    {
        var p = TerminalNative.bastion_terminal_screen(H, out var err);
        if (p == IntPtr.Zero) throw new BastionException(Take(err) ?? "no screen");
        try
        {
            var s = Marshal.PtrToStructure<NativeScreen>(p);
            var cells = new NativeCell[s.CellCount];
            unsafe
            {
                new ReadOnlySpan<NativeCell>((void*)s.Cells, cells.Length).CopyTo(cells);
                var text = new ReadOnlySpan<byte>((void*)s.Text, checked((int)s.TextLen));
                var strings = new string[cells.Length];
                for (var i = 0; i < cells.Length; i++)
                {
                    var c = cells[i];
                    // Bounds come from the core; check anyway so a bug there cannot read outside the buffer.
                    if (c.ChLen == 0 || c.ChOffset + c.ChLen > text.Length) { strings[i] = ""; continue; }
                    var slice = text.Slice((int)c.ChOffset, c.ChLen);
                    strings[i] = slice.Length == 1 && slice[0] < 0x80 ? AsciiCache[slice[0]] : Encoding.UTF8.GetString(slice);
                }
                return new TerminalScreen
                {
                    Cols = s.Cols, Rows = s.Rows, Cells = cells, CellText = strings,
                    CursorRow = s.CursorRow, CursorCol = s.CursorCol, CursorVisible = s.CursorVisible != 0,
                    AppCursor = s.AppCursor != 0, Alive = s.Alive != 0, Generation = s.Generation,
                    Title = s.Title == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(s.Title),
                };
            }
        }
        finally { TerminalNative.bastion_screen_free(p); }
    }

    private static readonly string[] AsciiCache = Enumerable.Range(0, 128).Select(i => ((char)i).ToString()).ToArray();

    public void Write(ReadOnlySpan<byte> bytes)
    {
        unsafe
        {
            fixed (byte* b = bytes)
                if (TerminalNative.bastion_terminal_write(H, b, (nuint)bytes.Length, out var err) != 0) throw new BastionException(Take(err) ?? "write failed");
        }
    }

    public void Write(string text) => Write(Encoding.UTF8.GetBytes(text));

    public void Paste(string text)
    {
        if (TerminalNative.bastion_terminal_paste(H, text, out var err) != 0) throw new BastionException(Take(err) ?? "paste failed");
    }

    public void Resize(int cols, int rows)
    {
        if (TerminalNative.bastion_terminal_resize(H, (ushort)cols, (ushort)rows, out var err) != 0) throw new BastionException(Take(err) ?? "resize failed");
    }

    public void Scroll(int lines) => TerminalNative.bastion_terminal_scroll(H, lines);
    public void SelectStart(int row, int col, int clicks) => TerminalNative.bastion_terminal_select_start(H, (ushort)Math.Max(0, row), (ushort)Math.Max(0, col), (byte)Math.Clamp(clicks, 1, 3));
    public void SelectExtend(int row, int col) => TerminalNative.bastion_terminal_select_extend(H, (ushort)Math.Max(0, row), (ushort)Math.Max(0, col));
    public void ClearSelection() => TerminalNative.bastion_terminal_clear_selection(H);
    /// <summary>Select the whole scrollback and screen (ABI 75).</summary>
    public void SelectAll() => TerminalNative.bastion_terminal_select_all(H);
    public string? SelectionText() => Take(TerminalNative.bastion_terminal_selection_text(H));
    /// <summary>The remote folder the shell last announced with OSC 7, or null (Follow Terminal Folder).</summary>
    public string? Cwd() => Take(EditLocalNative.bastion_terminal_cwd(H));

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        IntPtr h;
        // A TerminalWake wait may be in flight: free only after it returns. An idle shell's wake thread is nearly always
        // inside a 50 ms wait, so the UI thread waited out the rest of it on every tab close. Closing first ends the wait
        // at once (the core bumps the generation on close; core generation_tests), and the free closes again harmlessly.
        TerminalNative.bastion_terminal_close(_handle);
        lock (_waitGate)
        {
            h = _handle;
            _handle = IntPtr.Zero;
        }
        if (h == IntPtr.Zero) return;
        TerminalNative.bastion_terminal_free(h);
        LeakProbe.SessionFreed();
        LeakProbe.MarkDisposed(this);
    }
}

/// <summary>The core's built-in terminal colour themes (core/src/terminal.rs PRESETS), in display order.</summary>
public static class TerminalThemes
{
    public const string Default = "bastion-dark";

    public static readonly (string Id, string Label)[] All =
    [
        ("bastion-dark", "Gantry Dark"), ("bastion-light", "Gantry Light"), ("solarized-dark", "Solarized Dark"), ("high-contrast", "High Contrast"),
    ];
}

/// <summary>What happened in a terminal since the last poll (C ABI 132).</summary>
public sealed record TerminalEvents(
    [property: JsonPropertyName("activity")] bool Activity,
    [property: JsonPropertyName("finished")] FinishedCommand? Finished,
    [property: JsonPropertyName("notification")] ProgramNotification? Notification,
    [property: JsonPropertyName("typed_ssh")] TypedSsh? TypedSsh)
{
    public static readonly TerminalEvents None = new(false, null, null, null);
}

/// <summary>A command of 10 s or more finished (OSC 133 marks); <see cref="ExitCode"/> 0 is success, null unknown.</summary>
public sealed record FinishedCommand([property: JsonPropertyName("exit_code")] int? ExitCode, [property: JsonPropertyName("duration_ms")] ulong DurationMs);

/// <summary>A program's OSC 9 / OSC 777 notification, cleaned by the core.</summary>
public sealed record ProgramNotification([property: JsonPropertyName("title")] string Title, [property: JsonPropertyName("body")] string Body);

/// <summary><c>ssh [user@]host[:port]</c> typed in the local shell; never a password.</summary>
public sealed record TypedSsh([property: JsonPropertyName("host")] string Host, [property: JsonPropertyName("user")] string? User, [property: JsonPropertyName("port")] int? Port);

/// <summary>A program's OSC 52 copy; <see cref="Ask"/> means show it and copy only on Allow.</summary>
public sealed record ClipboardRequest(string Text, bool Ask);

/// <summary>Mouse buttons for <see cref="TerminalSession.Mouse"/>, numbered as the C ABI.</summary>
public enum TermMouseButton : uint { Left = 0, Middle = 1, Right = 2, WheelUp = 3, WheelDown = 4, None = 5 }

/// <summary>Mouse actions for <see cref="TerminalSession.Mouse"/>, numbered as the C ABI.</summary>
public enum TermMouseAction : uint { Press = 0, Release = 1, Motion = 2 }

/// <summary>Modifier bits for <see cref="TerminalSession.Mouse"/>.</summary>
[Flags]
public enum TermMouseMods : uint { None = 0, Shift = 1, Alt = 2, Ctrl = 4 }

/// <summary>Where the find bar's current match is: <see cref="Index"/> 1-based among <see cref="Total"/> (both 0 when
/// nothing matched); <see cref="Capped"/> when there are more matches than the core counted.</summary>
public sealed record TerminalFindResult(int Index, int Total, bool Capped)
{
    /// <summary>"3 of 12", "1000+ matches", or "No matches".</summary>
    public string Status => Total == 0 ? "No matches"
        : Capped ? (Index > 0 ? $"{Index} of {Total}+" : $"{Total}+ matches")
        : $"{Index} of {Total}";
}
