using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Bastion.Shell;

// Unit tests for the "Clear copied passwords after" setting (A3-S1, Native Windows; the Mac half is PR #828).
// Part 1 checks the app's rule (SecretClipboardLifetime). Part 2 checks it against the core through bastion_cabi.dll:
// the setting's definition, the capability that shows it, and the value read from settings.json at copy time.
// Prints one PASS or FAIL line per test and exits with the number of failures.

// The DLL: the argument when given; else BASTION_CABI_DLL; else the first bastion_cabi.dll found walking up from this
// program: apps\windows\native\ (where build-core.ps1 copies it) or core-cabi\target\release\ (a cargo build).
string? FindCabi()
{
    if (Environment.GetEnvironmentVariable("BASTION_CABI_DLL") is { Length: > 0 } env) return env;
    for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
    {
        foreach (var candidate in new[] { Path.Combine(dir.FullName, "native", "bastion_cabi.dll"), Path.Combine(dir.FullName, "core-cabi", "target", "release", "bastion_cabi.dll") })
            if (File.Exists(candidate)) return candidate;
    }
    return null;
}
var given = args.Length == 1 ? args[0] : args.Length == 0 ? FindCabi() : null;
if (given is null || !File.Exists(given))
{
    Console.Error.WriteLine("usage: SecretClipboardUnit [path to bastion_cabi.dll]");
    Console.Error.WriteLine("  without a path: BASTION_CABI_DLL, else apps\\windows\\native\\ or core-cabi\\target\\release\\ above this program");
    Console.Error.WriteLine(given is null ? "  no bastion_cabi.dll found" : $"  not found: {given}");
    return 2;
}
var dll = Path.GetFullPath(given);
Console.WriteLine($"core: {dll}");
NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), (name, _, _) => name == Cabi.Lib ? NativeLibrary.Load(dll) : IntPtr.Zero);

var passed = 0;
var failures = 0;
void Test(string name, Action body)
{
    try { body(); passed++; Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failures++; Console.WriteLine($"FAIL {name}: {ex.Message}"); }
}
void Equal<T>(T expected, T actual, string what)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"{what}: expected {expected}, got {actual}");
}
void True(bool ok, string what) { if (!ok) throw new InvalidOperationException(what); }

const string Id = "security.clipboard-clear-seconds";
const string Capability = "secret-clipboard-lifetime";
string[] withCapability = [Capability];
string[] rejected = ["", "600", "0", "29", "61", "abc", " 30", "30 ", "030", "-30", "60.0", "45s", "true"];

// ---- Part 1: the rule ----

Test("the setting id and the capability are the core's", () =>
{
    Equal(Id, SecretClipboardLifetime.SettingId, "setting id");
    Equal(Capability, SecretClipboardLifetime.Capability, "capability");
});

Test("each choice gives its own lifetime", () =>
{
    Equal(TimeSpan.FromSeconds(30), SecretClipboardLifetime.From("30"), "30");
    Equal(TimeSpan.FromSeconds(45), SecretClipboardLifetime.From("45"), "45");
    Equal(TimeSpan.FromSeconds(60), SecretClipboardLifetime.From("60"), "60");
});

Test("a value that could not be read gives 30 seconds", () =>
    Equal(TimeSpan.FromSeconds(30), SecretClipboardLifetime.From(null), "null"));

Test("anything that is not a choice gives 30 seconds", () =>
{
    foreach (var bad in rejected) Equal(TimeSpan.FromSeconds(30), SecretClipboardLifetime.From(bad), $"'{bad}'");
});

Test("no input gives less than 30 or more than 60 seconds", () =>
{
    foreach (var v in rejected.Concat(["30", "45", "60", "3600", "999999999999999999999"]).Append(null))
    {
        var s = SecretClipboardLifetime.From(v).TotalSeconds;
        True(s is >= 30 and <= 60, $"'{v}' gave {s} s");
    }
});

Test("a reader that fails gives 30 seconds", () =>
    Equal(TimeSpan.FromSeconds(30), SecretClipboardLifetime.Read(() => throw new IOException("settings.json could not be read")), "throwing reader"));

Test("a reader's value goes through the rule", () =>
{
    Equal(TimeSpan.FromSeconds(45), SecretClipboardLifetime.Read(() => "45"), "45");
    Equal(TimeSpan.FromSeconds(30), SecretClipboardLifetime.Read(() => "600"), "600");
});

// ---- Part 2: against the core ----

var dir = Path.Combine(Path.GetTempPath(), "bastion-a3-s1-unit-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dir);
var path = Path.Combine(dir, "settings.json");
// What the app does at copy time: open settings.json now, read the value, close.
TimeSpan AtCopyTime() => SecretClipboardLifetime.Read(() => Cabi.GetOnce(path, Id));

try
{
    Test("the core offers the setting to an app that reports the capability", () =>
    {
        var d = Cabi.Definitions(withCapability).Single(x => x.GetProperty("id").GetString() == Id);
        Equal("security", d.GetProperty("category").GetString(), "category");
        Equal("Clear copied passwords after", d.GetProperty("label").GetString(), "label");
        Equal("choice", d.GetProperty("kind").GetString(), "kind");
        Equal("60", d.GetProperty("default").GetString(), "default");
        Equal("Only while it is still the latest copy; clipboard tools that ignore the history exclusion may keep theirs.", d.GetProperty("help").GetString(), "help");
        var options = d.GetProperty("options").EnumerateArray().Select(o => $"{o.GetProperty("id").GetString()}={o.GetProperty("label").GetString()}");
        Equal("30=30 seconds, 45=45 seconds, 60=60 seconds", string.Join(", ", options), "options");
    });

    Test("the app's choices are the core's choices", () =>
    {
        var d = Cabi.Definitions(withCapability).Single(x => x.GetProperty("id").GetString() == Id);
        var core = d.GetProperty("options").EnumerateArray().Select(o => o.GetProperty("id").GetString() ?? "").ToList();
        Equal(string.Join(",", core), string.Join(",", SecretClipboardLifetime.Choices), "choices");
        Equal(core.Min(int.Parse), SecretClipboardLifetime.FallbackSeconds, "the fallback is the shortest choice");
    });

    Test("the core hides the setting from an app without the capability", () =>
        True(Cabi.Definitions([]).All(x => x.GetProperty("id").GetString() != Id), "the setting was offered"));

    Test("search finds the setting", () =>
        True(Cabi.Search("clipboard password", withCapability).Contains(Id), "not found for 'clipboard password'"));

    Test("no settings file yet: 60 seconds, the default", () =>
    {
        True(!File.Exists(path), "the file exists");
        Equal(TimeSpan.FromSeconds(60), AtCopyTime(), "lifetime");
    });

    Test("each saved choice is what a copy made now gets", () =>
    {
        foreach (var seconds in new[] { 30, 45, 60, 30 })
        {
            Cabi.SetOnce(path, Id, seconds.ToString());
            Equal(TimeSpan.FromSeconds(seconds), AtCopyTime(), $"after saving {seconds}");
        }
    });

    Test("the core refuses a value that is not a choice and keeps the saved one", () =>
    {
        Cabi.SetOnce(path, Id, "45");
        foreach (var bad in new[] { "600", "0", "abc", "" })
        {
            var refused = false;
            try { Cabi.SetOnce(path, Id, bad); } catch (InvalidOperationException) { refused = true; }
            True(refused, $"'{bad}' was accepted");
        }
        Equal(TimeSpan.FromSeconds(45), AtCopyTime(), "lifetime after the refused values");
    });

    Test("the saved value is read back from disk (what a restart reads)", () =>
    {
        Cabi.SetOnce(path, Id, "30");
        True(File.ReadAllText(path).Contains("\"30\""), "settings.json does not hold 30");
        Equal("30", Cabi.GetOnce(path, Id), "a new handle on the same file");
    });

    Test("a hand-edited value that is not a choice reads as the default, never longer than 60", () =>
    {
        File.WriteAllText(path, "{\"values\":{\"" + Id + "\":\"600\"}}", new UTF8Encoding(false));
        Equal(TimeSpan.FromSeconds(60), AtCopyTime(), "lifetime");
    });

    Test("a damaged settings file gives 30 seconds", () =>
    {
        File.WriteAllText(path, "{ not json", new UTF8Encoding(false));
        Equal(TimeSpan.FromSeconds(30), AtCopyTime(), "lifetime");
    });
}
finally
{
    try { Directory.Delete(dir, recursive: true); } catch (IOException) { Console.WriteLine($"NOTE could not remove {dir}"); }
}

Console.WriteLine($"{passed} passed, {failures} failed");
return failures;

/// <summary>The C ABI entry points the app's SettingsClient uses (core-cabi/src/prefs.rs), declared again so this test needs none of the app's WinUI code.</summary>
internal static class Cabi
{
    internal const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bastion_string_free(IntPtr s);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_setting_definitions_json([MarshalAs(UnmanagedType.LPUTF8Str)] string? links, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_settings_search_json([MarshalAs(UnmanagedType.LPUTF8Str)] string query, [MarshalAs(UnmanagedType.LPUTF8Str)] string? links, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_settings_open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bastion_settings_free(IntPtr s);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_settings_get(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern int bastion_settings_set(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string value, out IntPtr err);

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { bastion_string_free(s); }
    }

    private static string Value(IntPtr s, IntPtr err) => s != IntPtr.Zero ? Take(s) ?? "" : throw new InvalidOperationException(Take(err) ?? "the core returned no value");

    private static IntPtr Open(string path)
    {
        var h = bastion_settings_open(path, out var err);
        return h != IntPtr.Zero ? h : throw new InvalidOperationException(Take(err) ?? "could not read the settings");
    }

    internal static List<JsonElement> Definitions(string[] links) =>
        JsonDocument.Parse(Value(bastion_setting_definitions_json(JsonSerializer.Serialize(links), out var err), err)).RootElement.EnumerateArray().ToList();

    internal static List<string?> Search(string query, string[] links) =>
        JsonDocument.Parse(Value(bastion_settings_search_json(query, JsonSerializer.Serialize(links), out var err), err)).RootElement.EnumerateArray().Select(e => e.GetString()).ToList();

    /// <summary>Open the file, read one value, close: a damaged file throws.</summary>
    internal static string GetOnce(string path, string id)
    {
        var h = Open(path);
        try { return Value(bastion_settings_get(h, id, out var err), err); }
        finally { bastion_settings_free(h); }
    }

    internal static void SetOnce(string path, string id, string value)
    {
        var h = Open(path);
        try { if (bastion_settings_set(h, id, value, out var err) != 0) throw new InvalidOperationException(Take(err) ?? "could not save the setting"); }
        finally { bastion_settings_free(h); }
    }
}
