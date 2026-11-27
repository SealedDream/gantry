using System.Runtime.InteropServices;
using Bastion.Shell.Interop;

// A1-CORE-01-FU5 (Native Windows): "Did you make this library?" through the app's own interop (C ABI 100). Data folders
// stand for devices: a library made on device A is unknown on device B until it is answered for there.
// Usage: doc-origin-console --core <path to bastion_cabi.dll or .dylib> | --no-core. Exit 1 on a failure.
var results = new List<string>();
void Step(string name, bool ok, string detail = "") => results.Add($"{(ok ? "PASS" : "FAIL")} {name}{(detail.Length > 0 ? " (" + detail + ")" : "")}");

// --make <path>: write an unprotected library from a throwaway "device", which the app on this PC has never seen
// (the layout-fit surface "Library origin question" opens it). Needs --core.
if (Array.IndexOf(args, "--make") is >= 0 and var mk && mk + 1 < args.Length)
{
    var lib = Array.IndexOf(args, "--core") is >= 0 and var c && c + 1 < args.Length ? Path.GetFullPath(args[c + 1]) : "";
    NativeLibrary.SetDllImportResolver(typeof(LibraryClient).Assembly, (name, _, _) => name == "bastion_cabi" ? NativeLibrary.Load(lib) : IntPtr.Zero);
    var other = Path.Combine(Path.GetTempPath(), "bastion-origin-make-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(other);
    try
    {
        using var made = DocumentClient.Create("Sent by someone with a long library name for the fit check", other);
        made.Save(Path.GetFullPath(args[mk + 1]));
    }
    finally { Directory.Delete(other, true); }
    Console.WriteLine("made " + Path.GetFullPath(args[mk + 1]));
    return 0;
}

// ---- 1. Words (the packet's text) ----
Step("title", DocumentOriginText.Title == "Did you make this library?");
Step("buttons", DocumentOriginText.MadeIt == "I made it" && DocumentOriginText.SentIt == "Someone sent it");
Step("body names the library", DocumentOriginText.Body("Ops") == "\"Ops\" has not been opened on this device before. If someone else sent it to you, Bastion will ask before using any saved login it names.");

// ---- 2. The real core ----
if (!args.Contains("--no-core"))
{
    var core = Array.IndexOf(args, "--core") is >= 0 and var at && at + 1 < args.Length ? Path.GetFullPath(args[at + 1]) : "";
    if (!File.Exists(core)) { Console.WriteLine("ERROR give --core <path to bastion_cabi> or --no-core"); return 2; }
    NativeLibrary.SetDllImportResolver(typeof(LibraryClient).Assembly, (name, _, _) => name == "bastion_cabi" ? NativeLibrary.Load(core) : IntPtr.Zero);
    var root = Path.Combine(Path.GetTempPath(), "bastion-origin-" + Guid.NewGuid().ToString("N"));
    string deviceA = Path.Combine(root, "a"), deviceB = Path.Combine(root, "b"), deviceC = Path.Combine(root, "c");
    foreach (var d in new[] { deviceA, deviceB, deviceC }) Directory.CreateDirectory(d);
    try
    {
        // Device A makes the libraries (unprotected: no secrets in the test).
        string Make(string name)
        {
            var path = Path.Combine(root, name + ".bastion");
            using var made = DocumentClient.Create(name, deviceA);
            var before = made.OriginUnknown();
            made.Save(path);
            Step($"a library made here ({name}) is never asked: before and after its first save", !before && !made.OriginUnknown());
            return path;
        }
        var sentPath = Make("sent");
        var madePath = Make("made");
        var closedPath = Make("closed");
        // As the gate's Create does: a password before the first save (a throwaway value made here).
        using (var prot = DocumentClient.Create("protected", deviceA))
        {
            prot.SetPassword(Guid.NewGuid().ToString("N"));
            prot.Save(Path.Combine(root, "protected.bastion"));
            Step("a protected library made here is never asked", !prot.OriginUnknown() && !prot.Info.Locked);
        }
        using (var again = DocumentClient.Open(sentPath, deviceA))
            Step("a library made on this device is known", !again.OriginUnknown());

        // Device B: the migration runs once, before anything is opened, and knows none of A's files.
        Step("migration runs on the first start", DocumentClient.MigrateKnown(deviceB, null, []));
        Step("migration does not run twice", !DocumentClient.MigrateKnown(deviceB, null, []));

        using (var doc = DocumentClient.Open(sentPath, deviceB))
        {
            Step("opened by path on another device: asked", doc.OriginUnknown());
            doc.AnswerOrigin(madeByMe: false);
            Step("Someone sent it: no longer asked", !doc.OriginUnknown());
            Step("Someone sent it: the marks are a change to save", doc.Info.Dirty);
            doc.Save();
        }
        using (var doc = DocumentClient.Open(sentPath, deviceB))
            Step("Someone sent it: reopening is not asked again", !doc.OriginUnknown());

        var before = File.ReadAllBytes(madePath);
        using (var doc = DocumentClient.Open(madePath, deviceB))
        {
            doc.AnswerOrigin(madeByMe: true);
            Step("I made it: no longer asked, nothing to save", !doc.OriginUnknown() && !doc.Info.Dirty);
        }
        using (var doc = DocumentClient.Open(madePath, deviceB))
            Step("I made it: reopening is not asked again, file unchanged", !doc.OriginUnknown() && File.ReadAllBytes(madePath).SequenceEqual(before));

        var closedBefore = File.ReadAllBytes(closedPath);
        using (var doc = DocumentClient.Open(closedPath, deviceB)) Step("closed: asked", doc.OriginUnknown());
        using (var doc = DocumentClient.Open(closedPath, deviceB))
            Step("closed: asked again next time, file unchanged", doc.OriginUnknown() && File.ReadAllBytes(closedPath).SequenceEqual(closedBefore));

        var copy = Path.Combine(root, "copy-of-made.bastion");
        File.Copy(madePath, copy);
        using (var doc = DocumentClient.Open(copy, deviceB)) Step("a copy of a known library at another path is known", !doc.OriginUnknown());

        // Device C had the closed library in Recents before the update: the migration records it.
        using (DocumentClient.Open(closedPath, deviceC)) { }
        var cKnown = Path.Combine(deviceC, "known-documents.json");
        if (File.Exists(cKnown)) File.Delete(cKnown); // as before the update: Recents only, no record
        Step("migration from Recents runs", DocumentClient.MigrateKnown(deviceC, null, []));
        using (var doc = DocumentClient.Open(closedPath, deviceC)) Step("a library in Recents before the update is known", !doc.OriginUnknown());
        var record = File.Exists(cKnown) ? File.ReadAllText(cKnown) : "";
        Step("the record holds ids only", record.Length > 0 && !record.Contains("closed") && !record.Contains("bastion-origin"), record.Length > 200 ? record[..200] : record);
    }
    catch (BastionException ex) { Step("core calls", false, ex.Message); }
    finally { try { Directory.Delete(root, true); } catch (IOException) { } }
}

foreach (var r in results) Console.WriteLine(r);
var failed = results.Count(r => r.StartsWith("FAIL"));
Console.WriteLine($"{results.Count - failed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
