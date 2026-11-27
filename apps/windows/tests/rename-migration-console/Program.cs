// Console checks of AppRename (Bastion -> Gantry data folder migration). Exit code 0 = all passed.
using System.Text;
using Bastion.Shell;

var failures = 0;
void Check(bool ok, string what) { Console.WriteLine((ok ? "PASS " : "FAIL ") + what); if (!ok) failures++; }

string Fresh()
{
    var d = Path.Combine(Path.GetTempPath(), "gantry-rename-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(d);
    return d;
}

// 1. A real old-name data set is copied, verified, marked; the old folder is unchanged.
var parent = Fresh();
var old = Path.Combine(parent, "Bastion");
Directory.CreateDirectory(Path.Combine(old, "plugins", "dev.bastion.postgres"));
Directory.CreateDirectory(Path.Combine(old, "document-keys"));
File.WriteAllText(Path.Combine(old, "library.json"), "{\"folders\":[]}");
File.WriteAllBytes(Path.Combine(old, "credentials.vault"), Enumerable.Range(0, 70000).Select(i => (byte)(i * 7)).ToArray());
File.WriteAllText(Path.Combine(old, "known_hosts"), "web.example ssh-ed25519 AAAA\n");
File.WriteAllText(Path.Combine(old, "settings.json"), "{}");
File.WriteAllText(Path.Combine(old, "document-keys", "6b6579"), "blob");
File.WriteAllText(Path.Combine(old, "plugins", "dev.bastion.postgres", "installed.json"), "{\"id\":\"dev.bastion.postgres\"}");
var before = Snapshot(old);
Check(AppRename.MigrateFolder(parent) == AppRename.Outcome.Migrated, "first launch migrates");
var gantry = Path.Combine(parent, "Gantry");
var after = Snapshot(gantry);
Check(before.All(kv => after.TryGetValue(kv.Key, out var v) && v == kv.Value), "every file arrives byte for byte");
Check(File.Exists(Path.Combine(gantry, AppRename.Marker)), "marker written");
Check(Snapshot(old).SequenceEqual(before), "old folder kept unchanged");
Check(!Directory.GetDirectories(parent, "Gantry.migrating-*").Any(), "no staging folder left");

// 2. Second launch: nothing happens, and edits in Gantry are not overwritten.
File.WriteAllText(Path.Combine(gantry, "library.json"), "{\"changed\":true}");
Check(AppRename.MigrateFolder(parent) == AppRename.Outcome.NotNeeded, "second launch does nothing");
Check(File.ReadAllText(Path.Combine(gantry, "library.json")).Contains("changed"), "new data untouched");

// 3. No old folder: nothing happens, no Gantry folder is made here.
var empty = Fresh();
Check(AppRename.MigrateFolder(empty) == AppRename.Outcome.NotNeeded && !Directory.Exists(Path.Combine(empty, "Gantry")), "fresh install untouched");

// 4. A failed copy leaves nothing behind and the old folder intact; a later launch succeeds.
var failing = Fresh();
var oldF = Path.Combine(failing, "Bastion");
Directory.CreateDirectory(oldF);
File.WriteAllText(Path.Combine(oldF, "library.json"), "x");
var locked = Path.Combine(oldF, "locked.bin");
File.WriteAllText(locked, "y");
AppRename.Outcome outcome;
if (OperatingSystem.IsWindows())
{
    using (new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) outcome = AppRename.MigrateFolder(failing);
}
else
{
    File.SetUnixFileMode(locked, UnixFileMode.None);
    outcome = AppRename.MigrateFolder(failing);
    File.SetUnixFileMode(locked, UnixFileMode.UserRead | UnixFileMode.UserWrite);
}
Check(outcome == AppRename.Outcome.Failed, "unreadable file fails the copy");
Check(!Directory.Exists(Path.Combine(failing, "Gantry")) && !Directory.GetDirectories(failing, "Gantry.migrating-*").Any(), "failed copy leaves no Gantry folder");
Check(File.ReadAllText(Path.Combine(oldF, "library.json")) == "x", "old data intact after failure");
Check(AppRename.MigrateFolder(failing) == AppRename.Outcome.Migrated, "next launch retries and succeeds");

// 5. Personal document: an existing pre-rename document is used where it is; otherwise the new path.
var docs = Fresh();
var data = Path.Combine(docs, "data"); Directory.CreateDirectory(data);
Check(AppRename.PersonalDocument(docs, data) == Path.Combine(docs, "Gantry", "Personal.gantry"), "new install uses Gantry\\Personal.gantry");
Directory.CreateDirectory(Path.Combine(docs, "Bastion"));
File.WriteAllText(Path.Combine(docs, "Bastion", "Personal.bastion"), "doc");
Check(AppRename.PersonalDocument(docs, data) == Path.Combine(docs, "Gantry", "Personal.gantry"), "old Personal.bastion not used without the migration marker (its device key is not here)");
File.WriteAllText(Path.Combine(data, AppRename.Marker), "{}");
Check(AppRename.PersonalDocument(docs, data) == Path.Combine(docs, "Bastion", "Personal.bastion"), "existing Personal.bastion kept in place after a migration");

foreach (var d in new[] { parent, empty, failing, docs }) Directory.Delete(d, true);
// 6. The three cases of an existing profile (coordinator 2026-11-23): Roaming, Local and Documents together.
string Profile(bool gantrySeed, bool gantryLibrary)
{
    var root = Fresh();
    foreach (var d in new[] { "roaming/Bastion/device-key", "local/Bastion", "docs/Bastion" }) Directory.CreateDirectory(Path.Combine(root, d));
    File.WriteAllText(Path.Combine(root, "roaming/Bastion/device-key/blob"), "key");
    File.WriteAllText(Path.Combine(root, "local/Bastion/task-last.json"), "{}");
    File.WriteAllText(Path.Combine(root, "docs/Bastion/Personal.bastion"), "doc");
    if (gantrySeed) { Directory.CreateDirectory(Path.Combine(root, "roaming/Gantry")); File.WriteAllText(Path.Combine(root, "roaming/Gantry/seed.txt"), "s"); Directory.CreateDirectory(Path.Combine(root, "local/Gantry")); }
    if (gantryLibrary) { Directory.CreateDirectory(Path.Combine(root, "roaming/Gantry/device-key")); Directory.CreateDirectory(Path.Combine(root, "docs/Gantry")); File.WriteAllText(Path.Combine(root, "docs/Gantry/Personal.gantry"), "own"); }
    return root;
}
string R(string root, string p) => Path.GetFullPath(Path.Combine(root, p.Replace('/', Path.DirectorySeparatorChar)));

// a. Bastion data, an empty Gantry folder already there (failed first start, test seed): migrate now, both folders.
var a = Profile(gantrySeed: true, gantryLibrary: false);
Check(AppRename.MigrateDataFolders(R(a, "roaming"), R(a, "local"), R(a, "docs")) == AppRename.Outcome.Migrated, "case a: Bastion data + empty Gantry folder migrates");
Check(File.ReadAllText(R(a, "roaming/Gantry/device-key/blob")) == "key" && File.Exists(R(a, "roaming/Gantry/" + AppRename.Marker)), "case a: device key copied, marker written");
Check(File.Exists(R(a, "local/Gantry/task-last.json")) && File.Exists(R(a, "local/Gantry/" + AppRename.Marker)), "case a: Local migrated with Roaming");
Check(Directory.GetDirectories(R(a, "roaming"), "Gantry.before-migration-*").Any(d => File.Exists(Path.Combine(d, "seed.txt"))), "case a: the earlier Gantry folder is kept aside");
Check(File.ReadAllText(R(a, "roaming/Gantry/seed.txt")) == "s", "case a: the settings-only Gantry folder keeps its own files");
Check(File.ReadAllText(R(a, "roaming/Bastion/device-key/blob")) == "key", "case a: Bastion folder untouched");
Check(AppRename.PersonalDocument(R(a, "docs"), R(a, "roaming/Gantry")) == R(a, "docs/Bastion/Personal.bastion"), "case a: the old Personal.bastion opens with its key");

// b. Gantry already has its own library: both folders left alone, nothing merged.
var b = Profile(gantrySeed: false, gantryLibrary: true);
Check(AppRename.MigrateDataFolders(R(b, "roaming"), R(b, "local"), R(b, "docs")) == AppRename.Outcome.HasOwnLibrary, "case b: own Gantry library is kept");
Check(!File.Exists(R(b, "roaming/Gantry/" + AppRename.Marker)) && !Directory.Exists(R(b, "local/Gantry")), "case b: nothing migrated, Roaming and Local alike");
Check(AppRename.PersonalDocument(R(b, "docs"), R(b, "roaming/Gantry")) == R(b, "docs/Gantry/Personal.gantry"), "case b: its own Personal.gantry opens");

// c. No Bastion data at all: a new Personal.gantry.
var c = Fresh();
Check(AppRename.MigrateDataFolders(R(c, "roaming"), R(c, "local"), R(c, "docs")) == AppRename.Outcome.NotNeeded, "case c: no Bastion data, nothing to migrate");
Check(AppRename.PersonalDocument(R(c, "docs"), R(c, "roaming/Gantry")) == R(c, "docs/Gantry/Personal.gantry"), "case c: new Personal.gantry");
foreach (var d in new[] { a, b, c }) Directory.Delete(d, true);

Console.WriteLine(failures == 0 ? "ALL PASSED" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;

static Dictionary<string, string> Snapshot(string root) =>
    Directory.GetFiles(root, "*", SearchOption.AllDirectories)
        .Where(f => Path.GetFileName(f) != AppRename.Marker)
        .ToDictionary(f => Path.GetRelativePath(root, f), f => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(f))));
