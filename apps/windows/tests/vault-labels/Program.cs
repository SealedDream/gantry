using Bastion.Shell;

var cases = 0;
var failures = 0;
void Check(string name, bool ok)
{
    cases++;
    if (ok) return;
    failures++;
    Console.WriteLine($"FAIL {name}");
}

// A lookup that records being asked: with the vault locked it must never run.
var asked = 0;
string? Name(string id) { asked++; return id == "k1" ? "web key" : null; }
(string, string)? Inherited() { asked++; return ("k1", "Acme Corp"); }

// Locked (null lookups): "Locked", and nothing is asked of the vault.
Check("own credential, locked", VaultLabels.Credential("k1", null) == "Locked");
Check("inherited credential, locked", VaultLabels.Effective(null, null, null) == "Locked");
Check("own credential via Effective, locked", VaultLabels.Effective("k1", null, null) == "Locked");
Check("locked: the vault was not asked", asked == 0);

// No credential at all needs no vault either.
Check("no credential", VaultLabels.Credential(null, null) == "—");

// Open vault: names, missing and inherited.
Check("own credential, open", VaultLabels.Credential("k1", Name) == "web key");
Check("missing credential, open", VaultLabels.Credential("gone", Name) == "Missing from the vault");
Check("inherited, open", VaultLabels.Effective(null, Inherited, Name) == "web key (inherited from Acme Corp)");
Check("nothing inherited, open", VaultLabels.Effective(null, () => null, Name) == "—");

Console.WriteLine($"VAULT-LABELS cases={cases} failures={failures}");
return failures == 0 ? 0 : 1;
