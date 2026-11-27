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
bool Throws<T>(Action a) where T : Exception { try { a(); return false; } catch (T) { return true; } }

var store = new SessionStore<string>();
object w1 = new(), w2 = new();
string a = "a", b = "b", c = "c", d = "d";

Check("empty window has no tabs", store.TabsOf(w1).Count == 0);
store.Add(w1, a); store.Add(w1, b); store.Add(w1, c); store.Add(w2, d);
Check("add keeps order", store.TabsOf(w1).SequenceEqual(new[] { a, b, c }));
Check("windows are separate", store.TabsOf(w2).SequenceEqual(new[] { d }));
Check("window of tab", store.WindowOf(b) == w1 && store.WindowOf(d) == w2);
Check("index of", store.IndexOf(w1, c) == 2 && store.IndexOf(w2, c) == -1 && store.IndexOf(new object(), a) == -1);
Check("all tabs",store.All.Count() == 4);
Check("same tab twice refused", Throws<InvalidOperationException>(() => store.Add(w2, a)));

var live = store.TabsOf(w1);
store.Reorder(w1, new[] { c, a, b });
Check("reorder", store.TabsOf(w1).SequenceEqual(new[] { c, a, b }));
Check("TabsOf is the live list", live.SequenceEqual(new[] { c, a, b }));
Check("reorder missing a tab refused", Throws<ArgumentException>(() => store.Reorder(w1, new[] { c, a })));
Check("reorder with another window's tab refused", Throws<ArgumentException>(() => store.Reorder(w1, new[] { c, a, d })));
Check("reorder with a duplicate refused", Throws<ArgumentException>(() => store.Reorder(w1, new[] { c, a, a })));
Check("failed reorder changes nothing", store.TabsOf(w1).SequenceEqual(new[] { c, a, b }));

Check("remove", store.Remove(a) && store.TabsOf(w1).SequenceEqual(new[] { c, b }) && store.WindowOf(a) is null);
Check("remove twice is false", !store.Remove(a));
store.Add(w1, a);
Check("removed tab can open again", store.TabsOf(w1).SequenceEqual(new[] { c, b, a }));
store.Remove(d);
Check("live list stays valid when emptied", store.TabsOf(w2).Count == 0);
Check("forget open window refused", Throws<InvalidOperationException>(() => store.ForgetWindow(w1)));
store.ForgetWindow(w2);
Check("forget empty window", store.TabsOf(w2).Count == 0 && store.All.Count() == 3);

Console.WriteLine($"SESSION-STORE cases={cases} failures={failures}");
return failures == 0 ? 0 : 1;
