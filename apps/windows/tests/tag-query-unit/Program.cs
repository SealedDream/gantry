using Bastion.Shell;

// Unit tests for TagQuery (connection tags). One PASS or FAIL line per test; exit code = failures.
var failures = 0;
void Test(string name, Func<bool> body)
{
    bool ok;
    try { ok = body(); } catch (Exception) { ok = false; }
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (!ok) failures++;
}

Test("normalize: lower case, trimmed, no blanks or duplicates",
    () => string.Join(",", TagQuery.Normalize([" Prod", "web", "PROD", "", "db "])) == "prod,web,db");
Test("no tag: term keeps the text as typed", () => TagQuery.Parse("web 01") is { Tags.Count: 0, Text: "web 01" });
Test("tag:Prod is the tag prod, no free text", () => TagQuery.Parse("tag:Prod") is { Text: "" } q && q.Tags.SequenceEqual(["prod"]));
Test("several tag: terms combine; free text kept",
    () => TagQuery.Parse("TAG:prod web TAG:db") is { Text: "web" } q && q.Tags.SequenceEqual(["prod", "db"]));
Test("bare tag: is free text", () => TagQuery.Parse("tag:").Tags.Count == 0);
Test("admits: all tags present", () => TagQuery.Parse("tag:prod tag:db").Admits(["db", "prod", "x"]));
Test("admits: one missing refuses", () => !TagQuery.Parse("tag:prod tag:db").Admits(["prod"]));
Test("admits: null tags refuse a tag term", () => !TagQuery.Parse("tag:prod").Admits(null));
Test("admits: no tag terms admits all", () => TagQuery.Parse("web").Admits(null));

return failures;
