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

// Same wording as the Mac (QuitDecision.swift, CLOSE-01-MAC.md).
Check("title", QuitDecision.Title == "Quit Gantry?");
Check("buttons", QuitDecision.QuitButton == "Quit" && QuitDecision.CancelButton == "Cancel");
Check("one session", QuitDecision.Message(1) == "1 session is still open. Quitting disconnects it.");
Check("two sessions", QuitDecision.Message(2) == "2 sessions are still open. Quitting disconnects them.");
Check("three sessions", QuitDecision.Message(3) == "3 sessions are still open. Quitting disconnects them.");
Check("1000 sessions", QuitDecision.Message(1000) == "1000 sessions are still open. Quitting disconnects them.");

// Ask only with the setting on, a user's quit and something live.
Check("live, setting on: asks", QuitDecision.ShouldAsk(true, false, 1));
Check("many live: asks", QuitDecision.ShouldAsk(true, false, 7));
Check("nothing live: no question", !QuitDecision.ShouldAsk(true, false, 0));
Check("setting off: no question", !QuitDecision.ShouldAsk(false, false, 3));
Check("app-driven quit: no question", !QuitDecision.ShouldAsk(true, true, 3));
Check("setting off and nothing live", !QuitDecision.ShouldAsk(false, false, 0));

Console.WriteLine($"QUIT-DECISION cases={cases} failures={failures}");
return failures == 0 ? 0 : 1;
