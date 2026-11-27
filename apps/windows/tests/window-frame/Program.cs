using Bastion.Shell;

// W22: leaving full screen puts the window back inside the monitor's work area. Run: dotnet run --project tests/window-frame
var failures = 0;
var cases = 0;
void Check(string name, bool ok) { cases++; if (!ok) failures++; Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}"); }
var work = (X: 0, Y: 0, Width: 1280, Height: 760); // 1280x800 screen with a 40 px taskbar

Check("a frame that fits is unchanged", WindowFrame.ClampToWorkArea((100, 50, 900, 600), work) == (100, 50, 900, 600));
Check("1280x820 on a 1280x800 screen comes back 760 high, at the top", WindowFrame.ClampToWorkArea((0, 0, 1280, 820), work) == (0, 0, 1280, 760));
Check("a frame hanging off the bottom moves up", WindowFrame.ClampToWorkArea((100, 400, 800, 600), work) == (100, 160, 800, 600));
Check("a frame off the left moves right", WindowFrame.ClampToWorkArea((-300, 10, 800, 600), work) == (0, 10, 800, 600));
Check("a second monitor's work area keeps its offset", WindowFrame.ClampToWorkArea((1200, 0, 900, 700), (1280, 0, 1920, 1040)) == (1280, 0, 900, 700));
Check("wider and taller than the work area fills it", WindowFrame.ClampToWorkArea((-50, -50, 3000, 2000), work) == (0, 0, 1280, 760));

Console.WriteLine($"{cases - failures} passed, {failures} failed");
return failures == 0 ? 0 : 1;
