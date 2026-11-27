using Bastion.Shell;

var failures = 0;
void Check(bool ok, string what) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {what}"); if (!ok) failures++; }

var main = new PixelRect(0, 0, 1920, 1040);
var right = new PixelRect(1920, 0, 2560, 1400);

Check(WindowLaunch.Centred(1280, 800, main) == new PixelRect(320, 120, 1280, 800), "a fixed size is centred on its screen");
Check(WindowLaunch.Centred(4000, 3000, main) == new PixelRect(0, 0, 1920, 1040), "a fixed size larger than the screen is clamped to it");
Check(WindowLaunch.Clamp(new PixelRect(100, 50, 1000, 700), main) == new PixelRect(100, 50, 1000, 700), "a frame that fits stays where it was");
Check(WindowLaunch.Clamp(new PixelRect(1500, 900, 1000, 700), main) == new PixelRect(920, 340, 1000, 700), "a frame running off the screen moves back inside");
Check(WindowLaunch.Clamp(new PixelRect(-50, -20, 2500, 1300), main) == new PixelRect(0, 0, 1920, 1040), "a frame larger than the screen shrinks to it");
Check(WindowLaunch.WorkAreaFor(new PixelRect(2000, 100, 1200, 800), [main, right], main) == right, "a frame on the second monitor opens there");
Check(WindowLaunch.WorkAreaFor(new PixelRect(5000, 100, 1200, 800), [main], main) == main, "a saved monitor that is gone falls back to the main screen");
Check(WindowLaunch.WorkAreaFor(new PixelRect(1800, 100, 400, 400), [main, right], main) == right, "a frame across two monitors goes to the one it covers most");

if (failures > 0) { Console.WriteLine($"{failures} failed"); return 1; }
Console.WriteLine("all passed");
return 0;
