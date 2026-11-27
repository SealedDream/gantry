using Bastion.Shell;

// Unit tests for DesktopFitRules (RDP-VNC-FIT). One PASS or FAIL line per test; exit code = failures.
var failures = 0;
void Test(string name, Action body)
{
    try { body(); Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failures++; Console.WriteLine($"FAIL {name}: {ex.Message}"); }
}
void Equal<T>(T expected, T actual, string what)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"{what}: expected [{expected}], got [{actual}]");
}

Test("parse: fit is the default", () =>
{
    Equal(DesktopFit.Fit, DesktopFitRules.Parse(null), "null");
    Equal(DesktopFit.Fit, DesktopFitRules.Parse(""), "empty");
    Equal(DesktopFit.Fit, DesktopFitRules.Parse("bogus"), "unknown");
    Equal(DesktopFit.Fixed, DesktopFitRules.Parse("fixed"), "fixed");
    Equal(DesktopFit.Scale, DesktopFitRules.Parse(" Scale "), "scale");
});
Test("resolution: WxH parses, window and junk do not", () =>
{
    Equal<(int, int)?>((1920, 1080), DesktopFitRules.ParseResolution("1920x1080"), "1920x1080");
    Equal<(int, int)?>(null, DesktopFitRules.ParseResolution("window"), "window");
    Equal<(int, int)?>(null, DesktopFitRules.ParseResolution("0x10"), "zero");
    Equal<(int, int)?>(null, DesktopFitRules.ParseResolution("1x2x3"), "three parts");
});
Test("tab pixels: device pixels, clamped, fallback before layout", () =>
{
    Equal((1500, 900), DesktopFitRules.TabPixels(1000, 600, 1.5), "150%");
    Equal((DesktopFitRules.FallbackWidth, DesktopFitRules.FallbackHeight), DesktopFitRules.TabPixels(0, 0, 1), "not laid out");
    Equal((200, 8192), DesktopFitRules.TabPixels(50, 9000, 1), "clamped");
});
Test("connect size: fit uses the tab, fixed and scale use Desktop size", () =>
{
    var tab = (1600, 900);
    Equal(tab, DesktopFitRules.ConnectSize(DesktopFit.Fit, "1920x1080", tab), "fit ignores Desktop size");
    Equal((1920, 1080), DesktopFitRules.ConnectSize(DesktopFit.Fixed, "1920x1080", tab), "fixed");
    Equal((1280, 720), DesktopFitRules.ConnectSize(DesktopFit.Scale, "1280x720", tab), "scale");
    Equal(tab, DesktopFitRules.ConnectSize(DesktopFit.Fixed, "window", tab), "fixed + window = tab");
});
Test("placement: fit and scale fill one side, centred, never stretched", () =>
{
    var (x, y, s) = DesktopFitRules.Placement(DesktopFit.Scale, 1000, 500, 800, 800, 1);
    Equal(0.8, s, "scale"); Equal(0.0, x, "x"); Equal(200.0, y, "y");
    (x, y, s) = DesktopFitRules.Placement(DesktopFit.Fit, 800, 800, 800, 800, 1);
    Equal(1.0, s, "matching fit is 1:1"); Equal(0.0, x + y, "no margin");
});
Test("placement: fixed is one desktop pixel per device pixel, centred, clipped when larger", () =>
{
    var (x, y, s) = DesktopFitRules.Placement(DesktopFit.Fixed, 1000, 500, 800, 800, 1.25);
    Equal(0.8, s, "1/raster scale"); Equal(0.0, x, "x"); Equal(200.0, y, "y");
    (x, _, _) = DesktopFitRules.Placement(DesktopFit.Fixed, 2000, 500, 800, 800, 1);
    Equal(-600.0, x, "larger desktop overhangs both sides equally");
});
Test("pointer: maps through the placement, null outside", () =>
{
    Equal<(int, int)?>((500, 250), DesktopFitRules.ToDesktop(DesktopFit.Scale, 1000, 500, 800, 800, 1, 400, 400), "centre");
    Equal<(int, int)?>(null, DesktopFitRules.ToDesktop(DesktopFit.Scale, 1000, 500, 800, 800, 1, 400, 100), "letterbox");
    Equal<(int, int)?>((1000, 250), DesktopFitRules.ToDesktop(DesktopFit.Fixed, 2000, 500, 800, 800, 1, 400, 400), "fixed centre");
    Equal<(int, int)?>(null, DesktopFitRules.ToDesktop(DesktopFit.Fit, 0, 0, 800, 800, 1, 1, 1), "no frame");
});

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures;
