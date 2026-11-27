using Bastion.Shell;
using Rgb = Bastion.Shell.AccentContrast.Rgb;

var failures = 0;
void Check(bool ok, string what)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {what}");
    if (!ok) failures++;
}

// The palette (core/src/theme.rs ACCENTS).
var accents = new (string Name, Rgb Hex)[]
{
    ("electric", new(0x2E, 0x6B, 0xFF)), ("cyan", new(0x00, 0xA8, 0xD1)), ("violet", new(0x7D, 0x5C, 0xFF)),
    ("emerald", new(0x0F, 0xA6, 0x73)), ("amber", new(0xE6, 0x94, 0x0A)), ("rose", new(0xED, 0x40, 0x5E)),
};

Check(Math.Abs(AccentContrast.Ratio(Rgb.White, Rgb.Black) - 21) < 0.01, "white on black is 21:1");
Check(AccentContrast.Ratio(Rgb.White, new Rgb(0xE6, 0x94, 0x0A).Mix(Rgb.Black, 0.15)) < 4.5, "amber at Fluent's Dark1 fails with white text (the owner's report)");
foreach (var (name, hex) in accents)
{
    var fill = AccentContrast.ReadableFill(hex);
    foreach (var opacity in new[] { 1.0, AccentContrast.HoverOpacity })
    {
        var r = AccentContrast.Ratio(Rgb.White, AccentContrast.OverWhite(fill, opacity));
        Console.WriteLine($"  {name} fill {fill} opacity {opacity:0.0} white {r:0.00}");
        Check(r >= AccentContrast.RequiredRatio, $"{name}: white text on the accent fill at {opacity:0.0} is at least 4.5:1");
    }
    // Dark theme: Fluent's Light2 shade (45 % towards white) with black text.
    var dark = hex.Mix(Rgb.White, 0.45);
    Check(AccentContrast.Ratio(Rgb.Black, dark) >= AccentContrast.RequiredRatio, $"{name}: dark-theme fill {dark} with black text");
}
return failures == 0 ? 0 : 1;
