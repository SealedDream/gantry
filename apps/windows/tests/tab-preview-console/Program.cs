using Bastion.Shell;

var failures = 0;
void Check(bool ok, string what)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {what}");
    if (!ok) failures++;
}

var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

// Cap: the least recently shown goes first.
var cache = new PreviewCache<int, string>(3);
for (var i = 0; i < 3; i++) cache.Store(i, $"img{i}", t0);
cache.TryGet(0, out _);
cache.Store(3, "img3", t0);
Check(cache.Count == 3, "cache never holds more than its limit");
Check(!cache.TryGet(1, out _), "least recently shown image dropped first");
Check(cache.TryGet(0, out var kept) && kept == "img0", "recently shown image kept");
Check(new PreviewCache<int, string>().Limit == 64, "default cap is 64");

// Refresh at most once a second.
Check(cache.NeedsRefresh(9, t0), "missing image needs a refresh");
Check(!cache.NeedsRefresh(3, t0.AddMilliseconds(500)), "no refresh within a second");
Check(cache.NeedsRefresh(3, t0.AddSeconds(1)), "refresh after a second");

// Closed tabs and lock.
cache.Retain([0, 3]);
Check(cache.Count == 2 && !cache.TryGet(2, out _), "closed tabs leave the cache");
cache.Clear();
Check(cache.Count == 0, "lock clears every image");

// Who may show the remote screen.
Check(TabPreviewRules.MayShowImage(true, false, false), "shown normally");
Check(!TabPreviewRules.MayShowImage(true, true, false), "never while locked");
Check(!TabPreviewRules.MayShowImage(true, false, true), "never for Hide tab preview");
Check(!TabPreviewRules.MayShowImage(false, false, false), "never with previews off");

// Sizes, grid and keys (the same numbers as Native Mac).
Check(TabPreviewRules.ScaledSize(1920, 1080) == (480, 270), "1080p scales to 480 wide");
Check(TabPreviewRules.ScaledSize(300, 200) == (300, 200), "small pictures are not enlarged");
Check(TabPreviewRules.ScaledSize(0, 0) == (0, 0), "empty picture stays empty");
Check(TabPreviewRules.Columns(100) == 1, "at least one column");
Check(TabPreviewRules.Columns(1040) == 4, "1040 px gives four columns");
Check(TabPreviewRules.Move(0, 0, 1, 10, 4) == 4, "down moves one row");
Check(TabPreviewRules.Move(9, 1, 0, 10, 4) == 9, "right stops at the last tile");
Check(TabPreviewRules.Move(1, 0, -1, 10, 4) == 0, "up stops at the first tile");
Check(TabPreviewRules.Move(0, 1, 0, 0, 4) == 0, "empty overview");
Check(TabPreviewRules.HoverDelay == TimeSpan.FromMilliseconds(400), "400 ms hover delay");

// Downscale keeps the picture's pixels.
var w = 960; var h = 540;
var src = new byte[w * h * 4];
for (var p = 0; p < w * h; p++) { src[p * 4] = 10; src[p * 4 + 1] = 20; src[p * 4 + 2] = 30; src[p * 4 + 3] = 255; }
var (pix, dw, dh) = TabPreviewRules.Downscale(src, w, h);
Check(dw == 480 && dh == 270 && pix.Length == 480 * 270 * 4, "downscale size");
Check(pix[0] == 10 && pix[1] == 20 && pix[2] == 30 && pix[^1] == 255, "downscale keeps colours");
Check(TabPreviewRules.Downscale(new byte[4], 10, 10).Width == 0, "short buffer gives nothing");

// Terminal text: last rows with text.
var cells = new[] { "a", "b", "", "", "c", "", "", "", "", "", "", "" };
Check(TabPreviewRules.LastLines(cells, 3, 14) == "ab\n c", "terminal lines trimmed and trailing blank rows dropped");
Check(TabPreviewRules.LastLines(cells, 3, 1) == " c", "only the last rows");

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
