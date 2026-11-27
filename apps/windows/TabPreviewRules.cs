using System;
using System.Collections.Generic;
using System.Linq;

namespace Bastion.Shell;

/// <summary>
/// Rules for tab previews and the tab overview (B11, docs/plans/B11-PREVIEWS.md), the same numbers as Native Mac's
/// PreviewCache.swift. No WinUI types, so tests/tab-preview-console compiles this file on its own.
/// </summary>
public static class TabPreviewRules
{
    /// <summary>Pointer rest on a tab before its preview shows.</summary>
    public static readonly TimeSpan HoverDelay = TimeSpan.FromMilliseconds(400);
    /// <summary>A preview is refreshed at most this often, and only while a preview or the overview is shown.</summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(1);
    public const int CacheLimit = 64;
    public const int MaxImageSide = 480;
    public const double TileWidth = 260;
    public const int TextLines = 14;

    public static int Columns(double width) => Math.Max(1, (int)Math.Floor(width / TileWidth));

    public static (int Width, int Height) ScaledSize(int width, int height)
    {
        if (width <= 0 || height <= 0) return (0, 0);
        var scale = Math.Min(1.0, (double)MaxImageSide / Math.Max(width, height));
        return ((int)Math.Round(width * scale), (int)Math.Round(height * scale));
    }

    public static bool MayShowImage(bool previewsOn, bool locked, bool connectionHidesPreview) => previewsOn && !locked && !connectionHidesPreview;

    /// <summary>Overview keyboard: the index after an arrow key.</summary>
    public static int Move(int index, int dx, int dy, int count, int columns)
    {
        if (count <= 0) return 0;
        return Math.Clamp(index + dx + dy * Math.Max(1, columns), 0, count - 1);
    }

    /// <summary>A smaller copy of a top-down BGRA picture (nearest pixel), longest side at most <see cref="MaxImageSide"/>.</summary>
    public static (byte[] Pixels, int Width, int Height) Downscale(byte[] bgra, int width, int height)
    {
        var (w, h) = ScaledSize(width, height);
        if (w == 0 || bgra.Length < width * height * 4) return (Array.Empty<byte>(), 0, 0);
        var output = new byte[w * h * 4];
        for (var y = 0; y < h; y++)
        {
            var sy = Math.Min(height - 1, y * height / h);
            for (var x = 0; x < w; x++)
            {
                var sx = Math.Min(width - 1, x * width / w);
                Buffer.BlockCopy(bgra, (sy * width + sx) * 4, output, (y * w + x) * 4, 4);
            }
        }
        return (output, w, h);
    }

    /// <summary>The last <paramref name="count"/> rows with text of a row-major grid of cell strings.</summary>
    public static string LastLines(IReadOnlyList<string> cells, int cols, int count)
    {
        cols = Math.Max(cols, 1);
        var rows = new List<string>();
        for (var start = 0; start < cells.Count; start += cols)
            rows.Add(string.Concat(cells.Skip(start).Take(cols).Select(c => string.IsNullOrEmpty(c) ? " " : c)).TrimEnd());
        while (rows.Count > 0 && rows[^1].Length == 0) rows.RemoveAt(rows.Count - 1);
        return string.Join("\n", rows.Skip(Math.Max(0, rows.Count - count)));
    }
}

/// <summary>In-memory preview images, one per tab, capped, least recently shown first out. Never written anywhere.</summary>
public sealed class PreviewCache<TKey, TImage> where TKey : notnull
{
    private sealed class Entry
    {
        public required TImage Image { get; init; }
        public required DateTime Taken { get; init; }
        public ulong Shown { get; set; }
    }

    private readonly Dictionary<TKey, Entry> _entries = new();
    private ulong _clock;

    public PreviewCache(int limit = TabPreviewRules.CacheLimit) => Limit = Math.Max(1, limit);

    public int Limit { get; }
    public int Count => _entries.Count;

    public bool TryGet(TKey key, out TImage image)
    {
        if (_entries.TryGetValue(key, out var e))
        {
            e.Shown = ++_clock;
            image = e.Image;
            return true;
        }
        image = default!;
        return false;
    }

    public bool NeedsRefresh(TKey key, DateTime now) => !_entries.TryGetValue(key, out var e) || now - e.Taken >= TabPreviewRules.RefreshInterval;

    public void Store(TKey key, TImage image, DateTime now)
    {
        _entries[key] = new Entry { Image = image, Taken = now, Shown = ++_clock };
        while (_entries.Count > Limit) _entries.Remove(_entries.MinBy(kv => kv.Value.Shown).Key);
    }

    public void Remove(TKey key) => _entries.Remove(key);

    public void Retain(IEnumerable<TKey> keys)
    {
        var keep = keys.ToHashSet();
        foreach (var k in _entries.Keys.Where(k => !keep.Contains(k)).ToList()) _entries.Remove(k);
    }

    /// <summary>Lock or previews turned off: drop every image at once.</summary>
    public void Clear() => _entries.Clear();
}
