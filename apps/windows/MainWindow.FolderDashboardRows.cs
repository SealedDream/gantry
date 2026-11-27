using System.Text;
using System.Text.Json;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

// DASH-01 folder dashboard rows (MainWindow.FolderDashboard.cs has the page). WIN-STALL-USER: the rows are read, keyed
// and sorted on a worker. The core call reads the connection history file and walks the library, and with the JSON and
// the sort it sat in the UI thread's frame of every load, the first show's included ('Escape' after the tree search,
// q-stall-ab). The UI thread keeps what touches the live tree or XAML: the item index (session rows change under
// connections in place) and the binding.
public sealed partial class MainWindow
{
    /// <summary>Counts row loads: only the newest one's rows are shown.</summary>
    private int _dashLoads;

    /// <summary>Read the shown folder's rows on a worker, then show them. A load asked for later wins.</summary>
    private async void LoadDashboardRows()
    {
        if (_dashFolderId is not { } folderId) return;
        var load = ++_dashLoads;
        DashPhase("rows-asked");
        var deep = _dashSubfolders.GetValueOrDefault(folderId);
        var (library, vault, dir, roots) = (_library, _credentials, HistoryDir, _roots);
        var connected = LiveConnectionIds.ToHashSet();
        var (column, descending) = (_dashSort, _dashDescending);
        var folderItem = TreeItem.Find(roots, folderId);
        var items = DashItems(folderItem);
        // Set now: a refresh while this load runs finds it under way and asks for no second one (RefreshFolderDashboard).
        _dashLoadedRoots = roots;
        _dashConnected = connected;

        List<DashRow> sorted;
        string? error = null;
        try { sorted = await Task.Run(() => ReadDashRows(library, vault, dir, folderId, deep, items, connected, column, descending)); }
        catch (Exception ex) when (ex is BastionException or JsonException or ObjectDisposedException)
        {
            sorted = [];
            error = ex.Message;
        }
        if (load != _dashLoads || _windowClosed || _dash is null || _dashFolderId != folderId) return;
        DashPhase("rows-read");
        if (error is not null) Announce("Could not list the folder: " + error);

        _dashLocked = _credentials is null; // never opened here: opening the page must not prompt for the vault
        _dashSorted = sorted;
        if (_dashSort != column || _dashDescending != descending) SortDashboardRows(); // a header was clicked meanwhile
        _dashTitle.Text = folderItem?.Name ?? "Folder";
        _dashPath.Text = TreeItem.FolderPath(roots, folderItem?.ParentId) ?? "Library";
        _dashSubfoldersBox.IsChecked = deep;
        SyncDashLayout();
        ApplyDashFilter();
        DashPhase("rows-bound");
    }

    /// <summary>New rows made per frame while a page's first rows fill the list (see <see cref="BindDashRowsInSteps"/>).</summary>
    private const int DashRowsPerFrame = 8;

    /// <summary>Counts row binds: a step of an older bind stops when a newer one (a filter, a load) has bound its rows.</summary>
    private int _dashFills;

    /// <summary>
    /// WIN-STALL-USER round 4. A list that shows no rows yet makes a new container (a ListViewItem, its template and the
    /// row's cells) for every row in view, all in one frame: 35-69 ms for a full page on the speed VM ('frame
    /// render=68.8' right after 'rows-bound', q-stall-ab3). Here the first rows bind a few per frame until they fill the
    /// list's height, then all rows bind and reuse the containers made by then. The selection is set with all rows.
    /// </summary>
    private void BindDashRowsInSteps(int count, int fill)
    {
        var rows = _dashVisible;
        _dashSyncing = true;
        try { _dashList.ItemsSource = rows.GetRange(0, count); }
        finally { _dashSyncing = false; }
        DashPhase(FormattableString.Invariant($"rows-step {count}"));
        EventHandler<object>? laidOut = null;
        laidOut = (_, _) =>
        {
            _dashList.LayoutUpdated -= laidOut;
            // After the frame that made these rows: the next step runs in a frame of its own.
            DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
            {
                if (fill != _dashFills || _windowClosed || !ReferenceEquals(rows, _dashVisible)) return; // bound anew since
                var next = count + DashRowsPerFrame;
                if (next >= rows.Count || DashRowsFillList(count))
                {
                    BindDashRows();
                    UpdateDashState(); // the selection is back on the rows
                    DashPhase("rows-all");
                }
                else BindDashRowsInSteps(next, fill);
            });
        };
        _dashList.LayoutUpdated += laidOut;
    }

    /// <summary>The first <paramref name="count"/> rows reach the list's bottom (each as tall as the first one).</summary>
    private bool DashRowsFillList(int count) =>
        _dashList.ContainerFromIndex(0) is FrameworkElement first && first.ActualHeight > 0
        && count * first.ActualHeight >= _dashList.ActualHeight;

    /// <summary>The tree items below <paramref name="folder"/> by id. UI thread: it walks the live tree.</summary>
    private static Dictionary<string, TreeItem> DashItems(TreeItem? folder)
    {
        var items = new Dictionary<string, TreeItem>();
        void Index(IEnumerable<TreeItem> list) { foreach (var i in list) { items[i.Id] = i; Index(i.Children); } }
        if (folder is not null) Index(folder.Children);
        return items;
    }

    /// <summary>Worker: the core's rows, keyed and sorted. Reads only its arguments (the index is not changed after it is built).</summary>
    private static List<DashRow> ReadDashRows(LibraryClient library, CredentialStore? vault, string? dir, string folderId, bool deep,
        Dictionary<string, TreeItem> items, HashSet<string> connected, DashColumn column, bool descending)
    {
        var rows = FolderOverview.Rows(library, vault, dir, folderId, deep)
            .Select(r => new DashRow { Dto = r, Item = items.GetValueOrDefault(r.Id), FilterKey = FilterKeyOf(r) })
            .ToList();
        return Sorted(rows, column, descending, connected);
    }

    /// <summary>Lower-cased name, address, type, user and tags: the fields the filter matches, built once per load.</summary>
    private static string FilterKeyOf(OverviewRowDto r)
    {
        var sb = new StringBuilder();
        sb.Append(r.Name).Append('\n').Append(r.Address).Append('\n').Append(r.TypeLabel).Append('\n').Append(r.Username);
        if (r.Tags is { } tags) foreach (var t in tags) sb.Append('\n').Append(t);
        return sb.ToString().ToLowerInvariant();
    }

    /// <summary>One sort per load or sort change, on keys made once; connections stay before folders, as the core lists them.</summary>
    private void SortDashboardRows() => _dashSorted = Sorted(_dashSorted, _dashSort, _dashDescending, _dashConnected);

    private static List<DashRow> Sorted(List<DashRow> rows, DashColumn column, bool descending, IReadOnlySet<string> connected)
    {
        var keyed = rows.Select(r => (Key: SortKey(r, column, connected), Row: r)).ToArray();
        Array.Sort(keyed, (a, b) =>
        {
            if (a.Row.Dto.IsFolder != b.Row.Dto.IsFolder) return a.Row.Dto.IsFolder ? 1 : -1;
            var c = string.CompareOrdinal(a.Key, b.Key);
            return descending ? -c : c;
        });
        return keyed.Select(k => k.Row).ToList();
    }

    private static string SortKey(DashRow r, DashColumn column, IReadOnlySet<string> connected) => column switch
    {
        DashColumn.LastConnected => (r.Dto.LastConnectedAt ?? 0).ToString("D20"),
        DashColumn.Port => (r.Item?.Connection?.Port ?? 0).ToString("D10"),
        _ => Natural(CellText(r, column, connected)),
    };

    /// <summary>A byte-comparable key: lower-cased, digit runs zero-padded so "c2" sorts before "c10".</summary>
    private static string Natural(string s)
    {
        var sb = new StringBuilder(s.Length + 8);
        for (var i = 0; i < s.Length;)
        {
            if (!char.IsAsciiDigit(s[i])) { sb.Append(char.ToLowerInvariant(s[i++])); continue; }
            var start = i;
            while (i < s.Length && char.IsAsciiDigit(s[i])) i++;
            sb.Append('0', Math.Max(0, NaturalDigits - (i - start))).Append(s, start, i - start);
        }
        return sb.ToString();
    }

    private string CellText(DashRow r, DashColumn column) => CellText(r, column, _dashConnected);

    private static string CellText(DashRow r, DashColumn column, IReadOnlySet<string> connected)
    {
        var d = r.Dto;
        return column switch
        {
            DashColumn.Name => d.Name,
            DashColumn.Address => d.Address,
            DashColumn.Type => d.IsFolder ? "Folder" : d.TypeLabel,
            DashColumn.Status => connected.Contains(d.Id) ? "Connected" : "",
            DashColumn.User => d.Username ?? "",
            DashColumn.Login => d.IsFolder ? "" : LoginText(d),
            DashColumn.LastConnected => d.LastConnectedAt is { } t ? DateTimeOffset.FromUnixTimeSeconds(t).LocalDateTime.ToString("g") : "",
            DashColumn.LastResult => d.LastResult ?? "",
            DashColumn.Folder => d.FolderPath is { Count: > 0 } p ? string.Join(" / ", p) : "",
            DashColumn.Tags => d.Tags is { Count: > 0 } tags ? string.Join(", ", tags) : "",
            DashColumn.Port => r.Item?.Connection?.Port?.ToString() ?? "",
            _ => "",
        };
    }

    /// <summary>Only whether a login is available and where it comes from; never a secret.</summary>
    private static string LoginText(OverviewRowDto d) => d.Login switch
    {
        "saved" => "Saved",
        "inherited" => "From " + (d.LoginFrom ?? "folder"),
        "offered" => "Offered from " + (d.LoginFrom ?? "another connection"),
        _ => "None",
    };
}
