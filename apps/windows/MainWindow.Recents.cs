using System;
using System.Collections.Generic;
using System.Linq;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// The start page's bottom half: Recent sessions from the core's connection history, newest first. Double-click or
/// Enter opens one; right-click offers Remove from recents (spec docs/specs/session-restore-and-tab-bar.md, section 2).
/// </summary>
public sealed partial class MainWindow
{
    private const uint RecentLimit = 30;
    private ListView? _recentList;
    private TextBlock? _recentEmpty;

    /// <summary>One row of the list; the protocol glyph comes from the library item so it matches the tree.</summary>
    [WinRT.GeneratedBindableCustomProperty] // AOT: {Binding} in XamlReader templates reads properties through this, not reflection
    public sealed partial record RecentRow(string Connection, string Title, string Detail, string When, string Glyph, string Accessible)
    {
        /// <summary>
        /// The list item's name for screen readers and UI Automation. The template's Grid sets a name but a Grid has no
        /// automation peer, so the ListViewItem fell back to the record's default text ("RecentRow { ... }").
        /// </summary>
        public override string ToString() => Accessible;
    }

    private void BuildRecents()
    {
        var header = new TextBlock
        {
            Text = "Recent sessions",
            Style = (Style)Application.Current.Resources["BodyStrongTextStyle"],
            Margin = new Thickness(0, 0, 0, 8),
        };
        AutomationProperties.SetHeadingLevel(header, Microsoft.UI.Xaml.Automation.Peers.AutomationHeadingLevel.Level2);
        _recentEmpty = new TextBlock
        {
            Text = "Sessions you open appear here.",
            Style = (Style)Application.Current.Resources["BodySecondaryTextStyle"],
        };
        _recentList = new ListView
        {
            SelectionMode = ListViewSelectionMode.Single,
            IsItemClickEnabled = false,
            ItemTemplate = (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load(RecentTemplate),
        };
        AutomationProperties.SetName(_recentList, "Recent sessions");
        _recentList.DoubleTapped += (_, e) => { if (RowOf(e.OriginalSource) is { } r) { e.Handled = true; OpenRecent(r); } };
        // PreviewKeyDown: the ListViewItem handles Enter itself, so a KeyDown handler never sees it.
        _recentList.PreviewKeyDown += OnRecentKey;
        _recentList.ContextRequested += OnRecentContext;

        var panel = new Grid { MaxWidth = 640, Margin = new Thickness(24, 0, 24, 24) };
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(_recentEmpty, 1);
        Grid.SetRow(_recentList, 2);
        panel.Children.Add(header);
        panel.Children.Add(_recentEmpty);
        panel.Children.Add(_recentList);
        RecentHost.Children.Add(panel);
    }

    private const string RecentTemplate = """
        <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
          <Grid ColumnSpacing="12" Padding="0,6,0,6" AutomationProperties.Name="{Binding Accessible}">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto" />
              <ColumnDefinition Width="*" />
              <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <FontIcon Glyph="{Binding Glyph}" FontSize="16" VerticalAlignment="Center" />
            <StackPanel Grid.Column="1">
              <TextBlock Text="{Binding Title}" TextTrimming="CharacterEllipsis" />
              <TextBlock Text="{Binding Detail}" Style="{StaticResource CaptionSecondaryTextStyle}" TextTrimming="CharacterEllipsis" />
            </StackPanel>
            <TextBlock Grid.Column="2" Text="{Binding When}" Style="{StaticResource CaptionSecondaryTextStyle}" VerticalAlignment="Center" />
          </Grid>
        </DataTemplate>
        """;

    /// <summary>Counts refreshes: only the newest one's result is shown.</summary>
    private int _recentsGeneration;

    /// <summary>
    /// Read the recent sessions off the UI thread (the core call took 10-13 ms inside UI stalls when the last tab
    /// closed, q-kern-1), then fill the list on the UI thread. A refresh started later wins over an earlier one.
    /// </summary>
    private async void RefreshRecents()
    {
        if (_recentList is null) BuildRecents();
        var generation = ++_recentsGeneration;
        var library = _library;
        var dir = HistoryDir;
        IReadOnlyList<RecentSessionDto> recents;
        try { recents = _demo ? [] : await Task.Run(() => SessionRestore.Recents(library, dir, RecentLimit)); }
        catch (BastionException ex)
        {
            System.Diagnostics.Debug.WriteLine($"recent sessions unavailable: {ex.Message}");
            recents = [];
        }
        if (generation != _recentsGeneration || _windowClosed) return;
        var now = DateTimeOffset.UtcNow;
        var rows = recents.Select(r => ToRow(r, now)).ToList();
        _recentList!.ItemsSource = rows;
        _recentList.Visibility = rows.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        _recentEmpty!.Visibility = rows.Count > 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private RecentRow ToRow(RecentSessionDto r, DateTimeOffset now)
    {
        var glyph = FindItem(_roots, r.Connection)?.Glyph ?? FluentIcons.Object("terminal");
        var target = RecentText.Target(r.User, r.Host, r.Port);
        var detail = string.IsNullOrEmpty(r.LastError) ? $"{target} · {r.Protocol.ToUpperInvariant()}" : $"{target} · {r.LastError}";
        var when = RecentText.Ago(DateTimeOffset.FromUnixTimeSeconds(r.LastConnectedAt), now);
        return new RecentRow(r.Connection, r.Name, detail, when, glyph, $"{r.Name}, {target}, {r.Protocol}, last connected {when}");
    }

    private static RecentRow? RowOf(object source) => (source as FrameworkElement)?.DataContext as RecentRow;

    private void OnRecentKey(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != VirtualKey.Enter || _recentList?.SelectedItem is not RecentRow r) return;
        e.Handled = true;
        OpenRecent(r);
    }

    private void OnRecentContext(UIElement sender, ContextRequestedEventArgs e)
    {
        var row = RowOf(e.OriginalSource) ?? _recentList?.SelectedItem as RecentRow;
        if (row is null) return;
        e.Handled = true;
        var remove = new MenuFlyoutItem { Text = "Remove from recents" };
        remove.Click += (_, _) => RemoveRecent(row);
        var menu = new MenuFlyout();
        menu.Items.Add(remove);
        if (e.TryGetPosition(sender, out var at)) menu.ShowAt(sender, at);
        else menu.ShowAt(e.OriginalSource as FrameworkElement ?? (FrameworkElement)sender);
    }

    private void OpenRecent(RecentRow r)
    {
        if (FindItem(_roots, r.Connection) is not { } item) { RefreshRecents(); return; } // deleted since the list was built
        SelectItem(item.Id);
        _ = ConnectAsync(item);
    }

    private void RemoveRecent(RecentRow r)
    {
        try { ConnectionHistory.Forget(HistoryDir, r.Connection); }
        catch (BastionException ex) { _ = ShowModal("Could not remove from recents", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        RefreshRecents();
    }
}

/// <summary>Formatting for the Recent sessions rows; pure so it can be checked on its own.</summary>
public static class RecentText
{
    public static string Target(string? user, string host, int? port)
    {
        var who = string.IsNullOrEmpty(user) ? host : $"{user}@{host}";
        return port is { } p ? $"{who}:{p}" : who;
    }

    public static string Ago(DateTimeOffset then, DateTimeOffset now)
    {
        var d = now - then;
        if (d < TimeSpan.FromMinutes(1)) return "just now";
        if (d < TimeSpan.FromHours(1)) return $"{(int)d.TotalMinutes} min ago";
        if (d < TimeSpan.FromDays(1)) return $"{(int)d.TotalHours} h ago";
        if (d < TimeSpan.FromDays(7)) return $"{(int)d.TotalDays} d ago";
        return then.ToLocalTime().ToString("d MMM yyyy");
    }
}
