using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Minimal;

public sealed partial class MainWindow : Window
{
    private int _n;
    public MainWindow()
    {
        InitializeComponent();
        var mode = Environment.GetEnvironmentVariable("MINIMAL_TABS") ?? "";
        if (mode.Contains("show")) Tabs.Visibility = Visibility.Visible;
        if (mode.Contains("closable")) Tabs.TabItems.Add(new TabViewItem { Header = "Second", Content = new TextBlock { Text = "x" } });
        if ((Environment.GetEnvironmentVariable("MINIMAL_COMMANDBAR") ?? "").Contains("show")) Bar.Visibility = Visibility.Visible;
    }
    private void AddText_Click(object sender, RoutedEventArgs e) => Host.Children.Add(new TextBlock { Text = "line " + (++_n) });
    private void DisableMe_Click(object sender, RoutedEventArgs e) => ((Button)sender).IsEnabled = false;
}
