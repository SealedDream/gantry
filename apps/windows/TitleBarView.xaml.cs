using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The title bar's controls (TitleBarView.xaml). MainWindow builds it after the first frame, wires its events and reads
/// its named controls through properties of the same names (MainWindow.LightStart.cs, WIN-COLD-LIGHT).
/// </summary>
public sealed partial class TitleBarView : Grid
{
    public TitleBarView() => InitializeComponent();
}
