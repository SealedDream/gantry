using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The details pane's controls (InspectorView.xaml). MainWindow builds it when it is first shown, wires its events and
/// reads its named controls through properties of the same names (MainWindow.LightStart.cs, WIN-COLD-LIGHT).
/// </summary>
public sealed partial class InspectorView : Grid
{
    public InspectorView() => InitializeComponent();
}
