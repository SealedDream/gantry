using Microsoft.UI.Xaml;
using Windows.Foundation;

namespace Bastion.Shell;

public sealed partial class MainWindow
{
    /// <summary>Snapshot runs only: whether the open dialog and its primary button lie fully inside the window.</summary>
    internal string ModalFitForSnapshot()
    {
        if (Content is not FrameworkElement root || _modal is null) return "no dialog";
        Rect Bounds(FrameworkElement e) => e.TransformToVisual(root).TransformBounds(new Rect(0, 0, e.ActualWidth, e.ActualHeight));
        bool Inside(Rect r) => r.X >= 0 && r.Y >= 0 && r.Right <= root.ActualWidth + 0.5 && r.Bottom <= root.ActualHeight + 0.5;
        var card = Bounds(ModalCard);
        var primary = Bounds(ModalPrimary);
        var verdict = Inside(card) && Inside(primary) ? "fits" : "CLIPPED";
        return $"{verdict}: window {root.ActualWidth:0}x{root.ActualHeight:0}, dialog {card.Width:0}x{card.Height:0} at {card.X:0},{card.Y:0}, primary button bottom {primary.Bottom:0}";
    }
}
