using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;

namespace Bastion.Shell;

// Window shortcuts (Ctrl+N and the rest of the chord table) are read in RootGrid.PreviewKeyDown, which only sees keys
// while focus is inside the window's content. Right after launch, or when the window is activated with nothing focused,
// the keys went nowhere. On activation, focus moves to the place start-up would pick (PlaceStartupFocus).
public sealed partial class MainWindow
{
    private void InitKeyFocus() => Activated += (_, e) =>
    {
        if (e.WindowActivationState == WindowActivationState.Deactivated || _closed) return;
        _everActivated = true;
        // After this activation's own focus restore: only when nothing in the window holds focus.
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            if (_closed || _modal is not null || RootGrid.XamlRoot is not { } root) return;
            if (FocusManager.GetFocusedElement(root) is not null) return;
            PlaceStartupFocus();
        });
    };
}
