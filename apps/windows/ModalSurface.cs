using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The in-window dialog host (scrim + card). A plain Grid has no UI Automation peer, so screen readers and UIA saw the
/// dialog's controls mixed with everything under the scrim. This one is a Window-type element named after the dialog,
/// so assistive tech announces a dialog and tests can scope to it.
/// </summary>
public sealed partial class ModalSurface : Grid
{
    protected override AutomationPeer OnCreateAutomationPeer() => new ModalSurfacePeer(this);

    private sealed partial class ModalSurfacePeer(ModalSurface owner) : FrameworkElementAutomationPeer(owner)
    {
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Window;

        protected override string GetClassNameCore() => nameof(ModalSurface);

        protected override bool IsControlElementCore() => true;

        protected override string GetNameCore() =>
            AutomationProperties.GetName(Owner) is { Length: > 0 } name ? name : "Dialog";
    }
}
