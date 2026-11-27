using System;
using System.Linq;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Owner point 10: switch a host connection between SSH, RDP, VNC and Telnet from its right-click menu (and the details
// pane's More actions, which share MenuEntries). Each choice shows its protocol icon and full name; the current one is
// checked. The core does the change (core/src/properties.rs change_protocol): a default port follows the new protocol.
public sealed partial class MainWindow
{
    private static readonly (string Id, string Label)[] SwitchableProtocols =
        [("ssh", "SSH (terminal)"), ("rdp", "RDP (Remote Desktop)"), ("vnc", "VNC (screen sharing)"), ("telnet", "Telnet")];

    /// <summary>"Change protocol ▸" for a switchable connection, else null.</summary>
    private MenuFlyoutSubItem? ProtocolMenu(ConnectionDto c)
    {
        var current = c.Protocol.ToLowerInvariant();
        if (!SwitchableProtocols.Any(p => p.Id == current)) return null;
        var label = SwitchableProtocols.First(p => p.Id == current).Label.Split(' ')[0];
        var sub = new MenuFlyoutSubItem { Text = $"Protocol: {label}", Icon = MenuIcon(FluentIcons.Object(current)) };
        AutomationProperties.SetName(sub, $"Change protocol, now {label}");
        foreach (var (id, text) in SwitchableProtocols)
        {
            var item = new ToggleMenuFlyoutItem { Text = text, IsChecked = id == current, Icon = MenuIcon(FluentIcons.Object(id)) };
            AutomationProperties.SetName(item, text);
            if (id == current) item.IsEnabled = false;
            else item.Click += (_, _) => _ = Mutate(() => { _library.SetProperty(c.Id, "protocol", id); return c.Id; }, "Could not change the protocol");
            sub.Items.Add(item);
        }
        return sub;
    }
}
