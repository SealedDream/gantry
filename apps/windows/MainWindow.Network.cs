using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.UI.Dispatching;

namespace Bastion.Shell;

/// <summary>
/// Auto-reconnect on a network change (core C ABI 62, <c>EVENT_NETWORK_CHANGED</c>): when the machine's usable
/// addresses change (Wi-Fi to Ethernet, VPN up or down, a new DHCP lease), every supervised SSH tab is told, and the
/// core replaces a live link at once or cuts its back-off short (only with auto-reconnect on). Windows raises
/// NetworkAddressChanged several times per change, so events are debounced and sent only when the address set differs.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>Windows fires a burst of address events per change; wait for it to settle.</summary>
    private static readonly TimeSpan NetworkSettle = TimeSpan.FromSeconds(2);

    private DispatcherQueueTimer? _networkTimer;
    private string _networkFingerprint = "";

    private void StartNetworkWatch()
    {
        // Enumerating the interfaces takes tens of milliseconds: off the UI thread, so it is not on the start-up path.
        _ = System.Threading.Tasks.Task.Run(() =>
        {
            try { var first = NetworkFingerprint(); DispatcherQueue.TryEnqueue(() => { if (_networkFingerprint.Length == 0) _networkFingerprint = first; }); }
            catch (NetworkInformationException) { /* the first settled change records it */ }
        });
        _networkTimer = DispatcherQueue.CreateTimer();
        _networkTimer.Interval = NetworkSettle;
        _networkTimer.IsRepeating = false;
        _networkTimer.Tick += (_, _) => OnNetworkSettled();
        NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
    }

    private void StopNetworkWatch()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        _networkTimer?.Stop();
    }

    /// <summary>Raised on a thread-pool thread: restart the settle timer on the UI thread.</summary>
    private static void Trace(string s) { if (TestHooks.NetTrace is { } p) System.IO.File.AppendAllText(p, System.DateTime.Now.ToString("HH:mm:ss.fff ") + s + "\n"); }
    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    { Trace("event"); DispatcherQueue.TryEnqueue(() => { _networkTimer?.Stop(); _networkTimer?.Start(); }); }

    private void OnNetworkSettled()
    {
        string now;
        try { now = NetworkFingerprint(); }
        catch (NetworkInformationException) { return; } // the interface list is changing again; the next event retries
        Trace("settled same=" + (now == _networkFingerprint) + " tabs=" + _tabs.Count + " links=" + _tabs.Count(t => t.Link is not null));
        if (now == _networkFingerprint) return;
        _networkFingerprint = now;
        foreach (var tab in _tabs) tab.Link?.NetworkChanged();
    }

    /// <summary>The up, non-loopback interfaces and their unicast addresses, sorted: equal strings mean the same path.</summary>
    private static string NetworkFingerprint() => string.Join("|", NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .SelectMany(n => n.GetIPProperties().UnicastAddresses
            .Where(a => a.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 && !a.Address.IsIPv6LinkLocal)
            .Select(a => n.Id + "=" + a.Address))
        .OrderBy(s => s, StringComparer.Ordinal));
}
