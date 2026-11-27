using System.Diagnostics;
using System.Runtime.InteropServices;
using Bastion.Shell.Interop;
using Microsoft.UI.Dispatching;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

/// <summary>
/// Text clipboard sharing for one RDP session (as Mac <c>RdpView.syncClipboard</c>): text copied on this computer is
/// offered to the server, text copied on the server goes onto the Windows clipboard. Content marked as excluded from
/// clipboard monitoring (password managers) is never offered, nor is text another session's server put there
/// (<see cref="RdpClipboardOrigin"/>, SEC-6). Nothing is read when the connection does not share it.
/// </summary>
internal sealed partial class RdpClipboard : IDisposable
{
    /// <summary>The format password managers add to keep a copy out of clipboard history and monitors.</summary>
    private const string ExcludedFormat = "ExcludeClipboardContentFromMonitorProcessing";

    private readonly RdpSession _session;
    private readonly DispatcherQueue _queue;
    private string? _fromServer;
    private bool _disposed;
    // Win32 clipboard sequence number last offered. ContentChanged does not fire for a copy made while this app is not
    // in front (the copy is then never offered), so each frame poll also compares this cheap counter (as Mac changeCount).
    private uint _seen;
    private bool _offering;

    [DllImport("user32.dll")] private static extern uint GetClipboardSequenceNumber();

    /// <summary>Create on the UI thread; offers what is on the clipboard now.</summary>
    public RdpClipboard(RdpSession session)
    {
        _session = session;
        _queue = DispatcherQueue.GetForCurrentThread();
        if (!session.SharesClipboard) return;
        Clipboard.ContentChanged += OnChanged;
        _seen = GetClipboardSequenceNumber();
        _ = OfferAsync();
    }

    // ContentChanged may arrive on another thread; the clipboard is read on the UI thread.
    private void OnChanged(object? sender, object e) => _queue.TryEnqueue(() => _ = OfferAsync());

    /// <summary>UI thread, every frame poll: text copied on the server goes onto the Windows clipboard.</summary>
    public void Poll()
    {
        if (_disposed) return;
        if (_session.SharesClipboard && !_offering && GetClipboardSequenceNumber() is var seq && seq != _seen)
        {
            _seen = seq;
            _ = OfferAsync();
        }
        var text = _session.TakeRemoteClipboard();
        if (text is null) return;
        _fromServer = text;
        var data = new DataPackage();
        data.SetText(text);
        try
        {
            Clipboard.SetContent(data);
            RdpClipboardOrigin.MarkRemoteWrite(this, GetClipboardSequenceNumber());
        }
        catch (Exception ex) { Debug.WriteLine($"RDP clipboard: could not set the Windows clipboard: {ex.Message}"); }
    }

    private async Task OfferAsync()
    {
        if (_disposed) return;
        _offering = true;
        try
        {
            _seen = GetClipboardSequenceNumber();
            // Another session's server text is never offered to this server (SEC-6).
            if (!RdpClipboardOrigin.MayOffer(this, _seen)) return;
            var content = Clipboard.GetContent();
            if (!content.Contains(StandardDataFormats.Text) || content.Contains(ExcludedFormat)) return;
            var text = await content.GetTextAsync();
            // What the server just copied is not echoed back to it.
            if (_disposed || string.IsNullOrEmpty(text) || text == _fromServer) return;
            _session.SetLocalClipboard(text);
        }
        catch (Exception ex)
        {
            // Another program holds the clipboard open; the next change offers again.
            Debug.WriteLine($"RDP clipboard: could not read the Windows clipboard: {ex.Message}");
        }
        finally { _offering = false; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        RdpClipboardOrigin.Forget(this);
        if (_session.SharesClipboard) Clipboard.ContentChanged -= OnChanged;
    }
}
