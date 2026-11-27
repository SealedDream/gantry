using System.Runtime.InteropServices.WindowsRuntime;
using Bastion.Shell.Interop;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.System;

namespace Bastion.Shell;

public enum RemoteButton { Left, Right, Middle, WheelUp, WheelDown }

/// <summary>What <see cref="RemoteDesktopView"/> needs from a protocol (RDP or VNC), as RemoteDesktop on macOS.</summary>
public interface IRemoteDesktop : IDisposable
{
    bool IsConnected { get; }
    string? CloseReason { get; }
    /// <summary>Copy the picture (BGRA, top-down) when it changed since <paramref name="serial"/>; grows the buffer as needed.</summary>
    bool Frame(ref byte[] buffer, ref ulong serial, out int width, out int height);
    void MouseMove(int x, int y);
    void MouseButton(RemoteButton button, bool down);
    /// <summary>A key went down or up. Returns true when the protocol sent it (the event is then handled).</summary>
    bool Key(VirtualKey key, uint scanCode, bool extended, bool down);
    /// <summary>A character was typed (after the keyboard layout). Returns true when the protocol sent it.</summary>
    bool Character(char c);
    /// <summary>Ask the server to resize its desktop to the view (device pixels). A server that refuses keeps its size.</summary>
    void Resize(int width, int height) { }
}

/// <summary>
/// A remote desktop in a tab: polls <see cref="IRemoteDesktop.Frame"/> into a WriteableBitmap and sends the pointer, wheel
/// and keys back. <see cref="DesktopFit"/> decides how the picture meets the tab (RDP-VNC-FIT, as Mac #1146): Fit to tab asks
/// the server to follow the tab's size (debounced) and scales whatever comes back; Fixed size shows it 1:1, centred; Scale
/// scales it, aspect kept. Any margin is the session area's own theme background, not black. When the server ends the session the reason is shown over the picture.
/// </summary>
public sealed partial class RemoteDesktopView : UserControl, IDisposable
{
    private readonly IRemoteDesktop _desktop;
    private readonly Image _image = new() { Stretch = Stretch.Uniform };
    private readonly DesktopFit _fit;
    private readonly DispatcherTimer _resizeTimer = new() { Interval = DesktopFitRules.ResizeSettle };
    private (int Width, int Height) _askedSize;

    /// <summary>The newest size (device pixels) a desktop tab settled at, for the size an RDP connect asks for.</summary>
    public static (int Width, int Height)? LastViewPixels { get; private set; }
    /// <summary>The fit this view was opened with.</summary>
    public DesktopFit Fit => _fit;
    private readonly TextBlock _status = new() { Margin = new Thickness(16), TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed, IsTextSelectionEnabled = true };
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(33) };
    private WriteableBitmap? _bitmap;
    private byte[] _buffer = new byte[1280 * 800 * 4];
    private ulong _serial;
    private int _width, _height;
    private bool _closed;
    private readonly RdpClipboard? _clipboard;

    /// <summary>Raised once when the server or network ends the session.</summary>
    public event EventHandler<string>? Closed;
    /// <summary>Connected and not closed: counts as a live session when the app quits (CLOSE-01).</summary>
    public bool IsLive => !_closed && _desktop.IsConnected;

    public RemoteDesktopView(IRemoteDesktop desktop, DesktopFit fit = DesktopFit.Fit)
    {
        _desktop = desktop;
        _fit = fit;
        if (fit == DesktopFit.Fixed) _image.Stretch = Stretch.Fill; // sized to 1:1 device pixels in Poll
        if (desktop is RdpDesktop rdp) _clipboard = new RdpClipboard(rdp.Session);
        IsTabStop = true;
        UseSystemFocusVisuals = false;
        // Transparent (still hit-testable): a margin left by a server that keeps its size shows the session area's theme
        // background, as other tabs do. Fixed size clips a desktop larger than the tab.
        Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent);
        var grid = new Grid { Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent), Children = { _image, _status } };
        SizeChanged += (_, _) => grid.Clip = new RectangleGeometry { Rect = new Windows.Foundation.Rect(0, 0, ActualWidth, ActualHeight) };
        Content = grid;
        SizeChanged += (_, _) => { _resizeTimer.Stop(); _resizeTimer.Start(); };
        _resizeTimer.Tick += (_, _) => { _resizeTimer.Stop(); Settled(); };
        _timer.Tick += (_, _) => Poll();
        Loaded += (_, _) => { _timer.Start(); Poll(); };
        Unloaded += (_, _) => { _timer.Stop(); _resizeTimer.Stop(); };
        PointerMoved += (_, e) => { if (Map(e) is { } p) _desktop.MouseMove(p.X, p.Y); };
        PointerPressed += (_, e) => { Focus(FocusState.Pointer); CapturePointer(e.Pointer); Button(e, true); };
        PointerReleased += (_, e) => { Button(e, false); ReleasePointerCapture(e.Pointer); };
        PointerWheelChanged += (_, e) =>
        {
            var delta = e.GetCurrentPoint(this).Properties.MouseWheelDelta;
            var b = delta > 0 ? RemoteButton.WheelUp : RemoteButton.WheelDown;
            _desktop.MouseButton(b, true);
            _desktop.MouseButton(b, false);
            e.Handled = true;
        };
        KeyDown += (_, e) => Key(e, true);
        KeyUp += (_, e) => Key(e, false);
        CharacterReceived += (_, e) => { if (_desktop.Character(e.Character)) e.Handled = true; };
        LostFocus += (_, _) => (_desktop as RdpDesktop)?.ReleaseAll();
    }

    private double RasterScale => XamlRoot?.RasterizationScale is > 0 and var s ? s : 1.0;

    /// <summary>The tab kept its size for <see cref="DesktopFitRules.ResizeSettle"/>: remember it and, for Fit to tab, ask
    /// the server to follow. RDP holds a size sent before Display Control opens and asks again after a reactivation.</summary>
    private void Settled()
    {
        if (_closed || ActualWidth < 1 || ActualHeight < 1) return;
        var size = DesktopFitRules.TabPixels(ActualWidth, ActualHeight, RasterScale);
        LastViewPixels = size;
        if (_fit != DesktopFit.Fit || size == _askedSize) return;
        _askedSize = size;
        _desktop.Resize(size.Width, size.Height);
        TestHooks.LogDesktopFit(_fit, size.Width, size.Height);
    }

    /// <summary>Fixed size: the picture at one desktop pixel per device pixel.</summary>
    private void SizeImage()
    {
        if (_fit != DesktopFit.Fixed || _width == 0) return;
        _image.Width = _width / RasterScale;
        _image.Height = _height / RasterScale;
    }

    /// <summary>The desktop size the server chose (0 before the first frame).</summary>
    public (int Width, int Height) DesktopSize => (_width, _height);

    /// <summary>A small copy of the picture on screen now, for tab previews (B11); null before the first frame. Reads the
    /// view's own buffer: previews never poll the protocol (RDP sends only what changed since the last read).</summary>
    internal (byte[] Pixels, int Width, int Height)? PreviewPixels() =>
        _width == 0 || _height == 0 ? null : TabPreviewRules.Downscale(_buffer, _width, _height);

    /// <summary>The protocol behind the view, for snapshot checks.</summary>
    internal IRemoteDesktop Desktop => _desktop;

    // Speed suite: first frame after Connect, then frames per second over 5 s windows, named by frame size.
    private const int FpsWindowMs = 5000;
    private long _fpsT0;
    private int _fpsFrames;

    private void MarkFrame(int w, int h)
    {
        PerfTrace.End("rdp-open", "rdp-first-frame");
        if (_fpsT0 == 0) _fpsT0 = PerfTrace.Now();
        _fpsFrames++;
        var ms = PerfTrace.Ms(_fpsT0);
        if (ms < FpsWindowMs) return;
        PerfTrace.Write($"rdp-fps-{w}x{h}", _fpsFrames * 1000.0 / ms, "fps");
        _fpsFrames = 0;
        _fpsT0 = PerfTrace.Now();
    }

    /// <summary>Copy a new frame, if any, and notice the end of the session.</summary>
    public void Poll()
    {
        _clipboard?.Poll();
        if (_desktop.Frame(ref _buffer, ref _serial, out var w, out var h) && w > 0 && h > 0)
        {
            if (_bitmap is null || w != _width || h != _height)
            {
                _width = w;
                _height = h;
                _bitmap = new WriteableBitmap(w, h);
                _image.Source = _bitmap;
                SizeImage();
            }
            using (var stream = _bitmap.PixelBuffer.AsStream()) stream.Write(_buffer, 0, w * h * 4);
            _bitmap.Invalidate();
            if (PerfTrace.Enabled) MarkFrame(w, h);
        }
        if (!_closed && !_desktop.IsConnected)
        {
            _closed = true;
            _timer.Stop();
            var reason = _desktop.CloseReason ?? "The session ended.";
            _status.Text = "Disconnected: " + reason;
            _status.Visibility = Visibility.Visible;
            Closed?.Invoke(this, reason);
        }
    }

    /// <summary>Pointer position in desktop pixels, for the fit's scale and centring; null outside the picture.</summary>
    private (int X, int Y)? Map(PointerRoutedEventArgs e)
    {
        if (_width == 0 || ActualWidth <= 0 || ActualHeight <= 0) return null;
        var pos = e.GetCurrentPoint(this).Position;
        return DesktopFitRules.ToDesktop(_fit, _width, _height, ActualWidth, ActualHeight, RasterScale, pos.X, pos.Y);
    }

    private void Button(PointerRoutedEventArgs e, bool down)
    {
        RemoteButton? button = e.GetCurrentPoint(this).Properties.PointerUpdateKind switch
        {
            PointerUpdateKind.LeftButtonPressed or PointerUpdateKind.LeftButtonReleased => RemoteButton.Left,
            PointerUpdateKind.RightButtonPressed or PointerUpdateKind.RightButtonReleased => RemoteButton.Right,
            PointerUpdateKind.MiddleButtonPressed or PointerUpdateKind.MiddleButtonReleased => RemoteButton.Middle,
            _ => null,
        };
        if (button is not { } b) return;
        if (Map(e) is { } p) _desktop.MouseMove(p.X, p.Y);
        _desktop.MouseButton(b, down);
        e.Handled = true;
    }

    private void Key(KeyRoutedEventArgs e, bool down)
    {
        // Handled keys never reach focus navigation, so Tab and the arrows belong to the remote desktop.
        if (_desktop.Key(e.Key, e.KeyStatus.ScanCode, e.KeyStatus.IsExtendedKey, down)) e.Handled = true;
    }

    public void Dispose()
    {
        _timer.Stop();
        _resizeTimer.Stop();
        _clipboard?.Dispose();
        _desktop.Dispose();
    }
}

/// <summary>
/// RDP keyboard (owner point 29, as Mac RdpKeyText): keys that type text go to the server as Unicode, so what arrives
/// does not depend on the server's layout or on modifier state ("." is always "."); every other key (modifiers, Return,
/// Tab, Space, Backspace, Escape, arrows, function keys) and any shortcut with Ctrl, Alt or Windows goes as the scancode.
/// AltGr (Ctrl+Alt) characters are text. When focus leaves the view every key still down on the server is released.
/// </summary>
public sealed partial class RdpDesktop(RdpSession session) : IRemoteDesktop
{
    private readonly HashSet<uint> _textKeysDown = [];
    // Modifiers are sent lazily (owner point 29): typed text arrives as Unicode, so sending every Shift press would show the
    // server bare Shift taps (five in a row turn on Sticky Keys). A modifier goes down on the server only before a key or
    // click that needs it, or as a tap when it was pressed and released alone (Win opens Start, Shift taps still count).
    private readonly Dictionary<(uint Scan, bool Ext), bool> _modsHeld = [];
    private readonly HashSet<(uint Scan, bool Ext)> _modsSent = [];
    private bool _modTappedAlone;
    private char _highSurrogate;

    public RdpSession Session => session;
    public bool IsConnected => session.IsConnected;
    public string? CloseReason => session.CloseReason;
    public bool Frame(ref byte[] buffer, ref ulong serial, out int width, out int height) => session.Frame(ref buffer, ref serial, out width, out height);
    public void MouseMove(int x, int y) => session.MouseMove(x, y);
    public void Resize(int width, int height) => session.Resize(width, height);

    public void MouseButton(RemoteButton button, bool down)
    {
        if (down) SyncModifiers();
        switch (button)
        {
            case RemoteButton.Left: session.MouseButton(0, down); break;
            case RemoteButton.Right: session.MouseButton(1, down); break;
            case RemoteButton.Middle: session.MouseButton(2, down); break;
            // The RDP library has no wheel input yet.
        }
    }

    private void SyncModifiers()
    {
        _modTappedAlone = false;
        foreach (var (key, held) in _modsHeld)
            if (held && _modsSent.Add(key)) session.Key((byte)key.Scan, key.Ext, true);
    }

    public bool Key(VirtualKey key, uint scanCode, bool extended, bool down)
    {
        // Injected keys (SendInput/keybd_event from automation or remote tools) may carry no scan code: derive it.
        if (scanCode == 0) (scanCode, extended) = RdpKeyText.ScanCodeOf(key, extended);
        if (scanCode is 0 or > 0xFF) return false;
        if (RdpKeyText.IsModifier(key))
        {
            var id = (scanCode, extended);
            if (down)
            {
                if (_modsHeld.GetValueOrDefault(id)) return true; // auto-repeat
                _modsHeld[id] = true;
                _modTappedAlone = true;
                return true;
            }
            _modsHeld.Remove(id);
            if (_modsSent.Remove(id)) session.Key((byte)scanCode, extended, false);
            else if (_modTappedAlone && _modsHeld.Count == 0) { session.Key((byte)scanCode, extended, true); session.Key((byte)scanCode, extended, false); }
            if (_modsHeld.Count == 0) _modTappedAlone = false;
            return true;
        }
        // A text key's down and up are not sent: the character it types arrives in Character. Return false (KeyDown not
        // handled): WinUI raises CharacterReceived only for a KeyDown left unhandled, so true here lost every typed
        // character (C4 job68: empty lines on the server).
        if (down && RdpKeyText.TypesText(key, RdpKeyText.CurrentModifiers())) { _textKeysDown.Add(scanCode); _modTappedAlone = false; return false; }
        if (!down && _textKeysDown.Remove(scanCode)) return false;
        if (down) SyncModifiers();
        session.Key((byte)scanCode, extended, down);
        return true;
    }

    public bool Character(char c)
    {
        if (char.IsHighSurrogate(c)) { _highSurrogate = c; return true; }
        var text = char.IsLowSurrogate(c) && _highSurrogate != 0 ? new string([_highSurrogate, c]) : c.ToString();
        _highSurrogate = '\0';
        if (!RdpKeyText.IsTypedText(text)) return false;
        _modTappedAlone = false;
        session.TypeText(text);
        return true;
    }

    public void ReleaseAll()
    {
        _textKeysDown.Clear();
        _modsHeld.Clear();
        _modsSent.Clear();
        _modTappedAlone = false;
        session.ReleaseAll();
    }

    public void Dispose() => session.Dispose();
}

/// <summary>Which keys go to the RDP server as typed text (pure, so the keyboard test can check every key and modifier).</summary>
public static class RdpKeyText
{
    [System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint = "MapVirtualKeyW")]
    private static extern uint MapVirtualKey(uint code, uint mapType);
    private const uint MapVkToVscEx = 4; // MAPVK_VK_TO_VSC_EX: 0xE0xx for extended keys

    /// <summary>The set-1 scan code of a virtual key, and whether it is an extended key; (0, false) when there is none.</summary>
    public static (uint ScanCode, bool Extended) ScanCodeOf(VirtualKey key, bool extended)
    {
        var sc = MapVirtualKey((uint)key, MapVkToVscEx);
        return (sc & 0xFF, extended || (sc & 0xFF00) is 0xE000 or 0xE100);
    }

    [Flags]
    public enum Modifiers { None = 0, Shift = 1, Control = 2, Alt = 4, Windows = 8 }

    /// <summary>True when <paramref name="key"/> types a character with these modifiers: letters, digits, punctuation and
    /// the keypad's digits and operators, with no shortcut modifier (Shift and AltGr = Ctrl+Alt still type).</summary>
    public static bool TypesText(VirtualKey key, Modifiers mods)
    {
        if (mods.HasFlag(Modifiers.Windows)) return false;
        var control = mods.HasFlag(Modifiers.Control);
        var alt = mods.HasFlag(Modifiers.Alt);
        if (control != alt) return false; // Ctrl+C, Alt+F4 … stay shortcuts; Ctrl+Alt is AltGr
        var vk = (int)key;
        return vk is >= 0x30 and <= 0x39 // 0–9
            or >= 0x41 and <= 0x5A // A–Z
            or >= 0x60 and <= 0x6F and not 0x6C // keypad 0–9, * + - . / (not the separator)
            or >= 0xBA and <= 0xC0 // ; = , - . / `
            or >= 0xDB and <= 0xDF // [ \ ] ' and OEM_8
            or 0xE2; // the UK/ISO key beside left Shift
    }

    /// <summary>Shift, Ctrl, Alt (either side) and the Windows keys.</summary>
    public static bool IsModifier(VirtualKey key) => (int)key is 0x10 or 0x11 or 0x12 or >= 0xA0 and <= 0xA5 or 0x5B or 0x5C;

    /// <summary>Printable text (not a control character, which its key already sent as a scancode; not Space, which stays a key).</summary>
    public static bool IsTypedText(string text) => text.Length > 0 && text != " " && !text.Any(char.IsControl);

    internal static Modifiers CurrentModifiers()
    {
        static bool Down(VirtualKey k) => Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(k).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down);
        return (Down(VirtualKey.Shift) ? Modifiers.Shift : 0) | (Down(VirtualKey.Control) ? Modifiers.Control : 0)
            | (Down(VirtualKey.Menu) ? Modifiers.Alt : 0) | (Down(VirtualKey.LeftWindows) || Down(VirtualKey.RightWindows) ? Modifiers.Windows : 0);
    }
}

/// <summary>
/// VNC sends X11 keysyms: special keys and modifiers from KeyDown/KeyUp, printable characters from CharacterReceived (so the
/// local layout decides the character, as on macOS). Control+letter arrives as a control character and is sent as the letter
/// while the Control keysym is held.
/// </summary>
public sealed partial class VncDesktop(VncSession session) : IRemoteDesktop
{
    private static readonly Dictionary<VirtualKey, uint> Special = new()
    {
        [VirtualKey.Enter] = 0xFF0D, [VirtualKey.Tab] = 0xFF09, [VirtualKey.Back] = 0xFF08, [VirtualKey.Escape] = 0xFF1B,
        [VirtualKey.Delete] = 0xFFFF, [VirtualKey.Insert] = 0xFF63, [VirtualKey.Home] = 0xFF50, [VirtualKey.End] = 0xFF57,
        [VirtualKey.PageUp] = 0xFF55, [VirtualKey.PageDown] = 0xFF56,
        [VirtualKey.Left] = 0xFF51, [VirtualKey.Up] = 0xFF52, [VirtualKey.Right] = 0xFF53, [VirtualKey.Down] = 0xFF54,
        [VirtualKey.F1] = 0xFFBE, [VirtualKey.F2] = 0xFFBF, [VirtualKey.F3] = 0xFFC0, [VirtualKey.F4] = 0xFFC1,
        [VirtualKey.F5] = 0xFFC2, [VirtualKey.F6] = 0xFFC3, [VirtualKey.F7] = 0xFFC4, [VirtualKey.F8] = 0xFFC5,
        [VirtualKey.F9] = 0xFFC6, [VirtualKey.F10] = 0xFFC7, [VirtualKey.F11] = 0xFFC8, [VirtualKey.F12] = 0xFFC9,
        [VirtualKey.Shift] = 0xFFE1, [VirtualKey.LeftShift] = 0xFFE1, [VirtualKey.RightShift] = 0xFFE2,
        [VirtualKey.Control] = 0xFFE3, [VirtualKey.LeftControl] = 0xFFE3, [VirtualKey.RightControl] = 0xFFE4,
        [VirtualKey.Menu] = 0xFFE9, [VirtualKey.LeftMenu] = 0xFFE9, [VirtualKey.RightMenu] = 0xFFEA,
        [VirtualKey.LeftWindows] = 0xFFEB, [VirtualKey.RightWindows] = 0xFFEC, [VirtualKey.CapitalLock] = 0xFFE5,
    };

    public bool IsConnected => !session.IsClosed;
    public string? CloseReason => session.CloseReason;
    public bool Frame(ref byte[] buffer, ref ulong serial, out int width, out int height) => session.Frame(ref buffer, ref serial, out width, out height);
    public void MouseMove(int x, int y) => session.MouseMove(x, y);
    /// <summary>ExtendedDesktopSize; the core retries until the server announces support, and a refusal keeps its size.</summary>
    public void Resize(int width, int height) => session.Resize(width, height);
    public void MouseButton(RemoteButton button, bool down) => session.MouseButton((byte)(button switch
    {
        RemoteButton.Left => 0, RemoteButton.Middle => 1, RemoteButton.Right => 2, RemoteButton.WheelUp => 3, _ => 4,
    }), down);

    public bool Key(VirtualKey key, uint scanCode, bool extended, bool down)
    {
        if (!Special.TryGetValue(key, out var sym)) return false;
        session.Key(sym, down);
        return true;
    }

    public bool Character(char c)
    {
        if (Keysym(c) is not { } sym) return false;
        session.Key(sym, true);
        session.Key(sym, false);
        return true;
    }

    /// <summary>Latin-1 maps to itself, other Unicode to the 0x01000000 plane; Control+letter (1–26) to the letter.</summary>
    public static uint? Keysym(char c) => c switch
    {
        '\r' or '\n' or '\t' or '\b' or (char)0x1B => null, // sent from KeyDown as special keys
        >= (char)1 and <= (char)26 => (uint)('a' + c - 1),
        >= ' ' and <= '~' or >= (char)0xA0 and <= (char)0xFF => c,
        >= (char)0x100 when !char.IsSurrogate(c) => 0x0100_0000u | c,
        _ => null,
    };

    public void Dispose() => session.Dispose();
}
