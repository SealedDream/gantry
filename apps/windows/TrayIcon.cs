using System.Runtime.InteropServices;

namespace Bastion.Shell;

/// <summary>
/// The notification-area icon, matching Bastion Tauri on Windows: the colour app icon, a left click brings the
/// window forward, the right-click menu has Show Bastion / Quit Bastion. Messages arrive through a subclass of the
/// main window, so no extra window or thread is created. Re-added when Explorer restarts (TaskbarCreated).
/// </summary>
internal sealed partial class TrayIcon : IDisposable
{
    private const uint CallbackMessage = 0x8000 + 0x42; // WM_APP + n
    private const uint WmLButtonUp = 0x0202, WmRButtonUp = 0x0205, WmContextMenu = 0x007B;
    private const uint NimAdd = 0, NimModify = 1, NimDelete = 2;
    private const uint NifInfo = 0x10, NiifInfo = 1;
    private const uint NifMessage = 1, NifIcon = 2, NifTip = 4;
    private const uint MfString = 0, MfSeparator = 0x800;
    private const uint TpmReturnCmd = 0x100, TpmRightButton = 2, TpmBottomAlign = 0x20;
    private const int CmdShow = 1, CmdQuit = 2;
    private const nuint SubclassId = 0x7472;

    internal const string ShowLabel = "Show Gantry";
    internal const string QuitLabel = "Quit Gantry";

    private readonly IntPtr _hwnd;
    private readonly Action _show;
    private readonly Action _quit;
    private readonly SubclassProc _proc; // kept alive for as long as the subclass is installed
    private readonly uint _taskbarCreated;
    private IntPtr _icon;
    private bool _added;

    internal TrayIcon(IntPtr hwnd, string iconPath, Action show, Action quit)
    {
        _hwnd = hwnd;
        _show = show;
        _quit = quit;
        _proc = WndProc;
        _taskbarCreated = RegisterWindowMessage("TaskbarCreated");
        _icon = LoadImage(IntPtr.Zero, iconPath, 1 /* IMAGE_ICON */, GetSystemMetrics(49), GetSystemMetrics(50), 0x10 /* LR_LOADFROMFILE */);
        if (!SetWindowSubclass(_hwnd, _proc, SubclassId, 0)) throw new InvalidOperationException("Tray: subclass failed");
        Add();
    }

    private void Add()
    {
        var data = Data(NifMessage | NifIcon | NifTip);
        data.uCallbackMessage = CallbackMessage;
        data.hIcon = _icon;
        data.szTip = "Gantry";
        _added = Shell_NotifyIcon(NimAdd, ref data);
    }

    /// <summary>A notification-area balloon (a toast on Windows 10/11). Text is cut to the shell's limits.</summary>
    public void Balloon(string title, string text)
    {
        if (!_added) return;
        var data = Data(NifInfo);
        data.szInfoTitle = title.Length > 63 ? title[..63] : title;
        data.szInfo = text.Length > 255 ? text[..255] : text;
        data.dwInfoFlags = NiifInfo;
        Shell_NotifyIcon(NimModify, ref data);
    }

    private NotifyIconData Data(uint flags) => new()
    {
        cbSize = (uint)Marshal.SizeOf<NotifyIconData>(),
        hWnd = _hwnd,
        uID = 1,
        uFlags = flags,
        szTip = "",
        szInfo = "",
        szInfoTitle = "",
    };

    private IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam, nuint id, nuint data)
    {
        if (msg == CallbackMessage)
        {
            var mouse = (uint)(lParam.ToInt64() & 0xFFFF);
            if (mouse == WmLButtonUp) _show();
            else if (mouse is WmRButtonUp or WmContextMenu) ShowMenu();
            return IntPtr.Zero;
        }
        if (msg == _taskbarCreated && _taskbarCreated != 0) Add();
        return DefSubclassProc(hwnd, msg, wParam, lParam);
    }

    private void ShowMenu()
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero) return;
        try
        {
            AppendMenu(menu, MfString, CmdShow, ShowLabel);
            AppendMenu(menu, MfSeparator, 0, null);
            AppendMenu(menu, MfString, CmdQuit, QuitLabel);
            GetCursorPos(out var pt);
            // Without this the menu does not close when the user clicks elsewhere (documented TrackPopupMenu quirk).
            SetForegroundWindow(_hwnd);
            var cmd = TrackPopupMenuEx(menu, TpmReturnCmd | TpmRightButton | TpmBottomAlign, pt.X, pt.Y, _hwnd, IntPtr.Zero);
            if (cmd == CmdShow) _show();
            else if (cmd == CmdQuit) _quit();
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    public void Dispose()
    {
        if (_added)
        {
            var data = Data(0);
            Shell_NotifyIcon(NimDelete, ref data);
            _added = false;
        }
        RemoveWindowSubclass(_hwnd, _proc, SubclassId);
        if (_icon != IntPtr.Zero) DestroyIcon(_icon);
        _icon = IntPtr.Zero;
    }

    private delegate IntPtr SubclassProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam, nuint id, nuint data);

    [StructLayout(LayoutKind.Sequential)]
    private struct Point { public int X, Y; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern bool Shell_NotifyIcon(uint message, ref NotifyIconData data);
    [DllImport("comctl32.dll")] private static extern bool SetWindowSubclass(IntPtr hwnd, SubclassProc proc, nuint id, nuint data);
    [DllImport("comctl32.dll")] private static extern bool RemoveWindowSubclass(IntPtr hwnd, SubclassProc proc, nuint id);
    [DllImport("comctl32.dll")] private static extern IntPtr DefSubclassProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterWindowMessage(string name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadImage(IntPtr instance, string name, uint type, int cx, int cy, uint flags);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] private static extern IntPtr CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool AppendMenu(IntPtr menu, uint flags, nuint id, string? item);
    [DllImport("user32.dll")] private static extern bool DestroyMenu(IntPtr menu);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Point point);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int TrackPopupMenuEx(IntPtr menu, uint flags, int x, int y, IntPtr hwnd, IntPtr tpm);
}
