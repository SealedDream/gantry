using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Bastion.Shell;

/// <summary>
/// WIN-COLD: right after a reboot nothing of the app is in the file cache, and start-up reads about 100 MB of the app and
/// WinUI files as thousands of small page-fault reads (profile of 2026-11-15: 1,500 to 3,200 reads, 1.2 to 3.4 s of
/// summed read time before the tree paints). A few large sequential reads are much cheaper than that on any disk, so this
/// reads the biggest of those files once, in the order start-up needs them, on a low-priority worker thread that starts
/// when the app assembly loads (before <c>Main</c> and the App constructor). It only reads files from the app's own
/// folder and discards the bytes: nothing is opened, parsed or written, nothing is loaded into the process, and every
/// failure (file missing, locked, folder unreadable) is ignored because the normal start-up then simply reads them itself.
/// When the files are already cached (a warm start) the pass is a quick memory-speed copy on an idle core.
/// </summary>
internal static class ColdPrefetch
{
    /// <summary>The start-up files by the order the profile showed them being needed; names only, always the app folder.</summary>
    internal static readonly string[] Files =
    [
        "Microsoft.ui.xaml.dll",
        "Microsoft.WinUI.dll",
        "bastion_cabi.dll",
        "Microsoft.UI.Xaml.Controls.dll",
        "dwmcorei.dll",
        "dcompi.dll",
        "Microsoft.InteractiveExperiences.Projection.dll",
        "Microsoft.DirectManipulation.dll",
        "OneCoreUAPCommonProxyStub.dll",
    ];

    private const int ChunkBytes = 1024 * 1024;

    /// <summary>The core DLL whose on-access scan <see cref="WarmCoreImage"/> moves off the library open.</summary>
    internal const string CoreDll = "bastion_cabi.dll";
    private const uint PageReadonly = 0x02;
    private const uint SecImage = 0x1000000;

    // Blittable arguments only (AOT): the file handle is passed raw while the SafeFileHandle keeps it open.
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr attributes, uint protect, uint maxHigh, uint maxLow, IntPtr name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

#pragma warning disable CA2255 // the point is to run before any other app code
    [ModuleInitializer]
    internal static void Start()
#pragma warning restore CA2255
    {
        try
        {
            var dir = AppContext.BaseDirectory;
            if (!TestHooks.ColdPrefetchOff)
                new Thread(() => ReadAll(dir)) { IsBackground = true, Name = "cold-prefetch", Priority = ThreadPriority.BelowNormal }.Start();
            if (!TestHooks.ColdPrescanOff)
                new Thread(() => WarmCoreImage(Path.Combine(dir, CoreDll))) { IsBackground = true, Name = "core-image-scan" }.Start();
        }
        catch (Exception e) when (e is ThreadStartException or OutOfMemoryException or InvalidOperationException)
        {
            Debug.WriteLine("Gantry: cold prefetch not started: " + e.Message);
        }
    }

    internal static void ReadAll(string dir, IReadOnlyList<string>? files = null)
    {
        var buffer = new byte[ChunkBytes];
        foreach (var name in files ?? Files)
        {
            try
            {
                var options = new FileStreamOptions
                {
                    Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.ReadWrite | FileShare.Delete,
                    Options = FileOptions.SequentialScan, BufferSize = 0,
                };
                using var stream = new FileStream(Path.Combine(dir, name), options);
                while (stream.Read(buffer, 0, buffer.Length) > 0) { }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Debug.WriteLine("Gantry: cold prefetch skipped " + name + ": " + e.Message);
            }
        }
    }

    /// <summary>
    /// WIN-COLD-START round 3: on a first launch the antivirus scans the core DLL when an image section is created for it
    /// (the speed VM: MsMpEng 0.6-1 s of CPU while the UI thread waited at the library open). Plain reads (above) do not
    /// count as that scan. Inside <c>LoadLibrary</c> the scan runs under the loader lock, which is why loading the DLL on a
    /// worker made the UI thread wait (#1247). This creates the same image section without the loader: nothing is mapped,
    /// loaded or run, and the section is closed at once. The verdict stays with the file, so the library open's load finds
    /// it scanned. A failure changes nothing: the library open loads the DLL and reports errors as before.
    /// </summary>
    internal static void WarmCoreImage(string path)
    {
        try
        {
            using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            var section = CreateFileMappingW(file.DangerousGetHandle(), IntPtr.Zero, PageReadonly | SecImage, 0, 0, IntPtr.Zero);
            if (section == IntPtr.Zero)
            {
                Debug.WriteLine($"Gantry: core image scan skipped: CreateFileMapping error {Marshal.GetLastWin32Error()}");
                return;
            }
            CloseHandle(section);
            StartupProbe.Mark("core-scanned");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            Debug.WriteLine("Gantry: core image scan skipped: " + e.Message);
        }
    }
}
