using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// Cisco's OpenH264 binary, fetched on first RDP use so Cisco (not Bastion) distributes the H.264 code and pays its
/// licence (as OpenH264.swift on the Mac). bastion_rdp downloads it into <c>codecs\</c> and checks its SHA-256 against
/// Cisco's release list; anything that fails just leaves RDP on its non-H.264 codecs.
/// </summary>
internal static class OpenH264
{
    /// <summary>Cisco's file name for this version and architecture (matches rdp-ffi/src/openh264.rs).</summary>
    private static string FileName => RuntimeInformation.ProcessArchitecture == Architecture.Arm64
        ? "openh264-2.6.0-win-arm64.dll"
        : "openh264-2.6.0-win64.dll";

    private static bool _attempted;

    /// <summary>
    /// Hands bastion_rdp the library if it is on disk. If not, starts one background download per launch and never
    /// delays the connect: H.264 takes effect from the next session. Call on the UI thread.
    /// </summary>
    internal static void Prepare(string dataDir)
    {
        if (_attempted) return;
        _attempted = true;
        var codecs = Path.Combine(dataDir, "codecs");
        // Already downloaded: set it now so this connect offers H.264 (bastion_rdp re-checks the hash on load).
        if (File.Exists(Path.Combine(codecs, FileName)))
        {
            Install(codecs);
            return;
        }
        // Offline mode (the same switch as the core and bastion_rdp): never contact Cisco; RDP uses its other codecs,
        // as when the server cannot be reached.
        if (Offline.IsOn)
        {
            Debug.WriteLine("offline: OpenH264 is not downloaded");
            return;
        }
        Task.Run(() => Install(codecs));
    }

    private static void Install(string codecs)
    {
        try
        {
            var path = RdpNative.TakeString(RdpNative.bastion_rdp_install_openh264(codecs, out var err));
            if (path is null)
            {
                Debug.WriteLine($"OpenH264 unavailable, RDP uses non-H.264 codecs: {RdpNative.TakeString(err)}");
                return;
            }
            RdpNative.bastion_rdp_set_openh264_library_path(path);
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            Debug.WriteLine($"OpenH264 unavailable, RDP uses non-H.264 codecs: {e.Message}");
        }
    }
}
