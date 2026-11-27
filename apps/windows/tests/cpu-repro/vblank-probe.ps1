Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Diagnostics;
public static class VB {
  [DllImport("dwmapi.dll")] public static extern int DwmFlush();
  [StructLayout(LayoutKind.Sequential)] public struct OPENFROMHDC { public IntPtr hDc; public uint hAdapter; public long AdapterLuid; public uint VidPnSourceId; }
  [StructLayout(LayoutKind.Sequential)] public struct WAITVB { public uint hAdapter; public uint hDevice; public uint VidPnSourceId; }
  [DllImport("gdi32.dll")] public static extern int D3DKMTOpenAdapterFromHdc(ref OPENFROMHDC a);
  [DllImport("gdi32.dll")] public static extern int D3DKMTWaitForVerticalBlankEvent(ref WAITVB w);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  public static string Time(Func<int> f, int n) {
    var sw = Stopwatch.StartNew(); var t0 = Process.GetCurrentProcess().TotalProcessorTime; int bad = 0;
    for (int i = 0; i < n; i++) { if (f() != 0) bad++; }
    sw.Stop(); var cpu = (Process.GetCurrentProcess().TotalProcessorTime - t0).TotalMilliseconds;
    return string.Format("{0} calls: {1:F2} ms per call, CPU {2:F0} ms over {3:F0} ms wall, failures {4}", n, sw.Elapsed.TotalMilliseconds / n, cpu, sw.Elapsed.TotalMilliseconds, bad);
  }
}
"@
"DwmFlush (should block ~16.9 ms at 59 Hz): " + [VB]::Time({ [VB]::DwmFlush() }, 60)
$o = New-Object VB+OPENFROMHDC; $o.hDc = [VB]::GetDC([IntPtr]::Zero)
$rc = [VB]::D3DKMTOpenAdapterFromHdc([ref]$o)
"D3DKMTOpenAdapterFromHdc rc=0x{0:X} adapter={1} source={2}" -f $rc, $o.hAdapter, $o.VidPnSourceId
$w = New-Object VB+WAITVB; $w.hAdapter = $o.hAdapter; $w.VidPnSourceId = $o.VidPnSourceId
"D3DKMTWaitForVerticalBlankEvent (should block ~16.9 ms): " + [VB]::Time({ [VB]::D3DKMTWaitForVerticalBlankEvent([ref]$w) }, 60)
$rc2 = [VB]::D3DKMTWaitForVerticalBlankEvent([ref]$w)
"single wait NTSTATUS: 0x{0:X8}" -f $rc2
foreach ($src in 0..3) { $w.VidPnSourceId = $src; "source {0}: 0x{1:X8}" -f $src, [VB]::D3DKMTWaitForVerticalBlankEvent([ref]$w) }
