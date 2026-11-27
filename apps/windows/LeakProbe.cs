using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;

namespace Bastion.Shell;

/// <summary>
/// Memory soak only (test builds with BASTION_LEAK_PROBE set to a file path): what a closed tab leaves behind.
/// <see cref="TabClosed"/> schedules one report once the closes stop (<see cref="SettleMs"/>). The report is taken off the
/// UI thread: process private bytes, handles and managed heap before and after a full blocking GC with finalizers, the
/// tracked objects still alive (and how many of them were already disposed), the native sessions not yet freed, and
/// the process's handles by kernel object type. One line "LEAK ..." per report. In an owner build
/// <see cref="Enabled"/> is a constant false and every call returns at once.
/// </summary>
internal static partial class LeakProbe
{
#if BASTION_TEST_HOOKS
    private static readonly string? ReportPath = Environment.GetEnvironmentVariable("BASTION_LEAK_PROBE") is { Length: > 0 } p ? p : null;
    public static bool Enabled => ReportPath is not null;
#else
    private const string? ReportPath = null;
    public static bool Enabled => false;
#endif

    private const int SettleMs = 3000;
    private const double Mb = 1024.0 * 1024.0;

    private static readonly object Gate = new();
    private static readonly List<(WeakReference Ref, string Kind)> Tracked = new();
    private static readonly ConditionalWeakTable<object, object> DisposedObjects = new();
    private static readonly object DisposedMark = new();
    private static int _sessionsOpen;
    private static int _reportBusy;
    private static DispatcherQueueTimer? _settle;
    private static DispatcherQueue? _ui;

    /// <summary>Follow <paramref name="o"/> without keeping it alive.</summary>
    public static void Track(object o, string kind)
    {
        if (!Enabled) return;
        lock (Gate) Tracked.Add((new WeakReference(o), kind));
    }

    /// <summary><paramref name="o"/> was disposed: if a report still finds it alive, something holds a closed object.</summary>
    public static void MarkDisposed(object o)
    {
        if (!Enabled) return;
        DisposedObjects.AddOrUpdate(o, DisposedMark);
    }

    public static void SessionOpened() { if (Enabled) Interlocked.Increment(ref _sessionsOpen); }

    public static void SessionFreed() { if (Enabled) Interlocked.Decrement(ref _sessionsOpen); }

    /// <summary>A tab closed (UI thread): report once no tab has closed for <see cref="SettleMs"/>.</summary>
    public static void TabClosed(DispatcherQueue queue)
    {
        if (!Enabled) return;
        _ui ??= queue;
        if (_settle is null)
        {
            _settle = queue.CreateTimer();
            _settle.Interval = TimeSpan.FromMilliseconds(SettleMs);
            _settle.IsRepeating = false;
            _settle.Tick += (_, _) => StartReport();
        }
        _settle.Stop();
        _settle.Start();
    }

    private static void StartReport()
    {
        if (Interlocked.Exchange(ref _reportBusy, 1) == 1) return;
        // Off the UI thread: finalizers of UI objects may need it while the GC waits for them.
        _ = Task.Run(() =>
        {
            try { Append(Report()); }
            catch (Exception e) { Append("LEAK error " + e.GetType().Name + ": " + e.Message); }
            finally { Volatile.Write(ref _reportBusy, 0); }
        });
    }

    private static string Report()
    {
        var before = Sample();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        var after = Sample();
        return FormattableString.Invariant(
            $"LEAK before priv={before.Priv:0.0}MB handles={before.Handles} managed={before.Managed:0.0}MB | after-gc priv={after.Priv:0.0}MB handles={after.Handles} managed={after.Managed:0.0}MB | live {LiveCounts()} sessions-open={Volatile.Read(ref _sessionsOpen)} | native-live {NativeLiveOnUi(_ui)} | memory {NativeMemory.Summary()} | census {HeapCensus.Summary()} | handle-types {HandleTypes.Summary()}");
    }

    private static (double Priv, int Handles, double Managed) Sample()
    {
        using var self = Process.GetCurrentProcess();
        return (self.PrivateMemorySize64 / Mb, self.HandleCount, GC.GetTotalMemory(forceFullCollection: false) / Mb);
    }

    /// <summary>"Kind=alive/alive-and-disposed" per tracked kind; dead entries are dropped.</summary>
    private static string LiveCounts()
    {
        var counts = new SortedDictionary<string, (int Alive, int Disposed)>(StringComparer.Ordinal);
        lock (Gate)
        {
            Tracked.RemoveAll(t => !t.Ref.IsAlive);
            foreach (var (r, kind) in Tracked)
            {
                if (r.Target is not { } o) continue;
                var c = counts.GetValueOrDefault(kind);
                counts[kind] = (c.Alive + 1, c.Disposed + (DisposedObjects.TryGetValue(o, out _) ? 1 : 0));
            }
        }
        return counts.Count == 0 ? "none" : string.Join(' ', counts.Select(kv => $"{kv.Key}={kv.Value.Alive}/{kv.Value.Disposed}"));
    }

    private static void Append(string line)
    {
        if (ReportPath is not { } path) return;
        try { File.AppendAllText(path, $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}"); }
        catch (IOException) { /* a probe failure must not change what the app does */ }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>This process's handles counted by kernel object type (File, Event, Section, ...).</summary>
    private static class HandleTypes
    {
        private const int SystemExtendedHandleInformation = 0x40;
        private const int ObjectTypeInformation = 2;
        private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
        private const int HeaderBytes = 16; // NumberOfHandles, Reserved
        private const int EntryBytes = 40;  // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX on x64
        private const int PidOffset = 8, HandleOffset = 16, TypeOffset = 30;
        private const int MaxTries = 8;

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int needed);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryObject(IntPtr handle, int infoClass, IntPtr buffer, int length, out int needed);

        public static string Summary()
        {
            if (IntPtr.Size != 8) return "x64 only";
            var length = 1 << 22;
            for (var i = 0; i < MaxTries; i++)
            {
                var buffer = Marshal.AllocHGlobal(length);
                try
                {
                    var status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, length, out var needed);
                    if (status == 0) return Count(buffer);
                    if (status != StatusInfoLengthMismatch) return $"error 0x{status:x8}";
                    length = Math.Max(length * 2, needed + (1 << 16));
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            return "error: handle table kept growing";
        }

        private static string Count(IntPtr table)
        {
            var total = (long)Marshal.ReadIntPtr(table);
            var pid = (long)Environment.ProcessId;
            var byType = new Dictionary<ushort, (int Count, IntPtr Sample)>();
            for (long k = 0; k < total; k++)
            {
                var entry = IntPtr.Add(table, checked((int)(HeaderBytes + k * EntryBytes)));
                if ((long)Marshal.ReadIntPtr(entry, PidOffset) != pid) continue;
                var type = (ushort)Marshal.ReadInt16(entry, TypeOffset);
                var handle = Marshal.ReadIntPtr(entry, HandleOffset);
                byType[type] = byType.TryGetValue(type, out var c) ? (c.Count + 1, c.Sample) : (1, handle);
            }
            return string.Join(',', byType
                .Select(kv => (Name: TypeName(kv.Value.Sample, kv.Key), kv.Value.Count))
                .OrderByDescending(t => t.Count)
                .Select(t => $"{t.Name}:{t.Count}"));
        }

        /// <summary>The type name of one handle (ObjectTypeInformation never blocks, unlike a name query on a pipe).</summary>
        private static string TypeName(IntPtr handle, ushort index)
        {
            const int size = 1024;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (NtQueryObject(handle, ObjectTypeInformation, buffer, size, out _) != 0) return $"type{index}";
                var bytes = (ushort)Marshal.ReadInt16(buffer); // UNICODE_STRING.Length
                var text = Marshal.ReadIntPtr(buffer, 8);       // UNICODE_STRING.Buffer
                return text == IntPtr.Zero ? $"type{index}" : Marshal.PtrToStringUni(text, bytes / 2);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
