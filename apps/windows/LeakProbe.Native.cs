using System.Runtime.InteropServices;
using System.Text;
using Microsoft.UI.Dispatching;

namespace Bastion.Shell;

/// <summary>
/// The native half of the leak probe (WIN-SHELL-LEAK, test builds only): where the process's memory lives, which
/// WinRT objects of closed tabs are still alive natively after their managed wrappers are gone, and (with
/// BASTION_LEAK_CENSUS=1) which block sizes grow in the process heaps.
/// </summary>
internal static partial class LeakProbe
{
    private static readonly List<(IntPtr Weak, string Kind)> NativeTracked = new();

#if BASTION_TEST_HOOKS
    private static readonly bool CensusOn = Environment.GetEnvironmentVariable("BASTION_LEAK_CENSUS") == "1";
#else
    private const bool CensusOn = false;
#endif

    /// <summary>
    /// Follow the native object behind the WinRT wrapper <paramref name="o"/> through a COM weak reference: the report
    /// counts how many are still alive natively once the managed side has let go (UI thread).
    /// </summary>
    public static void TrackNative(object? o, string kind)
    {
        if (!Enabled || o is not WinRT.IWinRTObject w) return;
        var weak = NativeRefs.Weak(w.NativeObject.ThisPtr);
        if (weak == IntPtr.Zero) return;
        lock (Gate) NativeTracked.Add((weak, kind));
    }

    /// <summary>Tracked objects already freed natively, per kind (their weak references are released).</summary>
    private static readonly Dictionary<string, int> NativeFreed = new(StringComparer.Ordinal);

    /// <summary>
    /// "Kind=alive/tracked" per kind (UI thread: XAML and text-services objects belong to it). Freed objects' weak
    /// references are released, so the probe keeps nothing per closed tab itself.
    /// </summary>
    private static string NativeLiveCounts()
    {
        var counts = new SortedDictionary<string, (int Alive, int Total)>(StringComparer.Ordinal);
        lock (Gate)
        {
            for (var i = NativeTracked.Count - 1; i >= 0; i--)
            {
                var (weak, kind) = NativeTracked[i];
                if (NativeRefs.Alive(weak)) continue;
                NativeRefs.ReleaseRef(weak);
                NativeTracked.RemoveAt(i);
                NativeFreed[kind] = NativeFreed.GetValueOrDefault(kind) + 1;
            }
            foreach (var (_, kind) in NativeTracked)
            {
                var c = counts.GetValueOrDefault(kind);
                counts[kind] = (c.Alive + 1, c.Total + 1);
            }
            foreach (var (kind, freed) in NativeFreed)
            {
                var c = counts.GetValueOrDefault(kind);
                counts[kind] = (c.Alive, c.Total + freed);
            }
        }
        return counts.Count == 0 ? "none" : string.Join(' ', counts.Select(kv => $"{kv.Key}={kv.Value.Alive}/{kv.Value.Total}"));
    }

    /// <summary>Run <see cref="NativeLiveCounts"/> on the UI thread from the report's thread (at most 5 s).</summary>
    private static string NativeLiveOnUi(DispatcherQueue? ui)
    {
        if (ui is null) return "no-ui";
        var done = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!ui.TryEnqueue(() =>
        {
            try { done.TrySetResult(NativeLiveCounts()); }
            catch (Exception e) { done.TrySetResult("error " + e.GetType().Name); }
        })) return "ui-gone";
        return done.Task.Wait(TimeSpan.FromSeconds(5)) ? done.Task.Result : "ui-busy";
    }

    /// <summary>COM weak references (IWeakReferenceSource / IWeakReference), called through their vtables.</summary>
    private static unsafe class NativeRefs
    {
        private static readonly Guid IidWeakSource = new("00000038-0000-0000-C000-000000000046");
        private static readonly Guid IidInspectable = new("AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90");

        public static IntPtr Weak(IntPtr unknown)
        {
            if (unknown == IntPtr.Zero) return IntPtr.Zero;
            var iid = IidWeakSource;
            IntPtr source;
            var qi = (delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)(*(IntPtr**)unknown)[0];
            if (qi(unknown, &iid, &source) < 0 || source == IntPtr.Zero) return IntPtr.Zero;
            try
            {
                IntPtr weak;
                var get = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)(*(IntPtr**)source)[3];
                return get(source, &weak) < 0 ? IntPtr.Zero : weak;
            }
            finally { Release(source); }
        }

        public static bool Alive(IntPtr weak)
        {
            var iid = IidInspectable;
            IntPtr obj;
            var resolve = (delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)(*(IntPtr**)weak)[3];
            if (resolve(weak, &iid, &obj) < 0 || obj == IntPtr.Zero) return false;
            Release(obj);
            return true;
        }

        public static void ReleaseRef(IntPtr weak) => Release(weak);

        private static void Release(IntPtr p) => ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(IntPtr**)p)[2])(p);
    }

    /// <summary>
    /// Where the process's memory lives, after the GC: the process heaps (HeapAlloc: Rust, C and XAML objects), the GC
    /// heap, and the address space by region type (private, mapped, image). Private memory outside the heaps and the GC
    /// is VirtualAlloc made directly (graphics and composition surfaces, thread stacks). The three largest heaps are
    /// listed by index with their allocated and committed bytes (allocated/committed), so a growing one can be told apart.
    /// </summary>
    private static class NativeMemory
    {
        private const uint MemCommit = 0x1000, MemPrivate = 0x20000, MemMapped = 0x40000, MemImage = 0x1000000;
        private const int MaxHeaps = 256;

        [StructLayout(LayoutKind.Sequential)]
        private struct HeapSummaryData
        {
            public uint Cb;
            public nuint Allocated, Committed, Reserved, MaxReserve;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryBasicInformation
        {
            public IntPtr BaseAddress, AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public nuint RegionSize;
            public uint State, Protect, Type;
        }

        [DllImport("kernel32.dll")]
        private static extern uint GetProcessHeaps(uint count, IntPtr[] heaps);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcessHeap();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool HeapSummary(IntPtr heap, uint flags, ref HeapSummaryData summary);

        [DllImport("kernel32.dll")]
        private static extern nuint VirtualQuery(IntPtr address, out MemoryBasicInformation info, nuint length);

        public static IntPtr[] Heaps()
        {
            var heaps = new IntPtr[MaxHeaps];
            var n = (int)Math.Min(GetProcessHeaps(MaxHeaps, heaps), MaxHeaps);
            return heaps[..n];
        }

        /// <summary>Bytes allocated in all process heaps.</summary>
        public static long HeapAllocated()
        {
            long total = 0;
            foreach (var heap in Heaps())
            {
                var sum = new HeapSummaryData { Cb = (uint)Marshal.SizeOf<HeapSummaryData>() };
                if (HeapSummary(heap, 0, ref sum)) total += (long)sum.Allocated;
            }
            return total;
        }

        public static string Summary()
        {
            try
            {
                var heaps = Heaps();
                var main = GetProcessHeap();
                double heapCommitted = 0, heapAllocated = 0;
                var each = new List<(int Index, bool Main, double Allocated, double Committed)>();
                for (var i = 0; i < heaps.Length; i++)
                {
                    var sum = new HeapSummaryData { Cb = (uint)Marshal.SizeOf<HeapSummaryData>() };
                    if (!HeapSummary(heaps[i], 0, ref sum)) continue;
                    heapCommitted += sum.Committed;
                    heapAllocated += sum.Allocated;
                    each.Add((i, heaps[i] == main, sum.Allocated, sum.Committed));
                }
                double privateCommit = 0, mapped = 0, image = 0;
                var size = (nuint)Marshal.SizeOf<MemoryBasicInformation>();
                for (long address = 0; VirtualQuery((IntPtr)address, out var info, size) != 0; address = (long)info.BaseAddress + (long)info.RegionSize)
                {
                    if (info.RegionSize == 0) break;
                    if (info.State != MemCommit) continue;
                    if (info.Type == MemPrivate) privateCommit += info.RegionSize;
                    else if (info.Type == MemMapped) mapped += info.RegionSize;
                    else if (info.Type == MemImage) image += info.RegionSize;
                }
                var gc = GC.GetGCMemoryInfo().TotalCommittedBytes;
                var top = string.Join(',', each.OrderByDescending(h => h.Allocated).Take(3)
                    .Select(h => FormattableString.Invariant($"h{h.Index}{(h.Main ? "*" : "")}:{h.Allocated / Mb:0.0}/{h.Committed / Mb:0.0}")));
                return FormattableString.Invariant(
                    $"heaps={heaps.Length} heap-committed={heapCommitted / Mb:0.0}MB heap-allocated={heapAllocated / Mb:0.0}MB top-heaps={top} gc-committed={gc / Mb:0.0}MB private-commit={privateCommit / Mb:0.0}MB other-private={(privateCommit - heapCommitted - gc) / Mb:0.0}MB mapped={mapped / Mb:0.0}MB image={image / Mb:0.0}MB");
            }
            catch (Exception e) when (e is EntryPointNotFoundException or DllNotFoundException or ArgumentException)
            {
                return "error: " + e.GetType().Name;
            }
        }
    }

#if BASTION_TEST_HOOKS
    /// <summary>
    /// The loaded modules' address ranges, sorted, so a pointer can be named "module+rva": the first field of a C++
    /// object is its vtable, which tells which DLL made the object. Find runs inside a heap walk, so it never allocates.
    /// </summary>
    internal sealed unsafe class ModuleMap
    {
        private const int MaxModules = 1024, NameChars = 260;
        private readonly ulong[] _start, _end;
        private readonly string[] _name;

        [StructLayout(LayoutKind.Sequential)]
        private struct ModuleInfo
        {
            public IntPtr Base;
            public uint Size;
            public IntPtr Entry;
        }

        [DllImport("kernel32.dll", EntryPoint = "K32EnumProcessModules")]
        private static extern bool EnumProcessModules(IntPtr process, IntPtr* modules, uint bytes, out uint needed);

        [DllImport("kernel32.dll", EntryPoint = "K32GetModuleInformation")]
        private static extern bool GetModuleInformation(IntPtr process, IntPtr module, out ModuleInfo info, uint bytes);

        [DllImport("kernel32.dll", EntryPoint = "K32GetModuleBaseNameW")]
        private static extern uint GetModuleBaseName(IntPtr process, IntPtr module, char* name, uint chars);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        private ModuleMap(List<(ulong Start, ulong End, string Name)> list)
        {
            list.Sort((a, b) => a.Start.CompareTo(b.Start));
            _start = list.Select(m => m.Start).ToArray();
            _end = list.Select(m => m.End).ToArray();
            _name = list.Select(m => m.Name).ToArray();
        }

        public int Count => _name.Length;

        public string Name(int index) => _name[index];

        public static ModuleMap Snapshot()
        {
            var process = GetCurrentProcess();
            var handles = new IntPtr[MaxModules];
            var list = new List<(ulong, ulong, string)>();
            uint needed;
            fixed (IntPtr* p = handles)
                if (!EnumProcessModules(process, p, (uint)(handles.Length * IntPtr.Size), out needed)) return new ModuleMap(list);
            var n = (int)Math.Min(needed / (uint)IntPtr.Size, MaxModules);
            var buffer = new char[NameChars];
            for (var i = 0; i < n; i++)
            {
                if (!GetModuleInformation(process, handles[i], out var info, (uint)sizeof(ModuleInfo))) continue;
                uint length;
                fixed (char* b = buffer) length = GetModuleBaseName(process, handles[i], b, NameChars);
                var name = new string(buffer, 0, (int)length).ToLowerInvariant();
                if (name.EndsWith(".dll", StringComparison.Ordinal)) name = name[..^4];
                list.Add(((ulong)info.Base, (ulong)info.Base + info.Size, name));
            }
            return new ModuleMap(list);
        }

        /// <summary>The module that holds <paramref name="address"/>, or -1. No allocation.</summary>
        public int Find(ulong address)
        {
            int lo = 0, hi = _start.Length - 1;
            while (lo <= hi)
            {
                var mid = (lo + hi) / 2;
                if (address < _start[mid]) hi = mid - 1;
                else if (address >= _end[mid]) lo = mid + 1;
                else return mid;
            }
            return -1;
        }

        /// <summary>"module+RVA" when <paramref name="value"/> points into a module, else the value in hex.</summary>
        public string Describe(ulong value)
        {
            var m = Find(value);
            return m < 0 ? value.ToString("X", System.Globalization.CultureInfo.InvariantCulture)
                : FormattableString.Invariant($"{_name[m]}+{value - _start[m]:X}");
        }
    }

    /// <summary>
    /// BASTION_LEAK_CENSUS=1: busy blocks of every process heap by heap and size class (HeapWalk under HeapLock),
    /// compared with the first report. Lists the classes that grew most; the blocks counted by the module their first
    /// field points into ("typed": a C++ object's vtable names the DLL that made it); and for the top classes a few
    /// blocks' first fields with module names, and which blocks still point to one of them (its holders).
    /// </summary>
    private static class HeapCensus
    {
        private const ushort EntryBusy = 0x0004;
        private const int TopClasses = 8, TopModules = 6, SampleClasses = 4, SamplesPerClass = 2, SampleQwords = 8;
        private const int MaxHolders = 3, MaxClasses = 16384;
        private const int HeapShift = 40;
        private const long ClassMask = (1L << HeapShift) - 1;
        /// <summary>GC heap the whole process may allocate while a walk holds a heap lock.</summary>
        private const long NoGcBudget = 16L << 20;
        private static Dictionary<long, (long Count, long Bytes)>? _first;
        private static Dictionary<string, (long Count, long Bytes)>? _firstTyped;

        [StructLayout(LayoutKind.Explicit, Size = 40)]
        private struct ProcessHeapEntry
        {
            [FieldOffset(0)] public IntPtr Data;
            [FieldOffset(8)] public uint Size;
            [FieldOffset(14)] public ushort Flags;
        }

        /// <summary>
        /// HeapLock, HeapUnlock and HeapWalk bound once from kernel32 before any heap is locked: a P/Invoke bound lazily
        /// on its first call would take the loader lock while holding a heap lock (deadlock against a thread that holds
        /// the loader lock and allocates).
        /// </summary>
        private static unsafe class HeapApi
        {
            private static readonly IntPtr Kernel32 = NativeLibrary.Load("kernel32.dll");
            public static readonly delegate* unmanaged[Stdcall]<IntPtr, int> Lock =
                (delegate* unmanaged[Stdcall]<IntPtr, int>)NativeLibrary.GetExport(Kernel32, "HeapLock");
            public static readonly delegate* unmanaged[Stdcall]<IntPtr, int> Unlock =
                (delegate* unmanaged[Stdcall]<IntPtr, int>)NativeLibrary.GetExport(Kernel32, "HeapUnlock");
            public static readonly delegate* unmanaged[Stdcall]<IntPtr, ProcessHeapEntry*, int> Next =
                (delegate* unmanaged[Stdcall]<IntPtr, ProcessHeapEntry*, int>)NativeLibrary.GetExport(Kernel32, "HeapWalk");
        }

        /// <summary>A stable number per heap handle (the order of GetProcessHeaps can change between reports).</summary>
        private static readonly Dictionary<IntPtr, int> HeapIds = new();

        private static long SizeClass(uint size) => size <= 1024 ? (size + 15L) / 16 * 16 : (size + 1023L) / 1024 * 1024;

        private static long Key(int heap, uint size) => ((long)heap << HeapShift) | SizeClass(size);

        private static string KeyText(long key) => FormattableString.Invariant($"h{key >> HeapShift}:{key & ClassMask}B");

        /// <summary>
        /// Walk every busy block of every heap once; <paramref name="visit"/> sees the heap's id, the block's address
        /// and size. It runs under the heap's lock, so it must not allocate from the GC heap, and the walk runs in a no-GC
        /// region where the runtime grants one: a collection started by any thread would park this one while it holds the
        /// lock.
        /// </summary>
        private static unsafe void Walk(Action<int, IntPtr, uint> visit)
        {
            var heaps = NativeMemory.Heaps();
            var ids = new int[heaps.Length];
            lock (HeapIds) // the report and the drill may walk at the same time
                for (var h = 0; h < heaps.Length; h++)
                    if (!HeapIds.TryGetValue(heaps[h], out ids[h])) HeapIds[heaps[h]] = ids[h] = HeapIds.Count;
            var noGc = false;
            try { noGc = GC.TryStartNoGCRegion(NoGcBudget); }
            catch (Exception e) when (e is InvalidOperationException or ArgumentOutOfRangeException) { /* walk anyway */ }
            try
            {
                for (var h = 0; h < heaps.Length; h++)
                {
                    if (HeapApi.Lock(heaps[h]) == 0) continue;
                    try
                    {
                        var e = new ProcessHeapEntry();
                        while (HeapApi.Next(heaps[h], &e) != 0)
                            if ((e.Flags & EntryBusy) != 0) visit(ids[h], e.Data, e.Size);
                    }
                    finally { HeapApi.Unlock(heaps[h]); }
                }
            }
            finally
            {
                if (noGc && System.Runtime.GCSettings.LatencyMode == System.Runtime.GCLatencyMode.NoGCRegion) GC.EndNoGCRegion();
            }
        }

        /// <summary>Blocks whose first field points into each module (their vtable), with their bytes, by module name.</summary>
        public static Dictionary<string, (long Count, long Bytes)> Typed(ModuleMap modules, Dictionary<long, (long Count, long Bytes)>? classes)
        {
            var count = new long[modules.Count];
            var bytes = new long[modules.Count];
            var overflow = 0L;
            Walk((heap, data, size) =>
            {
                if (classes is not null)
                {
                    var k = Key(heap, size);
                    if (!classes.ContainsKey(k) && classes.Count >= MaxClasses) overflow++;
                    else
                    {
                        var c = classes.GetValueOrDefault(k);
                        classes[k] = (c.Count + 1, c.Bytes + size);
                    }
                }
                if (size < 8) return;
                var m = modules.Find((ulong)Marshal.ReadInt64(data));
                if (m < 0) return;
                count[m]++;
                bytes[m] += size;
            });
            var typed = new Dictionary<string, (long Count, long Bytes)>(StringComparer.Ordinal);
            for (var i = 0; i < modules.Count; i++)
            {
                if (count[i] == 0) continue;
                var t = typed.GetValueOrDefault(modules.Name(i));
                typed[modules.Name(i)] = (t.Count + count[i], t.Bytes + bytes[i]);
            }
            if (overflow > 0) typed["(classes-overflow)"] = (overflow, 0);
            return typed;
        }

        /// <summary>"module:+count/+KB" for the modules whose typed blocks grew most since <paramref name="first"/>.</summary>
        public static string TypedGrowth(Dictionary<string, (long Count, long Bytes)> now, Dictionary<string, (long Count, long Bytes)> first, int top)
        {
            var grew = now.Select(kv => (Name: kv.Key, DCount: kv.Value.Count - first.GetValueOrDefault(kv.Key).Count,
                    DBytes: kv.Value.Bytes - first.GetValueOrDefault(kv.Key).Bytes))
                .Where(g => g.DCount != 0).OrderByDescending(g => Math.Abs(g.DBytes)).Take(top).ToList();
            return grew.Count == 0 ? "none" : string.Join(',', grew.Select(g => FormattableString.Invariant($"{g.Name}:{g.DCount:+0;-0}/{g.DBytes / 1024.0:+0;-0}KB")));
        }

        public static string Summary()
        {
            if (!CensusOn) return "off";
            var modules = ModuleMap.Snapshot();
            // Sized up front: adding a key never grows the table inside the walk.
            var now = new Dictionary<long, (long Count, long Bytes)>(MaxClasses);
            var typed = Typed(modules, now);
            if (_first is null || _firstTyped is null)
            {
                _first = now;
                _firstTyped = typed;
                return $"baseline classes={now.Count} blocks={now.Values.Sum(v => v.Count)} modules={modules.Count}";
            }
            var grew = now.Select(kv => (Key: kv.Key, DCount: kv.Value.Count - _first.GetValueOrDefault(kv.Key).Count,
                    DBytes: kv.Value.Bytes - _first.GetValueOrDefault(kv.Key).Bytes))
                .Where(g => g.DBytes > 0).OrderByDescending(g => g.DBytes).Take(TopClasses).ToList();
            if (grew.Count == 0) return "no growth | typed " + TypedGrowth(typed, _firstTyped, TopModules);
            var text = string.Join(',', grew.Select(g => FormattableString.Invariant($"{KeyText(g.Key)}:+{g.DCount}/+{g.DBytes / 1024.0:0}KB")));
            var forced = ForcedKeys().Where(now.ContainsKey).Select(k => (k, now[k].Count));
            var sampled = forced.Concat(grew.Where(g => g.DCount > 0).Take(SampleClasses).Select(g => (g.Key, now[g.Key].Count)))
                .DistinctBy(c => c.Item1).ToArray();
            return text + " | typed " + TypedGrowth(typed, _firstTyped, TopModules) + " | samples " + Samples(modules, sampled);
        }

        /// <summary>BASTION_LEAK_CENSUS_KEYS="h2:496,h0:352": classes always sampled, first, whatever grew most.</summary>
        private static IEnumerable<long> ForcedKeys()
        {
            foreach (var part in (Environment.GetEnvironmentVariable("BASTION_LEAK_CENSUS_KEYS") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var bits = part.TrimStart('h').Split(':');
                if (bits.Length == 2 && int.TryParse(bits[0], out var heap) && uint.TryParse(bits[1].TrimEnd('B'), out var size))
                    yield return Key(heap, size);
            }
        }

        /// <summary>
        /// For each class: <see cref="SamplesPerClass"/> blocks spread evenly through it (most of them are the grown
        /// ones), their first fields named by module, and for the first one the blocks that point into it. Everything is
        /// copied into buffers made before the walks and rendered after them.
        /// </summary>
        private static string Samples(ModuleMap modules, (long Key, long Count)[] classes)
        {
            var n = classes.Length;
            var qwords = new long[n * SamplesPerClass * SampleQwords];
            var address = new long[n * SamplesPerClass];
            var sizes = new uint[n * SamplesPerClass];
            var picked = new int[n];
            var seen = new long[n];
            Walk((heap, data, size) =>
            {
                var k = Key(heap, size);
                for (var c = 0; c < n; c++)
                {
                    if (classes[c].Key != k || picked[c] >= SamplesPerClass) continue;
                    var step = Math.Max(1, classes[c].Count / (SamplesPerClass + 1));
                    if (++seen[c] % step != 0) return;
                    var slot = c * SamplesPerClass + picked[c]++;
                    address[slot] = (long)data;
                    sizes[slot] = size;
                    var words = (int)Math.Min(size / 8, SampleQwords);
                    for (var w = 0; w < words; w++) qwords[slot * SampleQwords + w] = Marshal.ReadInt64(data, w * 8);
                    return;
                }
            });
            // Holders of each class's first sample: blocks with a field that points into it.
            var holderHeap = new int[n * MaxHolders];
            var holderAt = new long[n * MaxHolders];
            var holderSize = new uint[n * MaxHolders];
            var holderOffset = new int[n * MaxHolders];
            var holderFirst = new long[n * MaxHolders];
            var holders = new int[n];
            Walk((heap, data, size) => FindHolders(heap, data, size, n, SamplesPerClass, address, sizes, holderHeap, holderAt, holderSize, holderOffset, holderFirst, holders));
            // And the holders of each first holder, one level further up (towards an object with a known type).
            var upHeap = new int[n * MaxHolders];
            var upAt = new long[n * MaxHolders];
            var upSize = new uint[n * MaxHolders];
            var upOffset = new int[n * MaxHolders];
            var upFirst = new long[n * MaxHolders];
            var ups = new int[n];
            Walk((heap, data, size) => FindHolders(heap, data, size, n, MaxHolders, holderAt, holderSize, upHeap, upAt, upSize, upOffset, upFirst, ups));

            var text = new StringBuilder();
            for (var c = 0; c < n; c++)
            {
                if (c > 0) text.Append(" ; ");
                text.Append(KeyText(classes[c].Key)).Append(':');
                for (var s = 0; s < picked[c]; s++)
                {
                    var slot = c * SamplesPerClass + s;
                    text.Append(" [");
                    var words = (int)Math.Min(sizes[slot] / 8, SampleQwords);
                    for (var w = 0; w < words; w++)
                    {
                        if (w > 0) text.Append(' ');
                        text.Append(modules.Describe((ulong)qwords[slot * SampleQwords + w]));
                    }
                    text.Append(']');
                }
                for (var h = 0; h < holders[c]; h++)
                {
                    var i = c * MaxHolders + h;
                    text.Append(FormattableString.Invariant($" <- h{holderHeap[i]}:{SizeClass(holderSize[i])}B+0x{holderOffset[i]:X} [{modules.Describe((ulong)holderFirst[i])}]"));
                }
                for (var h = 0; h < ups[c]; h++)
                {
                    var i = c * MaxHolders + h;
                    text.Append(FormattableString.Invariant($" <<- h{upHeap[i]}:{SizeClass(upSize[i])}B+0x{upOffset[i]:X} [{modules.Describe((ulong)upFirst[i])}]"));
                }
            }
            return text.ToString();
        }

        /// <summary>
        /// Within a heap walk: record this block as a holder of each target it points into (no allocation). Target c is
        /// <c>address[c * stride]</c> with its size.
        /// </summary>
        private static unsafe void FindHolders(int heap, IntPtr data, uint size, int n, int stride, long[] address, uint[] sizes,
            int[] holderHeap, long[] holderAt, uint[] holderSize, int[] holderOffset, long[] holderFirst, int[] holders)
        {
            var p = (long*)data;
            var words = size / 8;
            for (var c = 0; c < n; c++)
            {
                var slot = c * stride;
                var start = address[slot];
                if (start == 0 || holders[c] >= MaxHolders || (long)data == start) continue;
                var end = start + sizes[slot];
                for (var w = 0u; w < words && holders[c] < MaxHolders; w++)
                {
                    var v = p[w];
                    if (v < start || v >= end) continue;
                    var i = c * MaxHolders + holders[c]++;
                    holderHeap[i] = heap;
                    holderAt[i] = (long)data;
                    holderSize[i] = size;
                    holderOffset[i] = (int)(w * 8);
                    holderFirst[i] = words > 0 ? p[0] : 0;
                }
            }
        }
    }

#else
    /// <summary>Owner builds: no census.</summary>
    private static class HeapCensus
    {
        public static string Summary() => "off";
    }
#endif

    /// <summary>BASTION_EXP_NO_TSF=1 (test builds only): terminals make no TSF edit context, for A/B soaks.</summary>
#if BASTION_TEST_HOOKS
    public static readonly bool NoTsf = Environment.GetEnvironmentVariable("BASTION_EXP_NO_TSF") == "1";
#else
    public const bool NoTsf = false;
#endif

#if BASTION_TEST_HOOKS
    /// <summary>
    /// BASTION_LEAK_DRILL=1 with BASTION_LEAK_PROBE (test builds only): after start-up the window creates and removes
    /// one kind of element at a time and reports which native objects each kind leaves behind (MainWindow.LeakDrill.cs).
    /// </summary>
    public static bool DrillOn => Enabled && DrillMode is "1" or "cycles" or "bisect" or "bisect4";

    /// <summary>"1": soak-like tab cycles, then single elements; "cycles": the tab cycles only; "bisect": the parts of
    /// closing through the confirmation, one at a time.</summary>
    public static string? DrillMode => Environment.GetEnvironmentVariable("BASTION_LEAK_DRILL");

    /// <summary>A line in the probe file (the drill's results).</summary>
    public static void Note(string line) => Append(line);

    /// <summary>Typed heap blocks by module (see <see cref="HeapCensus"/>) and the bytes allocated in all heaps.</summary>
    public static (Dictionary<string, (long Count, long Bytes)> Typed, long HeapAllocated) DrillCount()
    {
        var typed = HeapCensus.Typed(ModuleMap.Snapshot(), null);
        return (typed, NativeMemory.HeapAllocated());
    }

    /// <summary>"module:+count/+KB" for the modules whose typed blocks changed most between two counts.</summary>
    public static string DrillGrowth(Dictionary<string, (long Count, long Bytes)> now, Dictionary<string, (long Count, long Bytes)> before, int top) =>
        HeapCensus.TypedGrowth(now, before, top);
#endif
}
