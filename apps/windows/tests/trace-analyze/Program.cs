// trace-analyze <trace.etl> --exe-dir <dir with Bastion.exe and Bastion.pdb> [--window <startMs>,<endMs>] [--stall-ms 40]
//               [--sym <symbol path>] [--top 25] [--steps <speed-suite speed-trace.txt>]
// Times are ms since the Bastion process started (the startup probe's marks use the same zero). Without --window the
// whole process lifetime in the trace is used. Output: markdown on stdout.
using System.Globalization;
using System.Text;
using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace Bastion.Tests;

internal static class Program
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>The suite's steps, in ms since the process started (see --steps).</summary>
    private static List<(double T, string Kind, string Name)> Steps = [];

    private static string StepAt(double t)
    {
        var at = Steps.LastOrDefault(x => x.T <= t);
        return at.Name is null ? "" : $" Step: {at.Kind} '{at.Name}'.";
    }

    private static int Main(string[] args)
    {
        if (args.Length < 1) { Console.Error.WriteLine("usage: trace-analyze <trace.etl> --exe-dir <dir> [--window a,b] [--stall-ms 40] [--sym path] [--top 25] [--process Bastion]"); return 2; }
        var etl = args[0];
        string Opt(string name, string def) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : def; }
        var exeDir = Opt("--exe-dir", "");
        var stallMs = double.Parse(Opt("--stall-ms", "40"), Inv);
        var top = int.Parse(Opt("--top", "25"), Inv);
        var procName = Opt("--process", "Gantry");
        var sym = Opt("--sym", $"{exeDir};SRV*{Path.Combine(Path.GetTempPath(), "bastion-sym")}*https://msdl.microsoft.com/download/symbols");

        var etlx = TraceLog.CreateFromEventTraceLogFile(etl);
        using var log = new TraceLog(etlx);
        var proc = log.Processes.Where(p => string.Equals(p.Name, procName, StringComparison.OrdinalIgnoreCase))
                                .OrderByDescending(p => p.CPUMSec).FirstOrDefault();
        if (proc is null) { Console.Error.WriteLine($"no process {procName} in the trace"); return 3; }
        var zero = proc.StartTimeRelativeMsec;
        var (from, to) = (0.0, proc.EndTimeRelativeMsec - zero);
        if (Opt("--window", "") is { Length: > 0 } w)
        {
            var parts = w.Split(',');
            from = double.Parse(parts[0], Inv); to = double.Parse(parts[1], Inv);
        }
        bool In(double rel) => rel - zero >= from && rel - zero <= to;

        // --steps: the speed suite's trace file. Its STEP lines (unix ms, kind, name) name what the suite was doing, so
        // each stall below says which step it fell in (the last step begun before it started).
        var startUnix = new DateTimeOffset(proc.StartTime).ToUnixTimeMilliseconds();
        Steps = Opt("--steps", "") is { Length: > 0 } stepFile && File.Exists(stepFile)
            ? File.ReadLines(stepFile).Select(l => l.Split(' ', 4)).Where(a => a.Length == 4 && a[0] == "STEP" && long.TryParse(a[1], out _))
                .Select(a => (T: (double)(long.Parse(a[1], Inv) - startUnix), Kind: a[2], Name: a[3])).OrderBy(x => x.T).ToList()
            : [];

        using (var reader = new SymbolReader(TextWriter.Null, sym) { SecurityCheck = _ => true })
        {
            foreach (var m in proc.LoadedModules)
                try { log.CodeAddresses.LookupSymbolsForModule(reader, m.ModuleFile); } catch (Exception e) { Console.Error.WriteLine($"symbols {m.ModuleFile.Name}: {e.Message}"); }
        }

        // The UI thread: the process's first thread (WinUI runs the window on the main thread).
        var ui = proc.Threads.OrderBy(t => t.StartTimeRelativeMSec).First().ThreadID;
        var interval = log.SampleProfileInterval.TotalMilliseconds;
        if (interval <= 0) interval = 1;

        // Kernel modules (ntoskrnl, win32k, file-system filters) are not in the process's module list, so their frames
        // stayed bare ("ntoskrnl!"). Look up symbols for every module the UI thread's samples pass through.
        using (var reader = new SymbolReader(TextWriter.Null, sym) { SecurityCheck = _ => true })
        {
            var done = new HashSet<string>(proc.LoadedModules.Select(m => m.ModuleFile.FilePath), StringComparer.OrdinalIgnoreCase);
            var kernelFiles = proc.EventsInProcess.ByEventType<SampledProfileTraceData>()
                .Where(e => e.ThreadID == ui && In(e.TimeStampRelativeMSec))
                .SelectMany(e => Frames(e.CallStack()))
                .Select(f => f.CodeAddress.ModuleFile).Where(f => f is not null)
                .GroupBy(f => f!.FilePath, StringComparer.OrdinalIgnoreCase).Select(g => g.First()!)
                .Where(f => done.Add(f.FilePath)).ToList();
            foreach (var f in kernelFiles)
                try { log.CodeAddresses.LookupSymbolsForModule(reader, f); } catch (Exception e) { Console.Error.WriteLine($"symbols {f.Name}: {e.Message}"); }
        }

        var samples = new List<(double T, TraceCallStack? Stack)>();
        var allSamples = new List<(double T, int Thread, TraceCallStack? Stack)>();
        var cpuByThread = new Dictionary<int, int>();
        foreach (var ev in proc.EventsInProcess.ByEventType<SampledProfileTraceData>())
        {
            if (!In(ev.TimeStampRelativeMSec)) continue;
            cpuByThread[ev.ThreadID] = cpuByThread.GetValueOrDefault(ev.ThreadID) + 1;
            if (ev.ThreadID != ui) allSamples.Add((ev.TimeStampRelativeMSec - zero, ev.ThreadID, ev.CallStack()));
            if (ev.ThreadID == ui) samples.Add((ev.TimeStampRelativeMSec - zero, ev.CallStack()));
        }

        var faults = new List<(double T, int Thread, string File, double Ms, int Bytes)>();
        foreach (var ev in proc.EventsInProcess.ByEventType<MemoryHardFaultTraceData>())
            if (In(ev.TimeStampRelativeMSec)) faults.Add((ev.TimeStampRelativeMSec - zero, ev.ThreadID, ev.FileName ?? "?", ev.ElapsedTimeMSec, ev.ByteCount));

        // Off-CPU intervals of the UI thread (from its switch-out to its next switch-in), with the reason and the stack.
        var waits = new List<(double Start, double Ms, string Reason, TraceCallStack? Stack)>();
        (double T, string Reason, TraceCallStack? Stack)? outAt = null;
        foreach (var ev in log.Events.ByEventType<CSwitchTraceData>())
        {
            if (ev.OldThreadID == ui) outAt = (ev.TimeStampRelativeMSec, ev.OldThreadWaitReason.ToString(), ev.CallStack());
            else if (ev.NewThreadID == ui && outAt is { } o)
            {
                if (In(o.T)) waits.Add((o.T - zero, ev.TimeStampRelativeMSec - o.T, o.Reason, o.Stack));
                outAt = null;
            }
        }

        var md = new StringBuilder();
        md.AppendLine(Inv, $"## {Path.GetFileName(etl)}: {proc.Name} pid {proc.ProcessID}, window {from:0}-{to:0} ms after process start");
        md.AppendLine();
        md.AppendLine(Inv, $"Sample interval {interval:0.###} ms. UI thread {ui}. ");
        md.AppendLine();
        CpuTable(md, cpuByThread, ui, interval);
        WaitTable(md, waits);
        StackTables(md, samples, interval, top);
        FaultTable(md, faults, ui, top);
        KernelTables(md, samples, interval, top);
        Stalls(md, samples, waits, interval, stallMs);
        Timeline(md, waits, allSamples, interval);
        OtherThreads(md, allSamples, cpuByThread, ui, interval, top);
        Console.Write(md.ToString());
        return 0;
    }

    /// <summary>Every UI-thread wait of 20 ms or more, idle ones included, in time order, with what the other threads ran
    /// meanwhile: an idle UI thread before the first paint is waiting for something.</summary>
    private static void Timeline(StringBuilder md, List<(double Start, double Ms, string Reason, TraceCallStack? Stack)> waits, List<(double T, int Thread, TraceCallStack? Stack)> others, double interval)
    {
        md.AppendLine("### UI thread waits of 20 ms or more, in time order, and what other threads ran meanwhile").AppendLine();
        foreach (var w in waits.Where(w => w.Ms >= 20).OrderBy(w => w.Start))
        {
            md.AppendLine(Inv, $"- {w.Start:0}-{w.Start + w.Ms:0} ms ({w.Ms:0} ms) {w.Reason}, UI at `{OwnFrame(w.Stack)}`");
            var during = others.Where(o => o.T >= w.Start && o.T <= w.Start + w.Ms).ToList();
            foreach (var g in during.GroupBy(o => o.Thread).OrderByDescending(g => g.Count()).Take(3))
            {
                var own = g.GroupBy(o => OwnFrame(o.Stack)).OrderByDescending(x => x.Count()).Take(3).Select(x => $"{x.Count() * interval:0} ms `{x.Key}`");
                md.AppendLine(Inv, $"  - thread {g.Key}: {g.Count() * interval:0} ms CPU: {string.Join("; ", own)}");
            }
        }
        md.AppendLine();
    }

    /// <summary>The busiest other threads: what they ran (Bastion's own frame nearest the leaf).</summary>
    private static void OtherThreads(StringBuilder md, List<(double T, int Thread, TraceCallStack? Stack)> others, Dictionary<int, int> cpu, int ui, double interval, int top)
    {
        md.AppendLine("### Other threads: what the busiest ones ran").AppendLine();
        foreach (var (t, _) in cpu.Where(kv => kv.Key != ui).OrderByDescending(kv => kv.Value).Take(3))
        {
            var mine = others.Where(o => o.Thread == t).ToList();
            md.AppendLine(Inv, $"Thread {t}, {mine.Count * interval:0} ms, first sample at {(mine.Count > 0 ? mine.Min(o => o.T) : 0):0} ms:").AppendLine();
            md.AppendLine("| ms | own frame |").AppendLine("|---|---|");
            foreach (var g in mine.GroupBy(o => OwnFrame(o.Stack)).OrderByDescending(g => g.Count()).Take(top / 2))
                md.AppendLine(Inv, $"| {g.Count() * interval:0} | `{g.Key}` |");
            md.AppendLine();
        }
    }

    private static void CpuTable(StringBuilder md, Dictionary<int, int> cpu, int ui, double interval)
    {
        md.AppendLine("### CPU by thread (sampled)").AppendLine().AppendLine("| thread | ms |").AppendLine("|---|---|");
        foreach (var (t, n) in cpu.OrderByDescending(kv => kv.Value).Take(8))
            md.AppendLine(Inv, $"| {t}{(t == ui ? " (UI)" : "")} | {n * interval:0} |");
        md.AppendLine();
    }

    private static void WaitTable(StringBuilder md, List<(double Start, double Ms, string Reason, TraceCallStack? Stack)> waits)
    {
        md.AppendLine("### UI thread off CPU, by wait reason").AppendLine().AppendLine("| reason | count | ms | longest ms |").AppendLine("|---|---|---|---|");
        foreach (var g in waits.GroupBy(w => w.Reason).OrderByDescending(g => g.Sum(w => w.Ms)))
            md.AppendLine(Inv, $"| {g.Key} | {g.Count()} | {g.Sum(w => w.Ms):0} | {g.Max(w => w.Ms):0} |");
        md.AppendLine().AppendLine("(UserRequest / WrUserRequest is the message loop waiting for input: idle, not a stall.)").AppendLine();
    }

    private static string Frame(TraceCallStack s) => $"{s.CodeAddress.ModuleName}!{s.CodeAddress.FullMethodName}";

    private static IEnumerable<TraceCallStack> Frames(TraceCallStack? s) { for (; s is not null; s = s.Caller) yield return s; }

    /// <summary>
    /// Who asked for the work: the nearest frame (from the leaf) in the app's own C# (Bastion.Shell, not the generated
    /// WinUI/WinRT projections or CoreLib compiled into the same exe), followed by the nearest frame in the exe at all
    /// ("via"); else the leaf.
    /// </summary>
    private static string OwnFrame(TraceCallStack? s)
    {
        var all = Frames(s).ToList();
        bool InExe(TraceCallStack f) => f.CodeAddress.ModuleName.StartsWith("Gantry", StringComparison.OrdinalIgnoreCase) && f.CodeAddress.FullMethodName.Length > 0;
        var via = all.FirstOrDefault(InExe);
        var app = all.FirstOrDefault(f => InExe(f) && f.CodeAddress.FullMethodName.Contains("Bastion_Shell_", StringComparison.Ordinal)
                                            && !f.CodeAddress.FullMethodName.Contains("Program__Main", StringComparison.Ordinal));
        if (app is not null) return ReferenceEquals(app, via) ? Frame(app) : $"{Frame(app)} via {via!.CodeAddress.FullMethodName}";
        return via is not null ? Frame(via) : all.Count > 0 ? Frame(all[0]) : "(no stack)";
    }

    private static void StackTables(StringBuilder md, List<(double T, TraceCallStack? Stack)> samples, double interval, int top)
    {
        var inclusive = new Dictionary<string, int>();
        var exclusiveModule = new Dictionary<string, int>();
        var own = new Dictionary<string, int>();
        foreach (var (_, s) in samples)
        {
            foreach (var f in Frames(s).Select(Frame).Distinct()) inclusive[f] = inclusive.GetValueOrDefault(f) + 1;
            var leafModule = s?.CodeAddress.ModuleName ?? "?";
            exclusiveModule[leafModule] = exclusiveModule.GetValueOrDefault(leafModule) + 1;
            var o = OwnFrame(s);
            own[o] = own.GetValueOrDefault(o) + 1;
        }
        md.AppendLine("### UI thread: Bastion's own frame nearest the leaf (who asked for the work)").AppendLine().AppendLine("| ms | frame |").AppendLine("|---|---|");
        foreach (var (f, n) in own.OrderByDescending(kv => kv.Value).Take(top)) md.AppendLine(Inv, $"| {n * interval:0} | `{f}` |");
        md.AppendLine().AppendLine("### UI thread: inclusive time by function").AppendLine().AppendLine("| ms | function |").AppendLine("|---|---|");
        foreach (var (f, n) in inclusive.OrderByDescending(kv => kv.Value).Take(top * 2)) md.AppendLine(Inv, $"| {n * interval:0} | `{f}` |");
        md.AppendLine().AppendLine("### UI thread: exclusive time by module").AppendLine().AppendLine("| ms | module |").AppendLine("|---|---|");
        foreach (var (m, n) in exclusiveModule.OrderByDescending(kv => kv.Value).Take(15)) md.AppendLine(Inv, $"| {n * interval:0} | {m} |");
        md.AppendLine();
    }

    private static void FaultTable(StringBuilder md, List<(double T, int Thread, string File, double Ms, int Bytes)> faults, int ui, int top)
    {
        md.AppendLine(Inv, $"### Hard faults (page-ins): {faults.Count}, {faults.Sum(f => f.Ms):0} ms in all, {faults.Where(f => f.Thread == ui).Sum(f => f.Ms):0} ms on the UI thread").AppendLine();
        md.AppendLine("| file | faults | MB | ms | UI ms |").AppendLine("|---|---|---|---|---|");
        foreach (var g in faults.GroupBy(f => f.File).OrderByDescending(g => g.Sum(f => f.Ms)).Take(top))
            md.AppendLine(Inv, $"| {Path.GetFileName(g.Key)} | {g.Count()} | {g.Sum(f => f.Bytes) / 1048576.0:0.0} | {g.Sum(f => f.Ms):0} | {g.Where(f => f.Thread == ui).Sum(f => f.Ms):0} |");
        md.AppendLine();
    }

    /// <summary>Stalls: UI-thread runs of CPU with no gap over 2 sample intervals, and non-idle waits, each at least
    /// <paramref name="stallMs"/> long, with what ran (top stacks) or what it waited on.</summary>
    private static void Stalls(StringBuilder md, List<(double T, TraceCallStack? Stack)> samples, List<(double Start, double Ms, string Reason, TraceCallStack? Stack)> waits, double interval, double stallMs)
    {
        md.AppendLine(Inv, $"### UI thread stalls of {stallMs:0} ms or more").AppendLine();
        var runs = new List<(double Start, double End, List<TraceCallStack?> Stacks)>();
        foreach (var (t, s) in samples.OrderBy(x => x.T))
        {
            if (runs.Count > 0 && t - runs[^1].End <= 2 * interval) { runs[^1] = (runs[^1].Start, t, runs[^1].Stacks); runs[^1].Stacks.Add(s); }
            else runs.Add((t, t, [s]));
        }
        var busy = runs.Where(r => r.End - r.Start + interval >= stallMs).ToList();
        md.AppendLine(Inv, $"Busy (on CPU): {busy.Count}").AppendLine();
        foreach (var r in busy.OrderByDescending(r => r.End - r.Start).Take(20))
        {
            md.AppendLine(Inv, $"- at {r.Start:0} ms, {r.End - r.Start + interval:0} ms busy.{StepAt(r.Start)} Own frames:");
            foreach (var g in r.Stacks.GroupBy(OwnFrame).OrderByDescending(g => g.Count()).Take(5))
                md.AppendLine(Inv, $"  - {g.Count() * interval:0} ms `{g.Key}`");
            foreach (var g in r.Stacks.GroupBy(s => s is null ? "?" : Frame(s)).OrderByDescending(g => g.Count()).Take(3))
                md.AppendLine(Inv, $"  - leaf {g.Count() * interval:0} ms `{g.Key}`");
            var kernel = r.Stacks.Where(IsKernel).GroupBy(KernelClass).OrderByDescending(g => g.Count()).Select(g => $"{g.Count() * interval:0} ms {g.Key}");
            md.AppendLine(Inv, $"  - kernel: {string.Join("; ", kernel)}");
            XamlWork(md, r.Stacks, interval);
        }
        var blocked = waits.Where(w => w.Ms >= stallMs && !w.Reason.Contains("UserRequest", StringComparison.Ordinal)).ToList();
        md.AppendLine().AppendLine(Inv, $"Blocked (off CPU, not the message-loop wait): {blocked.Count}").AppendLine();
        foreach (var w in blocked.OrderByDescending(w => w.Ms).Take(20))
            md.AppendLine(Inv, $"- at {w.Start:0} ms, {w.Ms:0} ms {w.Reason}: `{OwnFrame(w.Stack)}`");
        md.AppendLine();
    }

    /// <summary>Modules whose frames are WinUI's own work: XAML core and controls, text, drawing, composition, UI Automation.</summary>
    private static readonly string[] XamlModules = ["microsoft.ui.xaml", "dwrite", "d2d1", "dcompi", "dcomp", "uiautomationcore", "microsoft.ui.composition", "textinputframework"];

    private static bool IsXamlModule(string m) => XamlModules.Any(x => m.StartsWith(x, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// What WinUI did inside a stall when no app frame asked for it (layout and render run from the message loop after the
    /// app's handler returned): each sample goes to the first kind that matches its frames, leaf first.
    /// </summary>
    private static readonly (string Kind, string[] Parts)[] XamlKinds =
    [
        ("automation", ["Automation", "Peer", "Uia"]),
        ("text", ["dwrite!", "TextBlock", "TextLayout", "TextFormatter", "RichText", "Font", "Glyph"]),
        ("template", ["ApplyTemplate", "Template", "Parse", "LoadComponent", "XamlReader", "CreateInstance", "ResourceDictionary"]),
        ("layout", ["Measure", "Arrange", "UpdateLayout", "LayoutManager"]),
        ("render", ["Render", "Draw", "Composition", "Comp", "d2d1!", "dcompi!", "Commit", "Visual"]),
        ("input/focus", ["Focus", "Pointer", "Keyboard", "Input"]),
        ("events", ["RaiseEvent", "Event"]),
    ];

    private static void XamlWork(StringBuilder md, List<TraceCallStack?> stacks, double interval)
    {
        var kinds = new Dictionary<string, int>();
        var inclusive = new Dictionary<string, int>();
        foreach (var s in stacks)
        {
            var xaml = Frames(s).Where(f => IsXamlModule(f.CodeAddress.ModuleName)).Select(Frame).ToList();
            if (xaml.Count == 0) continue;
            var kind = XamlKinds.FirstOrDefault(k => xaml.Any(f => k.Parts.Any(p => f.Contains(p, StringComparison.OrdinalIgnoreCase)))).Kind ?? "other XAML";
            kinds[kind] = kinds.GetValueOrDefault(kind) + 1;
            foreach (var f in xaml.Distinct()) inclusive[f] = inclusive.GetValueOrDefault(f) + 1;
        }
        if (kinds.Count == 0) return;
        md.AppendLine(Inv, $"  - XAML by kind: {string.Join("; ", kinds.OrderByDescending(k => k.Value).Select(k => $"{k.Value * interval:0} ms {k.Key}"))}");
        // The frames every XAML sample shares are the message loop's scaffolding; the ones under them say what ran.
        var all = kinds.Values.Sum();
        foreach (var (f, n) in inclusive.Where(kv => kv.Value < all * 0.9).OrderByDescending(kv => kv.Value).Take(8))
            md.AppendLine(Inv, $"    - {n * interval:0} ms `{f}`");
    }

    private static bool IsKernelModule(string m) =>
        m.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) || m.StartsWith("ntoskrnl", StringComparison.OrdinalIgnoreCase)
        || m.StartsWith("ntkrnl", StringComparison.OrdinalIgnoreCase) || m.Equals("hal", StringComparison.OrdinalIgnoreCase);

    private static bool IsKernel(TraceCallStack? s) => s is not null && IsKernelModule(s.CodeAddress.ModuleName);

    /// <summary>
    /// Why a UI-thread sample is in the kernel: the tracer itself (ETW stack walks and event logging), paging (a page
    /// fault, hard or soft), memory (allocating, freeing, mapping), an interrupt, or else the system call the user code made.
    /// </summary>
    private static string KernelClass(TraceCallStack? s)
    {
        var frames = Frames(s).ToList();
        bool Any(params string[] parts) => frames.Any(f => IsKernelModule(f.CodeAddress.ModuleName)
            && parts.Any(p => f.CodeAddress.FullMethodName.Contains(p, StringComparison.Ordinal)));
        if (Any("Etw", "PerfInfo", "PerfLog")) return "tracer (ETW)";
        if (Any("KiPageFault", "MmAccessFault", "MiResolve", "MiDispatchFault")) return "paging (page fault)";
        if (Any("NtAllocateVirtualMemory", "NtFreeVirtualMemory", "MiAllocate", "MiFree", "MiDelete", "MiMap", "MiUnmap", "MmMap", "MmUnmap", "ExAllocatePool", "ExFreePool", "MiZero")) return "memory (allocate, free, map)";
        if (Any("KiInterrupt", "KiDpc", "KiIpi", "KiExecuteAllDpcs", "KiRetireDpcList")) return "interrupt or DPC";
        if (frames.Count == 0 || frames.All(f => f.CodeAddress.FullMethodName.Length == 0)) return "unresolved (no kernel symbols)";
        // The system call: the last user-mode frame before the kernel (ntdll!NtXxx, win32u!NtUserXxx).
        var entry = frames.FirstOrDefault(f => !IsKernelModule(f.CodeAddress.ModuleName));
        return entry is null ? "kernel thread work" : $"syscall {Frame(entry)}";
    }

    /// <summary>UI-thread time in the kernel, by cause, by kernel function at the leaf, and by system call.</summary>
    private static void KernelTables(StringBuilder md, List<(double T, TraceCallStack? Stack)> samples, double interval, int top)
    {
        var kernel = samples.Where(x => IsKernel(x.Stack)).Select(x => x.Stack).ToList();
        md.AppendLine(Inv, $"### UI thread in the kernel: {kernel.Count * interval:0} ms of {samples.Count * interval:0} ms on CPU").AppendLine();
        md.AppendLine("| ms | cause |").AppendLine("|---|---|");
        foreach (var g in kernel.GroupBy(KernelClass).OrderByDescending(g => g.Count()).Take(top))
            md.AppendLine(Inv, $"| {g.Count() * interval:0} | {g.Key} |");
        md.AppendLine().AppendLine("Kernel function at the leaf:").AppendLine().AppendLine("| ms | function |").AppendLine("|---|---|");
        foreach (var g in kernel.GroupBy(s => Frame(s!)).OrderByDescending(g => g.Count()).Take(top))
            md.AppendLine(Inv, $"| {g.Count() * interval:0} | `{g.Key}` |");
        md.AppendLine();
    }
}
