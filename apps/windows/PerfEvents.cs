using System.Diagnostics.Tracing;

namespace Bastion.Shell;

/// <summary>
/// ETW start/stop markers around each speed-suite measurement (<see cref="PerfTrace.AfterLayout"/>), so a WPR
/// recording can be cut to exactly the slow keystrokes in WPA (Generic Events, provider "Gantry-Perf").
/// Test builds with BASTION_PERF_TRACE only; in an owner build there is no event source at all.
/// Record: wpr -start CPU -start GeneralProfile -start apps\windows\tests\bastion-perf.wprp -filemode.
/// </summary>
internal static class PerfEvents
{
#if BASTION_TEST_HOOKS
    private static long _next;

    /// <summary>Marks the start of one measurement; the returned id pairs it with its <see cref="End"/>.</summary>
    public static long Begin(string metric)
    {
        var id = Interlocked.Increment(ref _next);
        if (Source.Log.IsEnabled()) Source.Log.MeasureStart(metric, id);
        return id;
    }

    public static void End(string metric, long id)
    {
        if (Source.Log.IsEnabled()) Source.Log.MeasureStop(metric, id);
    }

    [EventSource(Name = "Gantry-Perf")]
    private sealed class Source : EventSource
    {
        public static readonly Source Log = new();

        [Event(1, Opcode = EventOpcode.Start, Level = EventLevel.Informational)]
        public void MeasureStart(string metric, long id) => WriteEvent(1, metric, id);

        [Event(2, Opcode = EventOpcode.Stop, Level = EventLevel.Informational)]
        public void MeasureStop(string metric, long id) => WriteEvent(2, metric, id);
    }
#else
    public static long Begin(string metric) => 0;
    public static void End(string metric, long id) { }
#endif
}
