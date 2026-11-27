using System;

namespace Bastion.Shell.Interop;

/// <summary>
/// Owns one native handle whose C contract says "free only when no other thread is using it" (Codex W02).
/// A blocking call made off the UI thread holds a <see cref="Lease"/> for its whole duration. <see cref="Release"/>
/// (window close) never waits: when calls are still in flight it only marks the owner released, and the last lease
/// to end frees the handle on its own thread. New leases after release throw <see cref="ObjectDisposedException"/>.
/// </summary>
internal sealed class NativeLifetime
{
    private readonly object _gate = new();
    private readonly Action<IntPtr> _free;
    private readonly string _owner;
    private IntPtr _handle;
    private int _leases;
    private bool _released;

    public NativeLifetime(IntPtr handle, Action<IntPtr> free, string owner)
    {
        _handle = handle;
        _free = free;
        _owner = owner;
    }

    /// <summary>The handle for a short call on the owning thread; throws once released.</summary>
    public IntPtr Handle
    {
        get
        {
            lock (_gate)
            {
                if (_released || _handle == IntPtr.Zero) throw new ObjectDisposedException(_owner);
                return _handle;
            }
        }
    }

    /// <summary>True once <see cref="Release"/> ran (the handle may still be alive under a lease).</summary>
    public bool IsReleased
    {
        get { lock (_gate) return _released; }
    }

    /// <summary>Keep the handle alive until the returned lease is disposed.</summary>
    public Lease Acquire()
    {
        lock (_gate)
        {
            if (_released || _handle == IntPtr.Zero) throw new ObjectDisposedException(_owner);
            _leases++;
            return new Lease(this, _handle);
        }
    }

    /// <summary>Free now when idle; otherwise the last outstanding lease frees it. Safe to call more than once.</summary>
    public void Release()
    {
        IntPtr toFree;
        lock (_gate)
        {
            if (_released) return;
            _released = true;
            if (_leases > 0) return;
            toFree = _handle;
            _handle = IntPtr.Zero;
        }
        if (toFree != IntPtr.Zero) _free(toFree);
    }

    private void End()
    {
        var toFree = IntPtr.Zero;
        lock (_gate)
        {
            _leases--;
            if (_released && _leases == 0)
            {
                toFree = _handle;
                _handle = IntPtr.Zero;
            }
        }
        if (toFree != IntPtr.Zero) _free(toFree);
    }

    /// <summary>One in-flight use of the handle.</summary>
    public sealed partial class Lease : IDisposable
    {
        private NativeLifetime? _owner;

        internal Lease(NativeLifetime owner, IntPtr handle)
        {
            _owner = owner;
            Handle = handle;
        }

        public IntPtr Handle { get; }

        public void Dispose()
        {
            var owner = _owner;
            _owner = null;
            owner?.End();
        }
    }
}
