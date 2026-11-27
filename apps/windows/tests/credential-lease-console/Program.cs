// SEC-1 checks: the credential vault handle under a lease (CredentialStore.Leased) survives a lock (Dispose → Release)
// until the in-flight call ends, is freed exactly once, and refuses new calls after the lock.
using Bastion.Shell.Interop;

var failures = 0;
void Check(bool ok, string name) { Console.WriteLine((ok ? "PASS " : "FAIL ") + name); if (!ok) failures++; }

// 1. Lock while an import is running on a worker.
{
    var freed = 0;
    var handle = new IntPtr(0x1234);
    var life = new NativeLifetime(handle, h => { if (h == handle) Interlocked.Increment(ref freed); }, "CredentialStore");
    using var inCall = new ManualResetEventSlim();
    using var finish = new ManualResetEventSlim();
    var sawHandle = IntPtr.Zero;
    var worker = Task.Run(() =>
    {
        using var lease = life.Acquire();
        inCall.Set();
        finish.Wait(TimeSpan.FromSeconds(10));
        sawHandle = lease.Handle; // the native import still uses the handle here
        Check(Volatile.Read(ref freed) == 0, "vault not freed while the import holds its lease");
    });
    Check(inCall.Wait(TimeSpan.FromSeconds(10)), "import started");
    life.Release(); // the user locks the vault
    Check(Volatile.Read(ref freed) == 0, "lock during import does not free the vault");
    Check(life.IsReleased, "vault reads as locked at once");
    var refused = false;
    try { life.Acquire().Dispose(); } catch (ObjectDisposedException) { refused = true; }
    Check(refused, "new calls after the lock are refused");
    finish.Set();
    Check(worker.Wait(TimeSpan.FromSeconds(10)), "import finished");
    Check(sawHandle == handle, "import used the live handle");
    Check(Volatile.Read(ref freed) == 1, "vault freed once, when the import ended");
    life.Release();
    Check(Volatile.Read(ref freed) == 1, "second lock does not free again");
}

// 2. Lock with no call in flight frees at once.
{
    var freed = 0;
    var life = new NativeLifetime(new IntPtr(7), _ => freed++, "CredentialStore");
    life.Acquire().Dispose();
    life.Release();
    Check(freed == 1, "idle lock frees at once");
}

// 3. Many concurrent leased calls racing a lock: exactly one free, never before the last call ends.
{
    var freed = 0; var active = 0; var early = false;
    var life = new NativeLifetime(new IntPtr(9), _ => { if (Volatile.Read(ref active) != 0) early = true; Interlocked.Increment(ref freed); }, "CredentialStore");
    var tasks = Enumerable.Range(0, 32).Select(i => Task.Run(() =>
    {
        try
        {
            using var l = life.Acquire();
            Interlocked.Increment(ref active);
            Thread.Sleep(i % 5);
            Interlocked.Decrement(ref active);
        }
        catch (ObjectDisposedException) { }
    })).ToArray();
    Thread.Sleep(1);
    life.Release();
    Task.WaitAll(tasks, TimeSpan.FromSeconds(20));
    Check(freed == 1 && !early, "concurrent calls and a lock: one free, after the last call");
}

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
