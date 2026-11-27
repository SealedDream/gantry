using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// Library saves run off the UI thread, one at a time and in order (Mac parity: #1082 <c>LibraryModel.saveQueue</c>).
/// A full save of a 5,000-connection library takes 45–56 ms, which stalled the UI on every edit. The core takes
/// its own lock per call, so an edit on the UI thread and a save here never see a half-written document.
/// Every queued save is finished before the library is disposed or the process exits (<see cref="FlushLibrarySaves"/>).
/// </summary>
public sealed partial class MainWindow
{
    private readonly object _saveGate = new();
    private Task _saveChain = Task.CompletedTask;

    /// <summary>Queue a save of <paramref name="library"/> (the main library when null). Does nothing in demo mode.</summary>
    internal void SaveLibrary(LibraryClient? library = null)
    {
        if (_demo) return;
        var lib = library ?? _library;
        lock (_saveGate)
            _saveChain = _saveChain.ContinueWith(_ => SaveNow(lib), CancellationToken.None,
                TaskContinuationOptions.None, TaskScheduler.Default);
    }

    /// <summary>
    /// After a change to the main library: rebuild the tree, then queue the save. The core's save holds the library's
    /// lock while it writes the file, so a tree read queued behind it waited on the UI thread for the disk
    /// (WIN-TREE-REBUILD). The save is queued even when the rebuild throws, so a change is never left unsaved.
    /// </summary>
    private void ReloadThenSave(string? selectId)
    {
        try { Reload(selectId); }
        finally { SaveLibrary(); }
    }

    private void SaveNow(LibraryClient lib)
    {
        try
        {
            using var lease = lib.AcquireLease(); // keeps the handle alive for this save even while the window closes
            lib.Save();
        }
        catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            CrashLog.Write(ex);
            if (_closed) return; // no window left to show it; the log has it
            DispatcherQueue.TryEnqueue(() =>
                _ = ShowModal("Could not save the library", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null));
        }
    }

    /// <summary>
    /// Queue a save of the credential vault on the same chain as library saves, so the two are written in the order
    /// they were asked for and <see cref="FlushLibrarySaves"/> waits for both. The seal derives the key with Argon2id
    /// (100-250 ms), which stalled the first open of every SSH session whose typed password was saved
    /// (WIN-SSH-OPEN-STALL). A failure is shown as the synchronous save showed it.
    /// </summary>
    internal void SaveCredentials(CredentialStore store)
    {
        lock (_saveGate)
            _saveChain = _saveChain.ContinueWith(_ => SaveCredentialsNow(store), CancellationToken.None,
                TaskContinuationOptions.None, TaskScheduler.Default);
    }

    private void SaveCredentialsNow(CredentialStore store)
    {
        try { store.SaveLeased(); }
        catch (Exception ex) when (ex is BastionException or ObjectDisposedException)
        {
            CrashLog.Write(ex);
            if (_closed) return;
            DispatcherQueue.TryEnqueue(() => Announce("The password was not saved: " + ex.Message));
        }
    }

    /// <summary>
    /// Block until every queued save has been written. Called before the library is disposed and before the
    /// process exits, so an edit made just before close is on disk. No time limit: an edit is never dropped.
    /// </summary>
    internal void FlushLibrarySaves()
    {
        Task chain;
        lock (_saveGate) chain = _saveChain;
        chain.Wait(); // SaveNow catches its own errors, so the chain never faults
    }
}
