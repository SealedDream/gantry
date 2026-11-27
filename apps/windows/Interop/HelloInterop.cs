using System.Runtime.InteropServices;
using Windows.Security.Credentials.UI;

namespace Bastion.Shell.Interop;

/// <summary>
/// Windows Hello for a desktop window, called through <c>IUserConsentVerifierInterop</c> directly.
/// The SDK's <c>UserConsentVerifierInterop.RequestVerificationForWindowAsync</c> shows the prompt but then throws
/// NotSupportedException (0x80131515) in the NativeAOT build: it builds the generic operation's IID and wrapper at run
/// time. Here the IID is a constant and the operation is read through its plain COM vtables (IAsyncInfo status, then
/// GetResults), so nothing generic is marshalled. Live run on Windows 10, 2026-11-26.
/// </summary>
internal static class HelloInterop
{
    private const string ClassId = "Windows.Security.Credentials.UI.UserConsentVerifier";
    private static readonly Guid IidInterop = new("39E050C3-4E74-441A-8DC0-B81104DF949C");
    /// <summary>IAsyncOperation&lt;UserConsentVerificationResult&gt; (WinRT parameterised IID, computed from its signature).</summary>
    private static readonly Guid IidOperation = new("fd596ffd-2318-558f-9dbe-d21df43764a5");
    private static readonly Guid IidAsyncInfo = new("00000036-0000-0000-C000-000000000046");
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(100);

    // Vtable slots after IInspectable's six.
    private const int SlotRequestForWindow = 6; // IUserConsentVerifierInterop::RequestVerificationForWindowAsync
    private const int SlotGetStatus = 7;        // IAsyncInfo::get_Status
    private const int SlotGetErrorCode = 8;     // IAsyncInfo::get_ErrorCode
    private const int SlotCancel = 9;           // IAsyncInfo::Cancel
    private const int SlotClose = 10;           // IAsyncInfo::Close
    private const int SlotGetResults = 8;       // IAsyncOperation<T>::GetResults

    private const int E_FAIL = unchecked((int)0x80004005);
    private const int E_POINTER = unchecked((int)0x80004003);

    private enum AsyncStatus { Started = 0, Completed = 1, Canceled = 2, Error = 3 }

    /// <summary>Show the Windows Hello prompt owned by <paramref name="hwnd"/> and wait for the answer (UI thread safe).</summary>
    public static async Task<UserConsentVerificationResult> RequestForWindowAsync(IntPtr hwnd, string message)
    {
        var operation = Start(hwnd, message);
        var status = AsyncStatus.Started;
        try
        {
            while (true)
            {
                status = Status(operation, out var error);
                switch (status)
                {
                    case AsyncStatus.Started: break;
                    case AsyncStatus.Completed: return Results(operation);
                    case AsyncStatus.Canceled: return UserConsentVerificationResult.Canceled;
                    // Always throw, even for a non-negative code, so the loop can never poll forever.
                    case AsyncStatus.Error: throw new COMException("Windows Hello failed.", error < 0 ? error : E_FAIL);
                    default: throw new COMException($"Windows Hello returned an unknown status {(int)status}.", E_FAIL);
                }
                await Task.Delay(PollInterval);
            }
        }
        finally
        {
            CloseAsyncInfo(operation, cancel: status == AsyncStatus.Started);
            Marshal.Release(operation);
        }
    }

    private static unsafe IntPtr Start(IntPtr hwnd, string message)
    {
        IntPtr className = IntPtr.Zero, text = IntPtr.Zero, factory = IntPtr.Zero;
        try
        {
            Check(WindowsCreateString(ClassId, (uint)ClassId.Length, out className));
            var iid = IidInterop;
            Check(RoGetActivationFactory(className, ref iid, out factory));
            Check(WindowsCreateString(message, (uint)message.Length, out text));
            var opIid = IidOperation;
            IntPtr operation = IntPtr.Zero;
            var call = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, Guid*, IntPtr*, int>)Slot(factory, SlotRequestForWindow);
            Check(call(factory, hwnd, text, &opIid, &operation));
            if (operation == IntPtr.Zero) Marshal.ThrowExceptionForHR(E_POINTER);
            return operation;
        }
        finally
        {
            if (factory != IntPtr.Zero) Marshal.Release(factory);
            if (text != IntPtr.Zero) WindowsDeleteString(text);
            if (className != IntPtr.Zero) WindowsDeleteString(className);
        }
    }

    private static unsafe AsyncStatus Status(IntPtr operation, out int error)
    {
        error = 0;
        var info = AsyncInfo(operation);
        try
        {
            int status, code;
            Check(((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)Slot(info, SlotGetStatus))(info, &status));
            if ((AsyncStatus)status == AsyncStatus.Error)
            {
                Check(((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)Slot(info, SlotGetErrorCode))(info, &code));
                error = code;
            }
            return (AsyncStatus)status;
        }
        finally { Marshal.Release(info); }
    }

    private static unsafe UserConsentVerificationResult Results(IntPtr operation)
    {
        int result = -1;
        Check(((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)Slot(operation, SlotGetResults))(operation, &result));
        // Only a defined value is passed on; an unknown number throws, and the caller treats that as Failed.
        if (!Enum.IsDefined((UserConsentVerificationResult)result)) throw new COMException($"Windows Hello returned an unknown result {result}.", E_FAIL);
        return (UserConsentVerificationResult)result;
    }

    /// <summary>Cancel a prompt still running (the window closed or an error), then Close. Never throws: it runs in a finally.</summary>
    private static unsafe void CloseAsyncInfo(IntPtr operation, bool cancel)
    {
        try
        {
            var info = AsyncInfo(operation);
            try
            {
                if (cancel) ((delegate* unmanaged[Stdcall]<IntPtr, int>)Slot(info, SlotCancel))(info);
                ((delegate* unmanaged[Stdcall]<IntPtr, int>)Slot(info, SlotClose))(info);
            }
            finally { Marshal.Release(info); }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"hello close: 0x{ex.HResult:X8}"); }
    }

    private static IntPtr AsyncInfo(IntPtr operation)
    {
        var iid = IidAsyncInfo;
        Check(Marshal.QueryInterface(operation, in iid, out var info));
        return info;
    }

    private static unsafe IntPtr Slot(IntPtr obj, int index) => (*(IntPtr**)obj)[index];

    private static void Check(int hr)
    {
        if (hr < 0) Marshal.ThrowExceptionForHR(hr);
    }

    [DllImport("combase.dll", ExactSpelling = true)]
    private static extern int RoGetActivationFactory(IntPtr activatableClassId, ref Guid iid, out IntPtr factory);

    [DllImport("combase.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WindowsCreateString(string sourceString, uint length, out IntPtr hstring);

    [DllImport("combase.dll", ExactSpelling = true)]
    private static extern int WindowsDeleteString(IntPtr hstring);
}
