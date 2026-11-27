using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A1-CORE-01-FU5 (C ABI 100): a library opened by path is asked about once per device, by document id.</summary>
internal static class DocumentOriginNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_document_origin(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_document_answer_origin(IntPtr d, int madeByMe, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_known_documents_migrate([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? personalId, [MarshalAs(UnmanagedType.LPUTF8Str)] string? restorePathsJson, out IntPtr err);
}

public sealed partial class DocumentClient
{
    /// <summary>True while this device has never been told who made the library: every login it names is offered,
    /// not used. Ask before the tree is shown (a locked library: after unlock).</summary>
    public bool OriginUnknown()
    {
        var rc = DocumentOriginNative.bastion_document_origin(Live, out var err);
        if (rc < 0) throw new BastionException(GatewayNative.Take(err) ?? "could not read the library's origin");
        return rc == 1;
    }

    /// <summary>"I made it" (true) or "Someone sent it" (false). Closing the question sends nothing.</summary>
    public void AnswerOrigin(bool madeByMe) =>
        Ok(DocumentOriginNative.bastion_document_answer_origin(Live, madeByMe ? 1 : 0, out var err), err, "could not record the answer");

    /// <summary>Once at start, before any document is opened: when there is no record yet, every library this device
    /// already uses (Personal, Recents, <paramref name="restorePaths"/>) is recorded as known. True when it ran.</summary>
    public static bool MigrateKnown(string dataDir, string? personalId, IReadOnlyList<string> restorePaths)
    {
        var rc = DocumentOriginNative.bastion_known_documents_migrate(dataDir, personalId,
            restorePaths.Count == 0 ? null : JsonSerializer.Serialize(restorePaths, StringListJsonContext.Default.IReadOnlyListString), out var err);
        if (rc < 0) throw new BastionException(GatewayNative.Take(err) ?? "could not record the known libraries");
        return rc == 1;
    }
}

/// <summary>The question's words (as the packet gives them); no WinUI here, so the console test checks them.</summary>
public static class DocumentOriginText
{
    public const string Title = "Did you make this library?";
    public const string MadeIt = "I made it";
    public const string SentIt = "Someone sent it";

    public static string Body(string name) =>
        $"\"{name}\" has not been opened on this device before. If someone else sent it to you, Gantry will ask before using any saved login it names.";
}
