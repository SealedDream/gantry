using System;


namespace Bastion.Shell;

/// <summary>
/// Offline mode (<c>BASTION_OFFLINE=1</c>, the same switch the core and bastion_rdp read): the app makes no internet
/// requests. The core refuses them with <c>CoreError::Offline</c> (message prefix <c>offline:</c>); this side keeps that
/// quiet instead of reporting a failure, and skips its own downloads (OpenH264). Mirrors Native Mac (#282).
/// </summary>
internal static class Offline
{
    internal const string UpdateTitle = "Not checked: offline mode";

    internal static bool IsOn => Environment.GetEnvironmentVariable("BASTION_OFFLINE") == "1";

    /// <summary>True for the core's offline refusal, which the C ABI passes through as the error message.</summary>
    internal static bool IsOfflineError(string? message) =>
        message is not null && message.TrimStart().StartsWith("offline:", StringComparison.Ordinal);
}
