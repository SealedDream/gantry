namespace Bastion.Shell;

/// <summary>
/// UI-04: the words on the connection page's login line and the session bar's status text, as Native Mac's
/// ConnectionSummary.swift. Pure; no secret ever reaches it.
/// </summary>
internal static class ConnectionSummary
{
    /// <summary>Where the login a connect will use comes from, as the core ranks it.</summary>
    internal abstract record LoginState
    {
        public static readonly LoginState None = new NoneState();
        public static LoginState Locked(string user) => new LockedState(user);
        public static LoginState Offer(string user, string source, string sourceName, bool autoUse) => new OfferState(user, source, sourceName, autoUse);
    }
    private sealed record NoneState : LoginState;
    private sealed record LockedState(string User) : LoginState;
    private sealed record OfferState(string User, string Source, string SourceName, bool AutoUse) : LoginState;

    /// <summary>"Signs in as admin · From folder Customer A". One line.</summary>
    public static string LoginLine(LoginState state) => state switch
    {
        LockedState l => SignsInAs(l.User) + "Credentials locked",
        OfferState o => SignsInAs(o.User) + Origin(o),
        _ => "No login saved",
    };

    private static string Origin(OfferState o) =>
        !o.AutoUse ? (o.SourceName.Length == 0 ? "Offered" : "Offered from " + o.SourceName)
        : o.Source switch
        {
            "inherited" => o.SourceName.Length == 0 ? "From a folder" : "From folder " + o.SourceName,
            "named" => "Named by this connection",
            _ => "Saved for this connection",
        };

    private static string SignsInAs(string user) => user.Length == 0 ? "" : $"Signs in as {user} · ";

    /// <summary>"web1 (10.0.0.5:22) · admin · SSH": the session bar's text; the bar adds state and Logging itself.</summary>
    public static string StatusLine(string name, string address, string? user, string protocol)
    {
        var parts = new List<string> { $"{name} ({address})" };
        if (!string.IsNullOrWhiteSpace(user)) parts.Add(user);
        parts.Add(protocol.ToUpperInvariant());
        return string.Join(" · ", parts);
    }

    /// <summary>"OK", an error line, or "None yet" before the first attempt.</summary>
    public static string LastResult(string? result) => string.IsNullOrEmpty(result) ? "None yet" : result;
}
