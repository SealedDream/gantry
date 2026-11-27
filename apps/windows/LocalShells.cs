using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// Local terminal connections (core <c>local</c> protocol): the shells this PC offers, WSL distributions from the core's
/// detection, and what to tell the user when a saved WSL distribution cannot be opened. The core stores the choice as
/// <c>local.shell</c>: a built-in id, <c>custom</c>, or <c>wsl:&lt;distro&gt;</c>.
/// </summary>
internal static class LocalShells
{
    public const string ShellKey = "local.shell";
    public const string WslPrefix = "wsl:";
    public const string WslDocsUrl = "https://learn.microsoft.com/windows/wsl/install";

    private static readonly (string Id, string Label)[] Builtin =
    [
        ("powershell", "Windows PowerShell"), ("pwsh", "PowerShell 7"), ("cmd", "Command Prompt"), ("custom", "Custom program"),
    ];

    /// <summary>Installed distributions, or none when WSL is missing or cannot be read (the picker then offers only built-in shells).</summary>
    public static IReadOnlyList<WslDistro> Distros()
    {
        try { return TerminalSession.WslDistroDetails(); }
        catch (BastionException) { return []; }
    }

    /// <summary>"Ubuntu-24.04 (default, WSL 1, running)".</summary>
    public static string Label(WslDistro d)
    {
        var parts = new List<string>();
        if (d.IsDefault) parts.Add("default");
        if (d.Version > 0) parts.Add($"WSL {d.Version}");
        if (d.State is "running" or "stopped") parts.Add(d.State);
        return parts.Count == 0 ? d.Name : $"{d.Name} ({string.Join(", ", parts)})";
    }

    /// <summary>
    /// Shell choices: built-in shells, then one WSL entry per distribution (helpers such as docker-desktop only when
    /// <paramref name="includeHidden"/>). A stored WSL id whose distribution is gone stays in the list, marked, so the
    /// editor never silently changes it.
    /// </summary>
    public static List<(string Id, string Label)> Options(IReadOnlyList<WslDistro> distros, bool includeHidden, string? current)
    {
        var list = Builtin.ToList();
        foreach (var d in distros.Where(d => includeHidden || !d.Hidden || WslPrefix + d.Name == current))
            list.Add((WslPrefix + d.Name, "WSL: " + Label(d)));
        if (current is not null && list.All(o => o.Id != current) && current.StartsWith(WslPrefix, StringComparison.Ordinal))
            list.Add((current, $"WSL: {current[WslPrefix.Length..]} (not installed)"));
        return list;
    }

    /// <summary>The distribution a stored <c>local.shell</c> names, or null for a non-WSL shell.</summary>
    public static string? DistroOf(string? shell) =>
        shell is not null && shell.StartsWith(WslPrefix, StringComparison.Ordinal) ? shell[WslPrefix.Length..] : null;

    /// <summary>"WSL: Ubuntu-24.04", "Command Prompt"; the core's default (Windows PowerShell) when none is set.</summary>
    public static string Describe(string? shell) =>
        DistroOf(shell) is { } d ? "WSL: " + d : Builtin.FirstOrDefault(b => b.Id == shell).Label ?? Builtin[0].Label;

    /// <summary>
    /// Plain-words reason why <paramref name="distro"/> cannot be opened now, or null when it can (a stopped distribution
    /// starts on launch).
    /// </summary>
    public static string? Problem(string distro)
    {
        WslAvailability a;
        try { a = TerminalSession.WslAvailabilityOf(distro); }
        catch (BastionException ex) { return ex.Message; }
        return a.Kind switch
        {
            "ready" => null,
            "wsl_missing" => $"WSL is not installed on this PC. Install it with \"wsl --install\" (see {WslDocsUrl}), then open this connection again.",
            "busy" => $"WSL distribution '{distro}' is being installed, converted or removed. Try again when that has finished.",
            _ => a.Installed is { Count: > 0 } installed
                ? $"WSL distribution '{distro}' is not installed on this PC any more (removed or renamed). Installed: {string.Join(", ", installed)}. Edit the connection's Shell to pick another."
                : $"WSL distribution '{distro}' is not installed on this PC any more, and no other distribution is. Install one with \"wsl --install\".",
        };
    }

    /// <summary>
    /// Distributions not yet saved as a local connection under any name, helpers left out: what "Add all WSL distributions"
    /// creates.
    /// </summary>
    public static List<WslDistro> Missing(IReadOnlyList<WslDistro> distros, IEnumerable<string> savedShells)
    {
        var saved = savedShells.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return distros.Where(d => !d.Hidden && !saved.Contains(WslPrefix + d.Name)).ToList();
    }
}
