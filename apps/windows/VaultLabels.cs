namespace Bastion.Shell;

/// <summary>
/// LOCK-CREDENTIALS-REOPEN: the inspector's credential labels, without WinUI or the native core, so the "a label never
/// opens the vault" rule runs on any machine (tests/vault-labels). A null lookup means the vault is locked: the label
/// is <see cref="Locked"/> and nothing is asked of the vault.
/// </summary>
internal static class VaultLabels
{
    public const string Locked = "Locked";
    public const string None = "—";
    public const string Missing = "Missing from the vault";

    /// <summary>The label for credential <paramref name="id"/>; <paramref name="nameOf"/> is null while the vault is locked.</summary>
    public static string Credential(string? id, Func<string, string?>? nameOf) =>
        id is null ? None : nameOf is null ? Locked : nameOf(id) ?? Missing;

    /// <summary>
    /// A connection's own credential, or the one it inherits and from where. <paramref name="effective"/> and
    /// <paramref name="nameOf"/> are null while the vault is locked.
    /// </summary>
    public static string Effective(string? ownId, Func<(string CredentialId, string Source)?>? effective, Func<string, string?>? nameOf)
    {
        if (ownId is not null) return Credential(ownId, nameOf);
        if (effective is null || nameOf is null) return Locked;
        return effective() is { } eff ? $"{Credential(eff.CredentialId, nameOf)} (inherited from {eff.Source})" : None;
    }
}
