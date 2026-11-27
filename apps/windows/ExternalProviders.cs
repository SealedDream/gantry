using System.Text.Json;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// KeePass and HashiCorp Vault as read-only credential sources (core <c>providers</c>, C ABI 63), as Native Mac's
/// ExternalProviders. Only the locations are remembered (providers.json beside the library); passwords, key files
/// and tokens stay in the core until Lock or Lock Credentials. A connect uses <see cref="SshLoginKind.Provider"/>
/// with <c>"&lt;id&gt;:&lt;item&gt;"</c> and the core reads the secret at dial time. 1Password is not offered.
/// </summary>
internal sealed class ExternalProviders
{
    public enum Kind { KeePass, HcVault }

    public static string Id(Kind k) => k == Kind.KeePass ? "keepass" : "hcvault";
    public static string Title(Kind k) => k == Kind.KeePass ? "KeePass" : "HashiCorp Vault";
    /// <summary>What an item looks like, shown as the field prompt.</summary>
    public static string ItemPrompt(Kind k) => k == Kind.KeePass ? "entry uuid (or uuid#username)" : "secret/prod/db#password";

    /// <summary>Where each provider lives. No secret is stored here.</summary>
    public sealed record Config(string KeePassPath = "", string VaultUrl = "", int VaultKv = 2, string VaultNamespace = "");

    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, WriteIndented = true };
    private readonly string _configPath;
    private readonly Dictionary<Kind, CredentialProvider> _handles = new();

    public Config Settings { get; private set; }
    public IReadOnlyList<ProviderItemDto> KeePassItems { get; private set; } = [];

    public ExternalProviders(string dataDir)
    {
        _configPath = Path.Combine(dataDir, "providers.json");
        try { Settings = File.Exists(_configPath) ? JsonSerializer.Deserialize(File.ReadAllText(_configPath), AotJson.Options.Info<Config>()) ?? new() : new(); }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { Settings = new(); }
    }

    public bool IsReady(Kind k) => StatusOf(k)?.Status == "available";

    public bool AnyReady => IsReady(Kind.KeePass) || IsReady(Kind.HcVault);

    private ProviderStatusDto? StatusOf(Kind k)
    {
        if (!_handles.TryGetValue(k, out var h)) return null;
        try { return h.Status(); }
        catch (BastionException ex) { return new ProviderStatusDto(Id(k), "unavailable", ex.Message); }
    }

    /// <summary>"Not set up", "Locked", "Unlocked · 2 entries", "Ready" or why it is unavailable.</summary>
    public string StatusText(Kind k) => StatusOf(k) switch
    {
        null => "Not set up",
        { Status: "available" } => k == Kind.KeePass ? $"Unlocked · {KeePassItems.Count} {(KeePassItems.Count == 1 ? "entry" : "entries")}" : "Ready",
        { Status: "locked" } => "Locked",
        { Reason: { Length: > 0 } r } => "Unavailable: " + r,
        _ => "Unavailable",
    };

    /// <summary>
    /// Saves the location, (re)opens the provider, unlocks and registers it. Blocking (KeePass decrypts the file):
    /// call off the UI thread. Returns null on success, else what went wrong.
    /// </summary>
    public string? Open(Kind k, Config location, string? secret, string? keyFile)
    {
        Settings = location;
        var saveError = Save();
        CredentialProvider h;
        try
        {
            h = k == Kind.KeePass ? CredentialProvider.OpenKeePass(location.KeePassPath)
                : CredentialProvider.OpenHcVault(location.VaultUrl, location.VaultKv, location.VaultNamespace);
        }
        catch (BastionException ex) { return ex.Message; }
        try
        {
            if (h.Unlock(secret, keyFile) != ProviderCheck.Ok)
            {
                h.Dispose();
                return $"{Title(k)} refused that {(k == Kind.KeePass ? "password or key file" : "token")}.";
            }
            var items = k == Kind.KeePass ? h.Items() : [];
            h.Register();
            Replace(k, h);
            if (k == Kind.KeePass) KeePassItems = items;
            return saveError;
        }
        catch (BastionException ex)
        {
            h.Dispose();
            return ex.Message;
        }
    }

    /// <summary>Whether <paramref name="item"/> resolves, without the secret leaving the core. Blocking.</summary>
    public ProviderCheck Check(Kind k, string item) =>
        _handles.TryGetValue(k, out var h) ? h.CheckItem(item) : throw new BastionException($"{Title(k)} is not set up.");

    public void Lock(Kind k)
    {
        if (_handles.TryGetValue(k, out var h)) h.Lock();
        if (k == Kind.KeePass) KeePassItems = [];
    }

    /// <summary>Part of Lock Credentials: every provider forgets its unlock and is unregistered.</summary>
    public void LockAll()
    {
        CredentialProvider.LockAll();
        foreach (var h in _handles.Values) h.Lock();
        KeePassItems = [];
    }

    private void Replace(Kind k, CredentialProvider h)
    {
        if (_handles.Remove(k, out var old)) old.Dispose();
        _handles[k] = h;
    }

    private string? Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_configPath)!);
            File.WriteAllText(_configPath, AotJson.Write<Config>(Settings, Json));
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "providers.json was not saved: " + ex.Message; }
    }
}
