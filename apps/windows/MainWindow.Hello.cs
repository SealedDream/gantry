using Bastion.Shell.Interop;
using Windows.Security.Credentials.UI;

namespace Bastion.Shell;

// Windows Hello gate (Settings › Security › "Require Windows Hello to open the vault", off by default; the core's
// security.confirm-vault-open, Touch ID on macOS). When it is on, the local vault's key is not unwrapped (DPAPI) until
// Windows Hello (face, fingerprint or PIN) confirms the user at this PC, once per unlock: Lock Credentials, idle
// auto-lock and screen lock all forget the confirmation. Every use of the vault goes through Credentials, so nothing
// opens it around the gate. If Windows Hello is not set up the vault stays closed and the message says why.
public sealed partial class MainWindow
{
    /// <summary>Windows Hello confirmed the user since the vault was last locked.</summary>
    private bool _helloConfirmed;

    private bool VaultNeedsHello => SettingValue("security.confirm-vault-open") == "true";

    /// <summary>Why the vault cannot open yet, or null when it may.</summary>
    private string? VaultGateReason => VaultNeedsHello && !_helloConfirmed ? "The vault is locked. Unlock it with Windows Hello." : null;

    /// <summary>Open the vault for <see cref="Credentials"/>, refusing while the Windows Hello gate is closed.</summary>
    private CredentialStore OpenVault()
    {
        if (VaultGateReason is { } reason) throw new BastionException(reason);
        // The vault inside Personal.bastion when Personal is a document (no OS prompt, owner points 14, 20).
        return App.Personal is { } doc ? doc.Vault() : CredentialStore.Open(CredentialStore.PathFor(_personal.Path));
    }

    /// <summary>Ask Windows Hello when the gate is on and not yet passed. True when the vault may open.</summary>
    private async Task<bool> ConfirmVaultOpenAsync()
    {
        if (VaultGateReason is null) return true;
        var (ok, message) = await RequestHelloAsync("Gantry wants to open your credential vault.");
        _helloConfirmed = ok;
        if (!ok) _vaultError = message;
        return ok;
    }

    private async Task<(bool Ok, string Message)> RequestHelloAsync(string prompt)
    {
        var (outcome, message) = await AskHelloAsync(prompt);
        return (outcome == HelloOutcome.Verified, message);
    }

    /// <summary>What one Windows Hello prompt ended with. <c>Canceled</c> is the user's choice and shows no error.</summary>
    private enum HelloOutcome { Verified, Canceled, Unavailable, Failed }

    /// <summary>A Windows Hello prompt is on screen: a second click never stacks another one.</summary>
    private bool _helloAsking;

    /// <summary>One Windows Hello prompt; the outcome comes from the result code, never from message text.</summary>
    private async Task<(HelloOutcome Outcome, string Message)> AskHelloAsync(string prompt)
    {
        if (_helloAsking) return (HelloOutcome.Canceled, "");
        _helloAsking = true;
        try
        {
            TestHooks.TraceHelloPrompt();
            if (TestHooks.HelloMock is { } mock) return MockHello(mock);
            var available = await UserConsentVerifier.CheckAvailabilityAsync();
            TestHooks.TraceHello("hello-available " + available);
            if (available != UserConsentVerifierAvailability.Available)
                return (HelloOutcome.Unavailable, $"Windows Hello is not available ({available}). Set it up in Windows Settings › Accounts › Sign-in options, or turn off \"Require Windows Hello to open the vault\".");
            TestHooks.TraceHello("hello-ask");
            var result = await HelloInterop.RequestForWindowAsync(Hwnd, prompt);
            TestHooks.TraceHello("hello-result " + result);
            return result switch
            {
                UserConsentVerificationResult.Verified => (HelloOutcome.Verified, ""),
                UserConsentVerificationResult.Canceled => (HelloOutcome.Canceled, ""),
                _ => (HelloOutcome.Failed, $"Windows Hello did not confirm you ({result}). It stays locked."),
            };
        }
        catch (Exception ex)
        {
            // Any failure of the WinRT call (COM, access, or a projection/cast error in the AOT build) ends this prompt
            // with a message on the card; a fire-and-forget caller would otherwise lose it and leave the card waiting.
            TestHooks.TraceHello($"hello-result {ex.GetType().Name} 0x{ex.HResult:X8}");
            System.Diagnostics.Debug.WriteLine($"hello ask: {ex}");
            return (HelloOutcome.Failed, "Windows Hello could not be asked.");
        }
        finally { _helloAsking = false; }
    }

    /// <summary>Test builds only (BASTION_UITEST_HELLO). A mocked answer never proves the real Windows Hello prompt.</summary>
    private static (HelloOutcome, string) MockHello(string mock) => mock switch
    {
        "verified" => (HelloOutcome.Verified, ""),
        "canceled" => (HelloOutcome.Canceled, ""),
        "unavailable" => (HelloOutcome.Unavailable, "Windows Hello is not available (mock)."),
        _ => (HelloOutcome.Failed, "Windows Hello did not confirm you (mock). It stays locked."),
    };

    /// <summary>
    /// The one Windows Hello prompt of an unlock sheet: on Verified the core unwraps the document key (DPAPI, never in
    /// managed memory) and the same confirmation opens the vault gate, so opening a document never asks twice.
    /// Returns null when unlocked; "" when cancelled (no error); otherwise the reason to show on the sheet.
    /// </summary>
    private async Task<string?> UnlockDocumentWithHelloAsync(DocumentClient doc)
    {
        var (outcome, message) = await AskHelloAsync($"Gantry wants to unlock {doc.Info.Name}.");
        if (outcome == HelloOutcome.Canceled) return "";
        if (outcome != HelloOutcome.Verified) return message + " Type the password instead.";
        // The password may have opened it while the prompt was up: nothing left to unlock.
        if (!doc.Info.Locked) { _helloConfirmed = true; return null; }
        try { doc.UnlockWithHello(); }
        catch (BastionException ex)
        {
            TestHooks.TraceHello("hello-unlock failed");
            return ex.Message + " Type the password instead.";
        }
        TestHooks.TraceHello("hello-unlock ok");
        _helloConfirmed = true;
        return null;
    }
}
