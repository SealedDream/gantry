using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// SSH algorithms (C ABI 33). When a connect fails with no algorithm in common, say what the server offers and, when
/// the only way in is a weak algorithm Bastion implements, offer "Allow for this host". Policy
/// (<c>forbidWeakSshAlgorithms</c>) is still checked by the core on the retry.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>True when the user allowed the weak algorithms and the connect should be retried.</summary>
    private async Task<bool> OfferWeakAlgorithms(LibraryClient library, string connectionId, string name, SshConnectResult result)
    {
        var outcome = NoCommonAlgorithmDto.Parse(result.Fingerprint);
        var message = result.Error ?? "The server and Gantry have no algorithm in common.";
        var body = AlgorithmFailureBody(message, outcome);
        if (outcome is null || outcome.WeakAllowable.Count == 0)
        {
            await ShowModal("Could not connect to " + name, body, primary: "OK", cancel: null);
            return false;
        }
        if (!await ShowModal("Allow a weak algorithm?", body, primary: "Allow for this host", cancel: "Cancel", caption: name, focusCancel: true))
            return false;
        try
        {
            library.AllowWeakAlgorithms(connectionId, outcome);
            // The core edits the document in memory only; save it so the host stays allowed after a restart.
            SaveLibrary(library);
            return true;
        }
        catch (BastionException ex)
        {
            await ShowModal("Could not allow these algorithms", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return false;
        }
    }

    private static StackPanel AlgorithmFailureBody(string message, NoCommonAlgorithmDto? outcome)
    {
        var panel = new StackPanel { Spacing = Ui.Double("Space8"), MaxWidth = 460 };
        panel.Children.Add(ErrorText(message));
        if (outcome is null) return panel;
        panel.Children.Add(Labelled($"The server offers ({KindLabel(outcome.Kind)})", string.Join(", ", outcome.ServerOffers)));
        if (outcome.WeakAllowable.Count > 0)
        {
            panel.Children.Add(Labelled("Allowing turns on", string.Join(", ", outcome.WeakAllowable)));
            var warn = Ui.Text("These are weak. Allow them only for a host you cannot upgrade; the setting is saved on this connection under Properties › Advanced › Algorithms.", "CaptionSecondaryTextStyle");
            warn.TextWrapping = TextWrapping.Wrap;
            panel.Children.Add(warn);
        }
        return panel;
    }

    private static StackPanel Labelled(string label, string value)
    {
        var text = ErrorText(value);
        text.FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Cascadia Mono, Consolas");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(text, label);
        return new StackPanel { Spacing = 2, Children = { Ui.Text(label, "CaptionSecondaryTextStyle"), text } };
    }

    internal static string KindLabel(string kind) => kind switch
    {
        "kex" => "key exchange",
        "cipher" => "ciphers",
        "mac" => "MACs",
        "hostKey" or "host_key" => "host keys",
        _ => kind,
    };
}
