using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

// A1-CORE-01-FU5 (Native Windows): a library opened by path that this device has never been told about is asked about
// once, before its tree is shown: "I made it" or "Someone sent it". Until it is answered the core offers every login the
// file names instead of using it, so a restored tab or a task cannot use one meanwhile. Closing the question answers
// nothing: the library stays marked in memory and is asked about again next time. "Someone sent it" is the default
// (Enter); "I made it" must be clicked. The rule lives in the core (known_docs.rs); this file only asks.
public sealed partial class MainWindow
{
    /// <summary>Once at start, before the gate or a restore opens any document: record the libraries this device
    /// already uses, so the update itself asks about none of them. A failure is reported once; the core then asks about
    /// every unknown library and the next start tries again.</summary>
    private void MigrateKnownDocuments()
    {
        if (_demo) return;
        try
        {
            var personalId = App.Personal?.Info().Id;
            DocumentClient.MigrateKnown(SessionDataDir, personalId, []); // Recents covers what the gate restores
        }
        catch (BastionException ex) { Announce("Known libraries could not be recorded: " + ex.Message); }
    }

    /// <summary>Ask about an unlocked library of unknown origin. Closing the question sends nothing: the library is
    /// shown with its logins offered, not used, and is asked about again next time.</summary>
    private async Task AskDocumentOriginAsync(DocumentClient doc)
    {
        bool unknown;
        try { unknown = doc.OriginUnknown(); }
        catch (Exception ex) when (ex is BastionException or EntryPointNotFoundException or DllNotFoundException)
        {
            Announce("Could not check who made this library: " + ex.Message); // the core keeps its logins offered
            return;
        }
        if (!unknown) return;
        var madeByMe = false;
        _modalCancelPressed = () => madeByMe = true; // the "I made it" button itself, not Escape
        var body = Ui.Text(DocumentOriginText.Body(doc.Info.Name), "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        var sent = await ShowModal(DocumentOriginText.Title, body, primary: DocumentOriginText.SentIt, cancel: DocumentOriginText.MadeIt);
        if (!sent && !madeByMe) return;
        try
        {
            doc.AnswerOrigin(madeByMe);
            Announce(madeByMe ? "Logins in this library are used as saved" : "Gantry will ask before using logins from this library");
        }
        catch (BastionException ex)
        {
            await ShowModal("Answer not recorded", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    // ---- Snapshot hooks ----

    /// <summary>Snapshot only: whether the shown document is still of unknown origin.</summary>
    internal string DocumentOriginForSnapshot() =>
        _shownDocument is null ? "personal" : _shownDocument.OriginUnknown() ? "unknown" : "known";
}
