using Bastion.Shell.Interop;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Task prompt variables (`$Ask:Label$`, core tasks::ask_labels, C ABI 135), as Mac TaskAsk.swift: one dialog per run asks each
// label once; the answers go to every host of that run and are not stored.
public sealed partial class MainWindow
{
    /// <summary>The answers for <paramref name="t"/>'s prompt variables: empty when it has none, null when cancelled.</summary>
    private async Task<Dictionary<string, string>?> AskTaskAnswersAsync(TaskDto t)
    {
        List<string> labels;
        try { labels = TaskClient.AskLabels(_library, t.Id); }
        catch (BastionException ex) { await ShowModal("Cannot run " + t.Name, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return null; }
        if (labels.Count == 0) return [];
        var fields = labels.Select(label =>
        {
            var box = new TextBox { Header = label, IsSpellCheckEnabled = false, MinWidth = 260 };
            AutomationProperties.SetName(box, label);
            ToolTipService.SetToolTip(box, $"Replaces $Ask:{label}$ in the task.");
            return box;
        }).ToList();
        var body = new StackPanel { Spacing = Ui.Double("Space12") };
        foreach (var f in fields) body.Children.Add(f);
        if (!await ShowModal("Run “" + t.Name + "”", body, primary: "Run", cancel: "Cancel", caption: "Used for every host in this run.", focus: fields[0])) return null;
        var answers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < labels.Count; i++) answers.TryAdd(labels[i], fields[i].Text);
        return answers;
    }
}
