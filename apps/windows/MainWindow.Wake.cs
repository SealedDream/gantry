using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Wake-on-LAN (core `wol`, C ABI 71), as on macOS (Wake.swift): a Wake entry in the host's context menu when a MAC is
// set, and "Waking host…" with Connect Now / Cancel before a connect when "Wake before connect" is on. The settings are
// ordinary `wol_*` properties, so the schema-driven property editor already shows them.
public sealed partial class MainWindow
{
    /// <summary>Context-menu Wake for <paramref name="c"/>, or null when it has no MAC (or the plan cannot be read).</summary>
    private MenuFlyoutItem? WakeEntry(ConnectionDto c)
    {
        WolPlanDto? plan;
        try { plan = _library.WolPlan(c.Id); }
        catch (BastionException) { plan = null; }
        return plan is null ? null : ExtraEntry("Wake", "wake", (_, _) => _ = WakeAsync(c));
    }

    /// <summary>Send the magic packet now; the result shows as a short notice.</summary>
    internal async Task WakeAsync(ConnectionDto c)
    {
        if (_modal is not null) return;
        string text;
        try
        {
            _library.Wake(c.Id);
            text = $"Sent a Wake-on-LAN packet to {c.Name}.";
        }
        catch (BastionException ex) { text = $"{c.Name}: {ex.Message}"; }
        await ShowModal("Wake-on-LAN", WakeText(text, "WakeNotice"), primary: "OK", cancel: null);
    }

    /// <summary>
    /// Before a connect: when the host wants waking first, show the wait and return whether to go on connecting
    /// (true once the host answers, on a timeout or Connect Now; false on Cancel). True at once when no wake is needed.
    /// </summary>
    private async Task<bool> WakeBeforeConnectAsync(ConnectionDto c, LibraryClient library)
    {
        if (_modal is not null) return true;
        WolPlanDto? plan;
        try { plan = library.WolPlan(c.Id); }
        catch (BastionException) { return true; }
        if (plan is not { BeforeConnect: true }) return true;

        var progress = new ProgressBar { Maximum = Math.Max(plan.WaitSecs, 1), Value = 0 };
        AutomationProperties.SetAutomationId(progress, "WakeProgress");
        var outcome = WakeText("", "WakeOutcome");
        outcome.Visibility = Visibility.Collapsed;
        var body = new StackPanel { Spacing = 8 };
        body.Children.Add(WakeText(
            $"Sent Wake-on-LAN to {plan.Mac} via {plan.Broadcast}:{plan.Port}. Waiting up to {plan.WaitSecs} seconds for {plan.Host}:{plan.CheckPort} to answer.",
            "WakeDetail"));
        body.Children.Add(progress);
        body.Children.Add(outcome);

        using var cancel = new WakeCancel();
        var started = DateTime.UtcNow;
        var timer = DispatcherQueue.CreateTimer();
        timer.Interval = TimeSpan.FromSeconds(1);
        timer.Tick += (_, _) => progress.Value = Math.Min(progress.Maximum, (DateTime.UtcNow - started).TotalSeconds);
        timer.Start();

        var shown = ShowModal($"Waking {c.Name}…", body, primary: "Connect Now", cancel: "Cancel");
        var modal = _modal;
        var wait = Task.Run(() => library.WakeBeforeConnect(c.Id, cancel));
        _ = wait.ContinueWith(t => DispatcherQueue.TryEnqueue(() =>
        {
            if (_modal != modal) return; // the user already decided
            if (t.IsFaulted)
            {
                // The packet could not be sent (bad MAC, no network): say so and let the user decide.
                outcome.Text = t.Exception?.GetBaseException().Message ?? "Could not wake the host.";
                outcome.Visibility = Visibility.Visible;
                return;
            }
            if (t.Result.Result != WakeResult.Cancelled) CloseModal(true);
        }), TaskScheduler.Default);

        var proceed = await shown;
        timer.Stop();
        cancel.Cancel();
        try { await wait; } catch (BastionException) { } // already shown; the token must outlive the call
        return proceed;
    }

    private static TextBlock WakeText(string text, string automationId)
    {
        var block = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
        AutomationProperties.SetAutomationId(block, automationId);
        return block;
    }
}
