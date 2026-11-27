using Bastion.Shell.Interop;

namespace Bastion.Shell;

// Save as Task (owner tab bar review r3, item 11a, as Mac #1310): Run on Hosts and Ansible ad hoc save their command as a
// custom task. Saved by the user here, so it is trusted as if saved in the task editor.
public sealed partial class MainWindow
{
    /// <summary>Save and trust <paramref name="task"/>; null when saved, else the core's reason.</summary>
    private string? SaveAsTask(TaskDto task)
    {
        try { SaveAndTrust(task); return null; }
        catch (BastionException ex) { return ex.Message; }
    }

    /// <summary>Save and trust <paramref name="task"/>; its id, or null with the core's reason in <paramref name="error"/>.</summary>
    private string? SaveAsTaskId(TaskDto task, out string? error)
    {
        error = null;
        try { return SaveAndTrust(task); }
        catch (BastionException ex) { error = ex.Message; return null; }
    }

    /// <summary>
    /// A saved Ansible task that runs through WSL (<c>wsl.exe -e sh -c … gantry ansible…</c>, from Save as Task): check WSL
    /// and the program first and show the run sheet's message instead of a bare start failure. True when it must not run.
    /// </summary>
    private async Task<bool> AnsibleTaskBlockedAsync(TaskDto t)
    {
        if (t.Kind != "custom" || t.RunOn != "local" || !t.Program.Equals("wsl.exe", StringComparison.OrdinalIgnoreCase)) return false;
        var at = t.Args.IndexOf("gantry");
        if (at < 0 || at + 1 >= t.Args.Count || t.Args[at + 1] is not ("ansible" or "ansible-playbook")) return false;
        if (await WslProblemAsync(t.Args[at + 1]) is not { } problem) return false;
        await ShowModal("Cannot run Ansible here", ErrorText(problem), primary: "OK", cancel: null);
        return true;
    }

    private string SaveAndTrust(TaskDto task)
    {
        var id = TaskClient.Save(_library, task);
        TaskHookClient.Trust(_library, id, SessionDataDir);
        Announce("Task saved " + task.Name);
        return id;
    }
}
