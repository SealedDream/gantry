using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// More → Ansible: export the SSH connections as an inventory, or fill a run sheet (ad-hoc module or playbook) that the
/// core checks (C ABI 90) and run it in a terminal tab. Ansible has no native Windows control node, so the run goes
/// through WSL (<c>wsl.exe -e</c>, never a shell) with the Windows paths translated to <c>/mnt/&lt;drive&gt;/…</c>.
/// </summary>
public sealed partial class MainWindow
{

    private void ExportAnsible_Click(object sender, RoutedEventArgs e) => _ = ExportAnsibleAsync();

    private void AnsibleRun_Click(object sender, RoutedEventArgs e) => _ = AnsibleRunAsync();

    private static string AnsibleDir() =>
        TestHooks.AnsibleDir is { } dir
            ? dir
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Gantry", "ansible");

    internal async Task ExportAnsibleAsync()
    {
        if (_modal is not null) return;
        var format = new ComboBox { ItemsSource = new[] { "INI", "YAML" }, SelectedIndex = 0, Header = "Format", MinWidth = 160 };
        AutomationProperties.SetName(format, "Inventory format");
        if (!await ShowModal("Export Ansible inventory", format, primary: "Export", cancel: "Cancel", focus: format)) return;
        var yaml = format.SelectedIndex == 1;
        string? path;
        if (TestHooks.AnsibleDir is not null)
        {
            Directory.CreateDirectory(AnsibleDir());
            path = Path.Combine(AnsibleDir(), yaml ? "exported-inventory.yml" : "exported-inventory.ini");
        }
        else path = await PickAnsibleFile(yaml);
        if (path is null) return;
        AnsibleExportDto result;
        try { result = _library.ExportAnsibleInventory(path, null, yaml); }
        catch (BastionException ex)
        {
            await ShowModal("Could not export", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        await ShowModal("Export finished", ExportSummary(result.Exported, result.Skipped), primary: "OK", cancel: null, caption: path);
    }

    private static StackPanel ExportSummary(int exported, IReadOnlyCollection<string> skipped)
    {
        var body = new StackPanel { Spacing = 8 };
        body.Children.Add(Ui.Text($"Exported {exported} host{(exported == 1 ? "" : "s")}", "BodyStrongTextStyle"));
        if (skipped.Count == 0) return body;
        body.Children.Add(Ui.Text($"Skipped {skipped.Count}", "BodyTextStyle"));
        var list = new ListView { MaxHeight = 220, SelectionMode = ListViewSelectionMode.None, ItemsSource = skipped.ToList() };
        AutomationProperties.SetName(list, "Skipped hosts");
        body.Children.Add(list);
        return body;
    }

    private async Task<string?> PickAnsibleFile(bool yaml)
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "inventory" };
        picker.FileTypeChoices.Add(yaml ? "Ansible inventory (YAML)" : "Ansible inventory (INI)", new List<string> { yaml ? ".yml" : ".ini" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var file = await picker.PickSaveFileAsync();
        return file?.Path;
    }

    /// <summary>The run sheet's controls, read into an <see cref="AnsibleRunInput"/> on every change.</summary>
    private sealed class AnsibleSheet
    {
        public readonly RadioButtons Where = new() { Header = "Run on", ItemsSource = new[] { "This PC (WSL)", "Control host" }, SelectedIndex = 0, MaxColumns = 2 };
        public readonly ComboBox Host = new() { Header = "Control host", PlaceholderText = "Choose an SSH connection", MinWidth = 260 };
        public readonly CheckBox UploadFolder = Box("Upload playbook folder", false);
        public readonly TextBox Tags = Field("Tags (optional)", "");
        public readonly TextBox ExtraVars = Field("Extra vars (optional)", "");
        public readonly RadioButtons Kind = new() { Header = "Run", ItemsSource = new[] { "Ad-hoc module", "Playbook" }, SelectedIndex = 0, MaxColumns = 2 };
        public readonly TextBox Pattern = Field("Hosts (pattern)", "all");
        public readonly TextBox Module = Field("Module", "ping");
        public readonly TextBox ModuleArgs = Field("Module arguments", "");
        public readonly TextBox Playbook = Field("Playbook (.yml)", "");
        public readonly TextBox Limit = Field("Limit (optional)", "");
        public readonly CheckBox Check = Box("Check (dry run)", true);
        public readonly CheckBox Diff = Box("Diff", false);
        public readonly CheckBox Become = Box("Become root", false);
        public readonly TextBlock Preview = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas") };
        public readonly TextBlock Notes = new() { TextWrapping = TextWrapping.Wrap };

        public AnsibleSheet()
        {
            AutomationProperties.SetName(Kind, "Run kind");
            AutomationProperties.SetName(Where, "Run on");
            AutomationProperties.SetName(Host, "Control host");
            ToolTipService.SetToolTip(Where, "Control host: a saved SSH connection with Ansible installed. The inventory and playbook are copied there for the run and removed after. Targets need key login; password-only targets are not supported here.");
            ToolTipService.SetToolTip(UploadFolder, "Copy the playbook's whole folder (roles, group_vars, templates), not only the file.");
            ToolTipService.SetToolTip(ExtraVars, "Passed with -e. Visible in the process list: never put passwords here.");
            AutomationProperties.SetAutomationId(Preview, "AnsiblePreview");
            AutomationProperties.SetAutomationId(Notes, "AnsibleNotes");
        }

        public bool IsPlaybook => Kind.SelectedIndex == 1;
        public bool OnHost => Where.SelectedIndex == 1;

        /// <summary>Carry the typed values into a new sheet (the old one's controls belong to a closed dialog).</summary>
        public void CopyFrom(AnsibleSheet o)
        {
            Kind.SelectedIndex = o.Kind.SelectedIndex;
            foreach (var (to, from) in new[] { (Pattern, o.Pattern), (Module, o.Module), (ModuleArgs, o.ModuleArgs), (Playbook, o.Playbook), (Limit, o.Limit), (Tags, o.Tags), (ExtraVars, o.ExtraVars) }) to.Text = from.Text;
            foreach (var (to, from) in new[] { (Check, o.Check), (Diff, o.Diff), (Become, o.Become), (UploadFolder, o.UploadFolder) }) to.IsChecked = from.IsChecked;
        }

        public AnsibleRunInput Input(string inventory) => new(
            IsPlaybook ? "playbook" : "adhoc", inventory, Pattern.Text.Trim(), Module.Text.Trim(), ModuleArgs.Text.Trim(),
            Playbook.Text.Trim().Trim('"'), Limit.Text.Trim() is { Length: > 0 } l ? l : null,
            Check.IsChecked == true, Diff.IsChecked == true, Become.IsChecked == true, null, 0,
            IsPlaybook && Tags.Text.Trim() is { Length: > 0 } t ? t : null, ExtraVars.Text.Trim() is { Length: > 0 } x ? x : null);

        private static TextBox Field(string header, string text)
        {
            var box = new TextBox { Header = header, Text = text };
            AutomationProperties.SetName(box, header);
            return box;
        }

        private static CheckBox Box(string label, bool on)
        {
            var box = new CheckBox { Content = label, IsChecked = on };
            AutomationProperties.SetName(box, label);
            return box;
        }
    }

    internal Task AnsibleRunAsync() => AnsibleRunAsync(false, null);

    private async Task AnsibleRunAsync(bool onHost, AnsibleSheet? prior)
    {
        if (_modal is not null) return;
        var dir = AnsibleDir();
        var inventory = Path.Combine(dir, "run-inventory.ini");
        try
        {
            Directory.CreateDirectory(dir);
            _library.ExportAnsibleInventory(inventory, null, yaml: false); // the plan checks the file exists
        }
        catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException)
        {
            await ShowModal("Could not write the inventory", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }

        var sheet = new AnsibleSheet();
        if (prior is not null) sheet.CopyFrom(prior);
        var hosts = AllConnections().Where(IsSsh).ToList();
        sheet.Host.ItemsSource = hosts.Select(h => h.Name).ToList();
        sheet.Host.SelectedIndex = hosts.FindIndex(h => h.Id == RememberedControlHost());
        sheet.Where.SelectedIndex = onHost ? 1 : 0;
        AnsiblePlanDto? plan = null;
        void Refresh()
        {
            sheet.Host.Visibility = sheet.OnHost ? Visibility.Visible : Visibility.Collapsed;
            sheet.UploadFolder.Visibility = sheet.OnHost && sheet.IsPlaybook ? Visibility.Visible : Visibility.Collapsed;
            sheet.Tags.Visibility = sheet.IsPlaybook ? Visibility.Visible : Visibility.Collapsed;
            sheet.Module.Visibility = sheet.ModuleArgs.Visibility = sheet.Pattern.Visibility = sheet.IsPlaybook ? Visibility.Collapsed : Visibility.Visible;
            sheet.Playbook.Visibility = sheet.IsPlaybook ? Visibility.Visible : Visibility.Collapsed;
            try
            {
                plan = LibraryClient.AnsiblePlan(sheet.Input(inventory));
                sheet.Preview.Text = string.Join(' ', plan.Argv.Select(QuoteArg));
                sheet.Notes.Text = string.Join(Environment.NewLine,
                    plan.Warnings.Concat(sheet.OnHost && hosts.Count == 0 ? ["No SSH connections to use as a control host."] : []));
                Mirror();
            }
            catch (BastionException ex)
            {
                plan = null;
                sheet.Preview.Text = "";
                sheet.Notes.Text = Capitalised(ex.Message);
                Mirror();
            }
        }
        // A fixed UIA name would hide the text from screen readers and tests; mirror it instead.
        void Mirror()
        {
            AutomationProperties.SetName(sheet.Preview, sheet.Preview.Text);
            AutomationProperties.SetName(sheet.Notes, sheet.Notes.Text);
        }
        foreach (var box in new[] { sheet.Pattern, sheet.Module, sheet.ModuleArgs, sheet.Playbook, sheet.Limit, sheet.Tags, sheet.ExtraVars }) box.TextChanged += (_, _) => Refresh();
        sheet.Where.SelectionChanged += (_, _) => Refresh();
        foreach (var box in new[] { sheet.Check, sheet.Diff, sheet.Become }) { box.Checked += (_, _) => Refresh(); box.Unchecked += (_, _) => Refresh(); }
        sheet.Kind.SelectionChanged += (_, _) => Refresh();
        Refresh();

        var flags = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 16, Children = { sheet.Check, sheet.Diff, sheet.Become } };
        // Save as Task (owner, 2026-11-23, as Mac): any run as a custom task from the core (`task` in the plan input): on this PC
        // through WSL, or over SSH on the control host, which becomes the task's saved Run on… target. No password is stored.
        var saveAsTask = new Button { Content = "Save as Task" };
        void SyncSave()
        {
            var folder = sheet.OnHost && sheet.IsPlaybook && sheet.UploadFolder.IsChecked == true;
            saveAsTask.IsEnabled = plan is not null && !folder && (!sheet.OnHost || sheet.Host.SelectedIndex >= 0);
            saveAsTask.Content = "Save as Task";
            ToolTipService.SetToolTip(saveAsTask, folder ? "A task copies the playbook file only. Turn off Upload playbook folder to save."
                : sheet.OnHost ? "Save as a task that runs on the control host over SSH." : "Save as a task that runs on this PC through WSL.");
        }
        foreach (var box in new[] { sheet.Pattern, sheet.Module, sheet.ModuleArgs, sheet.Playbook, sheet.Limit, sheet.Tags, sheet.ExtraVars }) box.TextChanged += (_, _) => SyncSave();
        foreach (var box in new[] { sheet.Check, sheet.Diff, sheet.Become, sheet.UploadFolder }) { box.Checked += (_, _) => SyncSave(); box.Unchecked += (_, _) => SyncSave(); }
        sheet.Kind.SelectionChanged += (_, _) => SyncSave();
        sheet.Where.SelectionChanged += (_, _) => SyncSave();
        sheet.Host.SelectionChanged += (_, _) => SyncSave();
        SyncSave();
        saveAsTask.Click += (_, _) =>
        {
            if (plan is null) return;
            var host = sheet.OnHost && sheet.Host.SelectedIndex is var i && i >= 0 && i < hosts.Count ? hosts[i] : null;
            if (sheet.OnHost && host is null) return;
            AnsibleTaskDto spec;
            try
            {
                spec = LibraryClient.AnsiblePlan(sheet.Input(inventory) with { Task = new AnsibleTaskSpec(host is null ? "wsl" : "host", host?.Name) }).Task
                    ?? throw new BastionException("the core returned no task");
            }
            catch (BastionException ex) { sheet.Notes.Text = ex.Message; Mirror(); return; }
            var task = new TaskDto("", spec.Name, false, false, "custom", spec.Program, spec.Args, spec.RunOn, 600);
            if (SaveAsTaskId(task, out var error) is not { } id) { sheet.Notes.Text = error ?? ""; Mirror(); return; }
            if (host is not null) TaskTargetStore.Save(id, new TaskTargetChoice(null, [host.Id]));
            saveAsTask.Content = "Saved";
            saveAsTask.IsEnabled = false;
        };
        var body = new StackPanel
        {
            Spacing = 10,
            Children =
            {
                sheet.Where, sheet.Host, sheet.Kind, sheet.Pattern, sheet.Module, sheet.ModuleArgs, sheet.Playbook, sheet.UploadFolder, sheet.Tags,
                sheet.Limit, sheet.ExtraVars, flags,
                Ui.Text("Command", "BodyStrongTextStyle"), sheet.Preview, sheet.Notes,
            },
        };
        var scroll = new ScrollViewer { Content = body, MaxHeight = 520, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        var ok = await ShowModal("Run Ansible", scroll, primary: "Run in terminal", cancel: "Cancel",
            caption: "Inventory: " + inventory, validate: () => plan is not null && (!sheet.OnHost || sheet.Host.SelectedIndex >= 0), focus: sheet.Pattern, wide: true, extra: saveAsTask);
        if (!ok || plan is null) return;
        if (sheet.OnHost)
        {
            if (sheet.Host.SelectedIndex is var i && i >= 0 && i < hosts.Count)
                await StartOnControlHostAsync(hosts[i], sheet.Input(inventory), sheet.UploadFolder.IsChecked == true);
            return;
        }
        if (await WslProblemAsync(plan.Argv[0]) is { } problem)
        {
            var text = ErrorText(problem);
            ToolTipService.SetToolTip(text, "Ansible has no Windows version, so this PC runs it in WSL. Use control host runs it on a saved SSH connection with Ansible installed instead.");
            if (await ShowModal("Cannot run Ansible here", text, primary: "Use control host", cancel: "Close"))
                await AnsibleRunAsync(onHost: true, prior: sheet);
            return;
        }
        var argv = WslArgv(plan.Argv);
        OpenTerminal(plan.Argv[0], () => TerminalSession.Spawn("wsl.exe", argv, 100, 30));
    }

    /// <summary><c>wsl.exe -e argv…</c> with every absolute Windows path turned into its WSL mount path.</summary>
    internal static IReadOnlyList<string> WslArgv(IReadOnlyList<string> argv) =>
        new[] { "-e" }.Concat(argv.Select(a => WindowsToWslPath(a) ?? a)).ToList();

    /// <summary><c>C:\a\b.ini</c> → <c>/mnt/c/a/b.ini</c>; null for anything that is not a drive-rooted path.</summary>
    internal static string? WindowsToWslPath(string arg)
    {
        if (arg.Length < 3 || !char.IsAsciiLetter(arg[0]) || arg[1] != ':' || (arg[2] != '\\' && arg[2] != '/')) return null;
        return "/mnt/" + char.ToLowerInvariant(arg[0]) + arg[2..].Replace('\\', '/');
    }

    private static string QuoteArg(string a) => a.Length > 0 && !a.Any(c => char.IsWhiteSpace(c) || c is '"' or '\'') ? a : "'" + a.Replace("'", "'\\''") + "'";
}
