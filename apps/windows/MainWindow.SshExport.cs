using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>More → Export to ssh_config…: the core writes the SSH connections as an OpenSSH config (owner-only, atomic).</summary>
public sealed partial class MainWindow
{

    private void ExportSsh_Click(object sender, RoutedEventArgs e) => _ = ExportSshAsync();

    internal async Task ExportSshAsync()
    {
        if (_modal is not null) return;
        var path = TestHooks.ExportPath is { } fixedPath ? fixedPath : await PickExportFile();
        if (path is null) return;
        SshExportDto result;
        try { result = _library.ExportSshConfig(path, null); }
        catch (BastionException ex)
        {
            await ShowModal("Could not export", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        var body = new StackPanel { Spacing = 8 };
        body.Children.Add(Ui.Text($"Exported {result.Exported} host{(result.Exported == 1 ? "" : "s")}", "BodyStrongTextStyle"));
        if (result.Skipped.Count > 0)
        {
            body.Children.Add(Ui.Text($"Skipped {result.Skipped.Count}", "BodyTextStyle"));
            var list = new ListView { MaxHeight = 220, SelectionMode = ListViewSelectionMode.None, ItemsSource = result.Skipped.ToList() };
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(list, "Skipped hosts");
            body.Children.Add(list);
        }
        await ShowModal("Export finished", body, primary: "OK", cancel: null, caption: path);
    }

    private async Task<string?> PickExportFile()
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "bastion" };
        picker.FileTypeChoices.Add("OpenSSH config", new List<string> { ".conf" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var file = await picker.PickSaveFileAsync();
        return file?.Path;
    }
}
