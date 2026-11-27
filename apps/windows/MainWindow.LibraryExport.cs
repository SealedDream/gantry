using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// More → Export Library…: a portable, secret-free <c>bastion-export</c> v1 file. The core previews what it will hold
/// (counts and the fields it strips) and writes only after the user confirms; Windows counterpart of the Mac
/// File › Export Library…. The save path comes from <see cref="TestHooks.ExportPath"/> in UI tests.
/// </summary>
public sealed partial class MainWindow
{
    private void ExportLibrary_Click(object sender, RoutedEventArgs e) => _ = ExportLibraryAsync();

    internal async Task ExportLibraryAsync()
    {
        if (_modal is not null) return;
        ExportPreviewDto preview;
        try { preview = _library.ExportPreview(null); }
        catch (BastionException ex)
        {
            await ShowModal("Could not export", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        if (!await ShowModal("Export Connections to a File", ExportPreviewBody(preview), primary: "Export", cancel: "Cancel")) return;
        var path = TestHooks.ExportPath is { } fixedPath ? fixedPath : await PickLibraryExportFile();
        if (path is null) return;
        try { _library.ExportPortable(path, null); }
        catch (BastionException ex)
        {
            await ShowModal("Could not export", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        await ShowModal("Export finished", Ui.Text($"Exported {Plural(preview.Connections, "connection", "connections")} in {Plural(preview.Folders, "folder", "folders")}", "BodyStrongTextStyle"),
            primary: "OK", cancel: null, caption: path);
    }

    private static UIElement ExportPreviewBody(ExportPreviewDto p)
    {
        var body = new StackPanel { Spacing = 8 };
        body.Children.Add(Ui.Text($"{Plural(p.Connections, "connection", "connections")} in {Plural(p.Folders, "folder", "folders")}", "BodyStrongTextStyle"));
        body.Children.Add(Ui.Text("Passwords and other secrets are never exported.", "BodyTextStyle"));
        if (p.CredentialRefs > 0)
            body.Children.Add(Ui.Text($"{Plural(p.CredentialRefs, "credential reference", "credential references")} kept by name only.", "BodyTextStyle"));
        if (p.StrippedFields.Count > 0)
        body.Children.Add(new TextBlock { Text = $"Left out: {string.Join(", ", p.StrippedFields.Distinct())}", TextWrapping = TextWrapping.Wrap });
        return body;
    }

    private async Task<string?> PickLibraryExportFile()
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "bastion-export" };
        picker.FileTypeChoices.Add("Gantry export", new List<string> { ".json" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var file = await picker.PickSaveFileAsync();
        return file?.Path;
    }
}
