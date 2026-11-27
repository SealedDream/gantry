using System.Runtime.InteropServices;
using System.Text.Json;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell.Interop
{
/// <summary>What <c>bastion_library_import_file_json</c> added: the new folder, the detected format, and what it left out.</summary>
public sealed record ImportFileDto(string Folder, string Format, int Connections, List<string> Skipped);

internal static class ImportFileNative
{
    [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_import_file_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);
}
}

namespace Bastion.Shell
{

// File › Import Connections: CSV, .rdp, PuTTY sessions (.reg), Royal TS (.json), RDCMan (.rdg) and mRemoteNG (.xml), parsed by the core. Each
// file lands in its own new folder, so an import never mixes into existing folders; passwords are never read.
public sealed partial class MainWindow
{
    private static readonly string[] ImportFileTypes = [".csv", ".rdp", ".reg", ".json", ".rdg", ".xml"];

    private void ImportFile_Click(object sender, RoutedEventArgs e) => _ = ImportConnectionsAsync();

    internal async Task ImportConnectionsAsync()
    {
        if (_modal is not null) return;
        if (TestHooks.ImportPath is { } scripted) { await ImportConnectionsFromAsync(scripted); return; }
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        foreach (var t in ImportFileTypes) picker.FileTypeFilter.Add(t);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        if (await picker.PickSingleFileAsync() is not { } file) return;
        await ImportConnectionsFromAsync(file.Path);
    }

    /// <summary>Import one file, save, select the new folder and say what came in and what was left out.</summary>
    internal async Task<ImportFileDto?> ImportConnectionsFromAsync(string path)
    {
        ImportFileDto result;
        try
        {
            result = _library.ImportFile(path);
        }
        catch (BastionException ex)
        {
            await ShowModal("Could not import " + Path.GetFileName(path), CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return null;
        }
        ReloadThenSave(result.Folder);
        var summary = $"{result.Connections} {(result.Connections == 1 ? "connection" : "connections")} imported from {result.Format}.";
        Announce(summary);
        var body = result.Skipped.Count == 0
            ? summary
            : summary + " Left out: " + string.Join("; ", result.Skipped.Take(8)) + (result.Skipped.Count > 8 ? $" and {result.Skipped.Count - 8} more." : ".");
        await ShowModal("Import finished", ErrorText(body), primary: "OK", cancel: null);
        return result;
    }
}
}
