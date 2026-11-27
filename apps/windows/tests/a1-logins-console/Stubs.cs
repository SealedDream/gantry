// The three names the interop sources use that live in window files (MainWindow.ImportFile.cs, App.xaml.cs), with
// the same shape. The console test calls none of them.
using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop
{
    public sealed record ImportFileDto(string Folder, string Format, int Connections, List<string> Skipped);

    internal static class ImportFileNative
    {
        [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr bastion_library_import_file_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);
    }
}

namespace Bastion.Shell
{
    public static class LibraryLocation
    {
        public const string EnvVar = "BASTION_LIBRARY";
    }
}
