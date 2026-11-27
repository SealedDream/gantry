using System; using System.Diagnostics; using System.Text;
class M { static int Main(string[] a) {
  string root = @"C:\bastion-work\_mosh\msys64";
  var sb = new StringBuilder("exec mosh --server='LC_ALL=C.UTF-8 mosh-server new -i 0.0.0.0 -p 60001:60010'");
  foreach (var x in a) sb.Append(" '").Append(x.Replace("'", "'\\''")).Append("'");
  var p = new ProcessStartInfo(root + @"\usr\bin\bash.exe") { UseShellExecute = false };
  p.EnvironmentVariables["MSYSTEM"] = "MSYS"; p.EnvironmentVariables["CHERE_INVOKING"] = "1";
  p.EnvironmentVariables["HOME"] = root + @"\home\test"; p.EnvironmentVariables["LC_ALL"] = "C.UTF-8";
  p.EnvironmentVariables["PATH"] = root + @"\usr\bin;" + p.EnvironmentVariables["PATH"];
  p.Arguments = "-lc \"" + sb.ToString().Replace("\"", "\\\"") + "\"";
  var pr = Process.Start(p); pr.WaitForExit(); return pr.ExitCode; } }
