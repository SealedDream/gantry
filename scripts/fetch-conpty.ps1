<#
Fetches Microsoft's ConPTY (conpty.dll + OpenConsole.exe, x64) into a folder.

  scripts\fetch-conpty.ps1 [-Dest <folder>]   (default: apps\windows\native\conpty)

apps\windows\build-core.ps1 calls it for Native Windows; the Tauri packaging scripts pass their own -Dest.

Why: portable-pty loads a conpty.dll found next to the app before the system one. Windows 10's
built-in ConPTY drops mouse reports (SGR 1000/1006) on their way to programs in local tabs; the
current ConPTY passes them (ui:imemouse PASS on Win10 22H2 and Win11 with it, 2026-11-05).
Source: NuGet package Microsoft.Windows.Console.ConPTY (github.com/microsoft/terminal), MIT
licence (docs/third-party/ConPTY-LICENSE.txt). The version and the package hash are pinned
below; both files must carry a valid Microsoft Authenticode signature.
#>
param([string]$Dest = '')
$ErrorActionPreference = 'Stop'
$Version = '1.25.260930003'
$Sha256 = '02B07B349AF66D801159BDF9E440D4A1CE78BB951F37FC8609731665AFDAE7EE'
$root = Split-Path -Parent $PSScriptRoot   # repository root
$dest = if ($Dest) { $Dest } else { Join-Path $root 'apps\windows\native\conpty' }
$files = @{ 'conpty.dll' = 'runtimes\win-x64\native\conpty.dll'; 'OpenConsole.exe' = 'build\native\runtimes\x64\OpenConsole.exe' }

if ((Test-Path (Join-Path $dest 'VERSION')) -and (Get-Content (Join-Path $dest 'VERSION')) -eq $Version) {
  "ConPTY $Version already in $dest"; return
}
$tmp = Join-Path $env:TEMP ("bastion-conpty-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $tmp | Out-Null
try {
  $pkg = Join-Path $tmp 'conpty.nupkg'
  $id = 'microsoft.windows.console.conpty'
  Invoke-WebRequest -UseBasicParsing "https://api.nuget.org/v3-flatcontainer/$id/$Version/$id.$Version.nupkg" -OutFile $pkg
  $hash = (Get-FileHash $pkg -Algorithm SHA256).Hash
  if ($hash -ne $Sha256) { throw "ConPTY package hash mismatch: got $hash, expected $Sha256" }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [IO.Compression.ZipFile]::ExtractToDirectory($pkg, (Join-Path $tmp 'x'))
  New-Item -ItemType Directory -Force $dest | Out-Null
  foreach ($name in $files.Keys) {
    $src = Join-Path (Join-Path $tmp 'x') $files[$name]
    $sig = Get-AuthenticodeSignature $src
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { throw "$name is not validly signed by Microsoft: $($sig.Status)" }
    Copy-Item $src (Join-Path $dest $name) -Force
  }
  Set-Content (Join-Path $dest 'VERSION') $Version
  "ConPTY $Version -> $dest"
} finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
