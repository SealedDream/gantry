<#
Packages Gantry Terminal for Windows from a Release build (unsigned; the owner ships without paid signing):

  apps\windows\package-windows.ps1 [-Version 0.1.0] [-OutDir dist]

Run build-core.ps1 and `dotnet build -c Release -p:Platform=x64` first. -NoInstaller skips the setup.exe (no Inno Setup needed): the zip only. Produces, in -OutDir:
  Gantry-<version>-windows-x64-setup.exe Inno Setup 6 installer, per user by default, no admin rights (installer\Bastion.iss)
  Gantry-windows-x64.zip                  the same files, the archive Check for Updates downloads
The companion CLI (cli\target\release\bastion.exe, or $env:CARGO_TARGET_DIR\release) goes in a cli\ subfolder: Windows
file names ignore case, so it cannot sit next to Gantry.exe. Inno Setup 6: ISCC.exe on PATH, in Program Files, or in
%LOCALAPPDATA%\Programs\Inno Setup 6. The installer's licence page shows -License (default: the repository LICENSE).
The plugin helper (PLUG-14) goes next to Gantry.exe as bastion-plugin-host.exe: one program file with no files of its own,
so the AppContainer needs no folder grant (PLUG-01, question 8). -PluginPacks <folder> ships the signed plugin packs
in a Plugins\ subfolder (installer and zip), as the owner builds carry them; every pack needs its <name>.sig beside it. It is taken from -PluginHelper, else from
Generated\plugin-host (written by build-plugin-host.ps1), else from the Release output, else left out with a warning; -RequirePluginHelper makes it required.
#>
param([string]$Version = '', [string]$OutDir = '', [string]$PluginHelper = '', [switch]$RequirePluginHelper, [switch]$NoInstaller, [string]$License = '', [string]$PluginPacks = '')
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$repo = Split-Path (Split-Path $here)
if (-not $OutDir) { $OutDir = Join-Path $here 'dist' }
$bin = Get-ChildItem -Directory (Join-Path $here 'bin\x64\Release') -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'win-x64' } | Where-Object { Test-Path (Join-Path $_ 'Gantry.exe') } | Select-Object -First 1
if (-not $bin) { throw "no Release build in $here\bin\x64\Release: run dotnet build -c Release -p:Platform=x64 first" }
if (Test-Path (Join-Path $bin 'TEST-HOOKS-BUILD.txt')) { throw "$bin is a test build (BASTION_TEST_HOOKS): rebuild without -p:BastionTestHooks=true before packaging" }
foreach ($f in 'bastion_cabi.dll', 'bastion_rdp.dll', 'conpty.dll', 'OpenConsole.exe') {
  if (-not (Test-Path (Join-Path $bin $f))) { throw "$f is missing from $bin (run build-core.ps1, then the Release build)" }
}
if (-not $Version) { $Version = $env:BASTION_VERSION }
if (-not $Version) {
  $toml = Get-Content (Join-Path $repo 'core-cabi\Cargo.toml') -Raw
  if ($toml -notmatch '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') { throw 'cannot read the version from core-cabi\Cargo.toml; pass -Version' }
  $Version = $Matches[1]
}
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw "version must be x.y.z: $Version" }
# The exe's file version (BastionShell.csproj takes BASTION_VERSION) must be the version being packaged.
$fileVersion = (Get-Item (Join-Path $bin 'Gantry.exe')).VersionInfo.ProductVersion
if ($fileVersion -notlike "$Version*") { throw "Gantry.exe is version $($fileVersion), packaging $($Version); build with BASTION_VERSION=$($Version)" }

# The plugin helper: one file, next to Gantry.exe, never in a subfolder and never with sidecar files.
$helperName = 'bastion-plugin-host.exe'
if ($PluginHelper) {
  if (-not (Test-Path -PathType Leaf $PluginHelper)) { throw "plugin helper not found: $PluginHelper" }
} elseif (Test-Path -PathType Leaf (Join-Path $here "Generated\plugin-host\$helperName")) {
  $PluginHelper = Join-Path $here "Generated\plugin-host\$helperName"
} elseif (Test-Path -PathType Leaf (Join-Path $bin $helperName)) {
  $PluginHelper = Join-Path $bin $helperName
} elseif ($RequirePluginHelper) {
  throw "plugin helper not built: pass -PluginHelper <path to $helperName>"
} else {
  Write-Warning "no plugin helper ($helperName); the package has no plugin support"
}
if ($PluginHelper) {
  if ((Split-Path $PluginHelper -Leaf) -ne $helperName) { throw "the plugin helper must be named $helperName, not $(Split-Path $PluginHelper -Leaf)" }
  if ((Get-Item $PluginHelper).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "the plugin helper must be a regular file, not a link: $PluginHelper" }
  $mz = [byte[]]::new(2); $fs = [IO.File]::OpenRead($PluginHelper); try { [void]$fs.Read($mz, 0, 2) } finally { $fs.Dispose() }
  if ($mz[0] -ne 0x4D -or $mz[1] -ne 0x5A) { throw "the plugin helper is not a Windows program: $PluginHelper" }
}

$cliTarget = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'cli\target' }
$cli = Join-Path $cliTarget 'release\bastion.exe'
if (-not (Test-Path $cli)) { throw "companion CLI not built: cd cli; cargo build --release ($cli)" }

$iscc = @((Get-Command ISCC -ErrorAction SilentlyContinue).Source, "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
  Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc -and -not $NoInstaller) { throw 'ISCC.exe not found (install Inno Setup 6)' }
if (-not $License) { $License = Join-Path $repo 'LICENSE' }
if (-not $NoInstaller -and -not (Test-Path -PathType Leaf $License)) { throw "LICENSE not found: $License (pass -License)" }

# Stage: the Release output without debug symbols or snapshot leftovers, plus the CLI.
$stage = Join-Path ([IO.Path]::GetTempPath()) ("bastion-native-stage-" + [guid]::NewGuid().ToString('N'))
try {
  Copy-Item $bin $stage -Recurse
  Get-ChildItem $stage -Recurse -Include *.pdb | Remove-Item -Force
  if ($PluginHelper) {
    Copy-Item $PluginHelper (Join-Path $stage $helperName) -Force
    # One file only: no bastion-plugin-host.* config, manifest or symbols beside it, and no copy elsewhere.
    $extra = Get-ChildItem $stage -Recurse -File | Where-Object { $_.Name -like 'bastion-plugin-host*' -and $_.FullName -ne (Join-Path $stage $helperName) }
    if ($extra) { throw "unexpected plugin helper files in the package: $($extra.FullName -join ', ')" }
  }
  if ($PluginPacks) {
    if (-not (Test-Path -PathType Container $PluginPacks)) { throw "plugin packs folder not found: $PluginPacks" }
    $packs = @(Get-ChildItem $PluginPacks -File | Where-Object { $_.Extension -ne '.sig' })
    if (-not $packs) { throw "no plugin packs in $PluginPacks" }
    # Each pack ships with <name>.sig beside it (proxmox-0.2.1.bastionplugin + proxmox-0.2.1.sig), as the app reads it.
    $sig = { param($pk) Join-Path $pk.DirectoryName ($pk.BaseName + '.sig') }
    foreach ($pk in $packs) { if (-not (Test-Path -PathType Leaf (& $sig $pk))) { throw "unsigned plugin pack (no $($pk.BaseName).sig): $($pk.FullName)" } }
    New-Item -ItemType Directory -Force (Join-Path $stage 'Plugins') | Out-Null
    foreach ($pk in $packs) { Copy-Item $pk.FullName, (& $sig $pk) (Join-Path $stage 'Plugins') }
  }
  New-Item -ItemType Directory (Join-Path $stage 'cli') | Out-Null
  Copy-Item $cli (Join-Path $stage 'cli\bastion.exe')
  New-Item -ItemType Directory -Force $OutDir | Out-Null
  $setup = $null
  if (-not $NoInstaller) {
    $setup = Join-Path (Resolve-Path $OutDir) "Gantry-$Version-windows-x64-setup.exe"
    & $iscc /Qp "/DSource=$stage" "/DVersion=$Version" "/DLicense=$((Resolve-Path $License).Path)" "/DOutputDir=$(Split-Path $setup)" "/DOutputBaseFilename=$([IO.Path]::GetFileNameWithoutExtension($setup))" (Join-Path $here 'installer\Bastion.iss')
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }
  }
  $zip = Join-Path (Resolve-Path $OutDir) 'Gantry-windows-x64.zip'
  Remove-Item $zip -ErrorAction SilentlyContinue
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
  foreach ($f in @($setup, $zip) | Where-Object { $_ }) { "{0}  {1:N1} MB  sha256 {2}" -f (Split-Path $f -Leaf), ((Get-Item $f).Length / 1MB), (Get-FileHash $f -Algorithm SHA256).Hash }
} finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
