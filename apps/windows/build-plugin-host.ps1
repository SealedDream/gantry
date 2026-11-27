<#
Builds the plugin helper (plugin-host/, PLUG-02b) for the Windows package and copies it to
Generated\plugin-host\bastion-plugin-host.exe, where package-windows.ps1 takes it from (PLUG-14).
The same path as the Mac's build-plugin-host.sh. Run on a builder; publish the package once to the build share.
#>
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$repo = Resolve-Path (Join-Path $here '..\..')
Push-Location (Join-Path $repo 'plugin-host')
try {
  & cargo build --release --features helper
  if ($LASTEXITCODE -ne 0) { throw "cargo build of plugin-host failed ($LASTEXITCODE)" }
} finally { Pop-Location }
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'plugin-host\target' }
$built = Join-Path $target 'release\bastion-plugin-host.exe'
if (-not (Test-Path -PathType Leaf $built)) { throw "helper not found after the build: $built" }
$out = Join-Path $here 'Generated\plugin-host'
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item $built (Join-Path $out 'bastion-plugin-host.exe') -Force
"bastion-plugin-host.exe  {0:N1} MB  sha256 {1}" -f ((Get-Item $built).Length / 1MB), (Get-FileHash $built -Algorithm SHA256).Hash
