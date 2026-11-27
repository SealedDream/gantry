# Build the native core for the Windows shell: core-cabi (a thin C ABI over bastion-ffi) and rdp-ffi (IronRDP, its own
# crate because its dependencies cannot resolve together with russh) as release DLLs, copied to native\ where
# BastionShell.csproj picks them up.
# Windows counterpart of apps\macos\build-core.sh. Needs rustup + the MSVC Build Tools; NASM and
# CMake must be on PATH for aws-lc-sys (NASM is added below if it is in the winget location).
# -TestHooks: core-cabi with its test-hooks feature (UI proof builds with test hooks only, never an owner build).
param([switch]$NoLto, [switch]$TestHooks)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cabi = Join-Path $here '..\..\core-cabi' | Resolve-Path
$rdp = Join-Path $here '..\..\rdp-ffi' | Resolve-Path
foreach ($dir in @((Join-Path $env:USERPROFILE '.cargo\bin'), (Join-Path $env:LOCALAPPDATA 'bin\NASM'))) {
    if ((Test-Path $dir) -and ($env:Path -notlike "*$dir*")) { $env:Path = "$env:Path;$dir" }
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'cargo not found: install Rust with rustup first.' }

foreach ($crate in @($cabi, $rdp)) {
    Push-Location $crate
    $originalRustflags = $env:CARGO_ENCODED_RUSTFLAGS
    try {
        # WIN-SPEED-ROOTCAUSE: the first load of a freshly installed bastion_cabi.dll (about 20 MB) costs about 400 ms
        # of kernel time (image section, code integrity, the AV filter) that the whole start-up waits behind. Fat LTO
        # with one codegen unit gives a smaller image. Release profile only, the core DLL only (the RDP DLL loads
        # later), set here so no other build of the crates changes. Panics still unwind; the PDB is still written.
        # -NoLto builds as before (for A/B measurements).
        $lto = ($crate -eq $cabi) -and -not $NoLto
        if ($lto) { $env:CARGO_PROFILE_RELEASE_LTO = 'fat'; $env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS = '1' }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        if ($crate -eq $cabi) {
            $root = Split-Path $cabi -Parent
            $workspace = Join-Path $root 'target\windows-core-workspace'

            # Remap paths in Rust dependencies as well as in the DLL crate. Encoded
            # flags keep checkout and toolchain paths containing spaces intact.
            $flags = @()
            if ($originalRustflags) {
                $flags += $originalRustflags
            } elseif ($null -eq $originalRustflags -and $env:RUSTFLAGS) {
                $flags += $env:RUSTFLAGS -split ' ' | Where-Object { $_ }
            }
            $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
            $rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $env:USERPROFILE '.rustup' }
            $prefixes = [ordered]@{
                '/bastion' = $workspace
                '/cargo' = $cargoHome
                '/rustup' = $rustupHome
            }
            foreach ($virtualPath in $prefixes.Keys) {
                $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($prefixes[$virtualPath])
                $flags += "--remap-path-prefix=$path=$virtualPath"
                $flags += "--remap-path-prefix=$($path.Replace('\', '/'))=$virtualPath"
            }
            $env:CARGO_ENCODED_RUSTFLAGS = $flags -join [char]31

            # Cargo hashes absolute paths for dependencies outside its workspace.
            # Stage the crates under a private workspace to make those IDs relative.
            New-Item -ItemType Directory -Force $workspace | Out-Null
            $lock = [IO.File]::Open((Join-Path $workspace '.build.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
            try {
                foreach ($name in 'core-cabi', 'core-ffi', 'core', 'plugin-host') {
                    $source = Join-Path $root $name
                    $destination = Join-Path $workspace $name
                    # Copy same-sized files even when their timestamps match.
                    robocopy.exe $source $destination /MIR /IS /IT /IM /XD target /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
                    if ($LASTEXITCODE -ge 8) { throw "Staging $name failed (robocopy exit $LASTEXITCODE)" }
                }
                $manifest = Join-Path $workspace 'Cargo.toml'
                Set-Content -LiteralPath $manifest -Encoding ascii -Value @'
[workspace]
members = ["core-cabi"]
exclude = ["core", "core-ffi", "plugin-host"]
resolver = "2"
'@
                Copy-Item (Join-Path $cabi 'Cargo.lock') (Join-Path $workspace 'Cargo.lock') -Force

                $features = @(); if ($TestHooks) { $features = @('--features', 'test-hooks') }
                # Record the PDB basename in the PE and keep generating the matching PDB.
                cargo rustc --manifest-path $manifest --target-dir (Join-Path $cabi 'target') --package bastion-cabi --locked --release --lib @features -- -Clink-arg=/Brepro '-Clink-arg=/PDBALTPATH:%_PDB%'
            } finally {
                $lock.Dispose()
            }
        } else {
            cargo build --release --lib
        }
        $code = $LASTEXITCODE
        Write-Host ("cargo build {0}{1}: {2:0} s" -f (Split-Path $crate -Leaf), $(if ($lto) { ' (fat LTO, 1 codegen unit)' } else { '' }), $sw.Elapsed.TotalSeconds)
        if ($code -ne 0) { throw "cargo build failed in $crate ($code)" }
    } finally {
        $env:CARGO_ENCODED_RUSTFLAGS = $originalRustflags
        Remove-Item Env:\CARGO_PROFILE_RELEASE_LTO, Env:\CARGO_PROFILE_RELEASE_CODEGEN_UNITS -ErrorAction SilentlyContinue
        Pop-Location
    }
}

$native = Join-Path $here 'native'
New-Item -ItemType Directory -Force $native | Out-Null
Copy-Item (Join-Path $cabi 'target\release\bastion_cabi.dll') $native -Force
Copy-Item (Join-Path $rdp 'target\release\bastion_rdp.dll') $native -Force
# Current ConPTY (pinned version, package hash and Microsoft signature checked); skipped when already present.
& (Join-Path $PSScriptRoot '..\..\scripts\fetch-conpty.ps1') -Dest (Join-Path $native 'conpty')
Write-Host ("built $native\bastion_cabi.dll ({0:0.0} MB) and bastion_rdp.dll" -f ((Get-Item (Join-Path $native 'bastion_cabi.dll')).Length / 1MB))
