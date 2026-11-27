<#
Installs Gantry for Windows from the latest GitHub release (or -Version), per user, without admin rights:

  irm https://github.com/SealedDream/gantry/releases/latest/download/install.ps1 | iex

With options:

  & ([scriptblock]::Create((irm https://github.com/SealedDream/gantry/releases/latest/download/install.ps1))) -Version 0.2.0 -AllUsers

Downloads the setup and SHA256SUMS from the release, checks the setup's SHA-256 (any mismatch or missing line stops
here, nothing runs), then runs the setup silently. -AllUsers installs to Program Files and asks for admin rights.
Works on Windows PowerShell 5.1 and PowerShell 7. The setup is unsigned, so this is the same file the release page
offers, checked against the release's SHA256SUMS. -ApiUrl is for tests (a local server standing in for GitHub).
#>
param(
    [string]$Version = $env:BASTION_VERSION,
    [switch]$AllUsers,
    [string]$ApiUrl = ''
)

function Install-Gantry {
    param([string]$Version, [switch]$AllUsers, [string]$ApiUrl)
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest on 5.1 is many times slower with the progress bar
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'Gantry needs 64-bit Windows.' }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $repo = 'SealedDream/gantry'
    if (-not $ApiUrl) {
        $ApiUrl = if ($Version) { "https://api.github.com/repos/$repo/releases/tags/v$($Version.TrimStart('v'))" }
                  else { "https://api.github.com/repos/$repo/releases/latest" }
    }
    $headers = @{ 'User-Agent' = 'gantry-install'; 'Accept' = 'application/vnd.github+json' }
    try { $release = Invoke-RestMethod -Uri $ApiUrl -Headers $headers -UseBasicParsing }
    catch { throw "Cannot read the release ($ApiUrl): $($_.Exception.Message)" }

    $setup = @($release.assets | Where-Object { $_.name -match '^Gantry-[0-9]+\.[0-9]+\.[0-9]+-windows-x64-setup\.exe$' })
    $sums = @($release.assets | Where-Object { $_.name -eq 'SHA256SUMS' })
    if ($setup.Count -ne 1) { throw "Release $($release.tag_name) has no single Windows setup asset." }
    if ($sums.Count -ne 1) { throw "Release $($release.tag_name) has no SHA256SUMS; not installing an unchecked file." }
    $setup = $setup[0]; $sums = $sums[0]
    Write-Host "Gantry $($release.tag_name): $($setup.name)"

    $dir = Join-Path ([IO.Path]::GetTempPath()) ('gantry-install-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $dir | Out-Null
    try {
        $exe = Join-Path $dir $setup.name
        $sumFile = Join-Path $dir 'SHA256SUMS'
        Invoke-WebRequest -Uri $setup.browser_download_url -OutFile $exe -Headers $headers -UseBasicParsing
        Invoke-WebRequest -Uri $sums.browser_download_url -OutFile $sumFile -Headers $headers -UseBasicParsing

        # Lines are "<sha256>  <name>" (sha256sum format; a leading * marks binary mode).
        $want = @(Get-Content $sumFile | ForEach-Object {
            if ($_ -match '^\s*([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $setup.name) { $Matches[1].ToLowerInvariant() }
        })
        if ($want.Count -ne 1) { throw "SHA256SUMS has no single line for $($setup.name); not installing." }
        $got = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $want[0]) { throw "SHA-256 mismatch for $($setup.name) (expected $($want[0]), got $got); not installing." }
        Write-Host "SHA-256 OK"

        $setupArgs = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', $(if ($AllUsers) { '/ALLUSERS' } else { '/CURRENTUSER' }))
        Write-Host $(if ($AllUsers) { 'Installing for all users (admin prompt)...' } else { 'Installing for this user...' })
        $p = if ($AllUsers) { Start-Process $exe -ArgumentList $setupArgs -Verb RunAs -Wait -PassThru }
             else { Start-Process $exe -ArgumentList $setupArgs -Wait -PassThru }
        if ($p.ExitCode -ne 0) { throw "Setup failed (exit code $($p.ExitCode))." }
        Write-Host 'Gantry is installed. Start it from the Start menu.'
    } finally {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-Gantry -Version $Version -AllUsers:$AllUsers -ApiUrl $ApiUrl
