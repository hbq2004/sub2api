param(
    [string]$IdentityFile = 'D:\Downloads\Chrome\zynexus_shop_tokyo.pem',
    [string]$KnownHostsFile = 'C:\Users\hbq\.ssh\known_hosts',
    [string]$Destination = (Join-Path $PSScriptRoot 'private-backups'),
    [string]$HostAddress = '43.165.175.45',
    [string]$RemoteUser = 'ubuntu'
)

$ErrorActionPreference = 'Stop'
$remoteDirectory = '/home/ubuntu/sub2api/backups/daily'
$remoteKeyringDirectory = '/home/ubuntu/sub2api/backups/keyring'
$sshOptions = @(
    '-i', $IdentityFile,
    '-o', "UserKnownHostsFile=$KnownHostsFile",
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=10',
    '-o', 'ServerAliveCountMax=3'
)
$remote = "$RemoteUser@$HostAddress"

if (!(Test-Path -LiteralPath $IdentityFile -PathType Leaf) -or
    !(Test-Path -LiteralPath $KnownHostsFile -PathType Leaf) -or
    !(Test-Path -LiteralPath $Destination -PathType Container)) {
    throw 'Identity, known-hosts, or private backup directory is missing.'
}

$listing = & ssh @sshOptions $remote "timeout 60 sudo -n find $remoteDirectory -maxdepth 1 -type f -name '*.p7m' -printf '%T@ %f\n' | sort -nr | head -n 1"
if ($LASTEXITCODE -ne 0 -or !$listing) { throw 'Cannot list remote encrypted backups.' }
$name = ($listing -split ' ', 2)[1]
if ($name -notmatch '^\d{8}T\d{6}Z\.p7m$') { throw 'Unexpected remote backup name.' }
$stamp = [DateTime]::ParseExact($name.Substring(0, 16), 'yyyyMMddTHHmmssZ', [Globalization.CultureInfo]::InvariantCulture)
if (([DateTime]::UtcNow - $stamp).TotalHours -gt 26) { throw 'The latest remote backup is stale.' }

$source = "$remoteDirectory/$name"
$target = Join-Path $Destination $name
$temporaryRemote = "/home/$RemoteUser/.sub2api-export-$name"
$temporaryLocal = "$target.incomplete"
$keyringName = $name.Substring(0, 16) + '.keyring.p7m'
$keyringTarget = Join-Path $Destination $keyringName
$temporaryRemoteKeyring = "/home/$RemoteUser/.sub2api-export-$keyringName"
$temporaryLocalKeyring = "$keyringTarget.incomplete"
try {
    & ssh @sshOptions $remote "timeout 60 sudo -n install -m 0600 -o $RemoteUser -g $RemoteUser $source $temporaryRemote"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare encrypted backup for download.' }

    $remoteHashLine = & ssh @sshOptions $remote "timeout 60 sudo -n sha256sum $source"
    if ($LASTEXITCODE -ne 0 -or $remoteHashLine -notmatch '^([0-9a-f]{64})\s') {
        throw 'Cannot verify remote encrypted backup hash.'
    }
    $remoteHash = $Matches[1]

    if (!(Test-Path -LiteralPath $target -PathType Leaf) -or
        (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $remoteHash) {
        & scp -O @sshOptions "${remote}:$temporaryRemote" $temporaryLocal
        if ($LASTEXITCODE -ne 0) { throw 'Encrypted backup download failed.' }
        if ((Get-FileHash -LiteralPath $temporaryLocal -Algorithm SHA256).Hash -ine $remoteHash) {
            throw 'Downloaded encrypted backup hash mismatch.'
        }
        Move-Item -LiteralPath $temporaryLocal -Destination $target -Force
    }

    $keyringSource = "$remoteKeyringDirectory/$keyringName"
    $keyringHashLine = & ssh @sshOptions $remote "timeout 60 sudo -n sha256sum $keyringSource"
    if ($LASTEXITCODE -ne 0 -or $keyringHashLine -notmatch '^([0-9a-f]{64})\s') {
        throw 'Cannot verify the matching remote keyring archive hash.'
    }
    $keyringHash = $Matches[1]
    if (!(Test-Path -LiteralPath $keyringTarget -PathType Leaf) -or
        (Get-FileHash -LiteralPath $keyringTarget -Algorithm SHA256).Hash -ine $keyringHash) {
        & ssh @sshOptions $remote "timeout 60 sudo -n install -m 0600 -o $RemoteUser -g $RemoteUser $keyringSource $temporaryRemoteKeyring"
        if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the keyring archive for download.' }
        & scp -O @sshOptions "${remote}:$temporaryRemoteKeyring" $temporaryLocalKeyring
        if ($LASTEXITCODE -ne 0) { throw 'Keyring archive download failed.' }
        if ((Get-FileHash -LiteralPath $temporaryLocalKeyring -Algorithm SHA256).Hash -ine $keyringHash) {
            throw 'Downloaded keyring archive hash mismatch.'
        }
        Move-Item -LiteralPath $temporaryLocalKeyring -Destination $keyringTarget -Force
    }

    $powerShell = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    & $powerShell -NoProfile -File (Join-Path $PSScriptRoot 'Test-EncryptedBackup.ps1') -Archive $target -KeyringArchive $keyringTarget -Directory $Destination | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Encrypted backup recovery check failed.' }
    $verified = [pscustomobject]@{
        archive = $name
        sha256 = $remoteHash
        keyringArchive = $keyringName
        keyringSha256 = $keyringHash
        verifiedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    $marker = Join-Path $Destination 'last-verified.json'
    $pendingMarker = "$marker.incomplete"
    $verified | ConvertTo-Json -Compress | Set-Content -LiteralPath $pendingMarker -Encoding utf8
    Move-Item -LiteralPath $pendingMarker -Destination $marker -Force
    Write-Output "Encrypted backup downloaded and verified: $name"
}
finally {
    if (Test-Path -LiteralPath $temporaryLocal) { Remove-Item -LiteralPath $temporaryLocal -Force }
    if (Test-Path -LiteralPath $temporaryLocalKeyring) { Remove-Item -LiteralPath $temporaryLocalKeyring -Force }
    if (Test-Path -LiteralPath (Join-Path $Destination 'last-verified.json.incomplete')) {
        Remove-Item -LiteralPath (Join-Path $Destination 'last-verified.json.incomplete') -Force
    }
    & ssh @sshOptions $remote "sudo -n rm -f -- $temporaryRemote" 2>$null | Out-Null
    & ssh @sshOptions $remote "sudo -n rm -f -- $temporaryRemoteKeyring" 2>$null | Out-Null
}
