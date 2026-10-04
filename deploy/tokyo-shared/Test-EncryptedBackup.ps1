param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [ValidateSet('Daily', 'Migration')][string]$Kind = 'Daily',
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups'),
    [string]$KeyringArchive = '',
    [string]$KeyringDirectory = (Join-Path $PSScriptRoot 'private-backups/keyring-recovery'),
    [switch]$AllowLegacyWithoutKeyring
)

$ErrorActionPreference = 'Stop'
$keyPath = Join-Path $Directory 'backup-private-key.pem'
$certificatePath = Join-Path $Directory 'backup-recipient.pem'
if (!(Test-Path -LiteralPath $Archive) -or !(Test-Path -LiteralPath $keyPath) -or
    !(Test-Path -LiteralPath $certificatePath)) {
    throw 'The encrypted archive, private key, or recipient certificate is missing.'
}

Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
    $certificatePath, $keyPath
)
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("sub2api-backup-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $cms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
    $cms.Decode([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Archive)))
    $recipients = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$recipients.Add($certificate)
    $cms.Decrypt($recipients)
    $payload = Join-Path $work 'payload.tgz'
    [System.IO.File]::WriteAllBytes($payload, $cms.ContentInfo.Content)

    $expected = if ($Kind -eq 'Daily') {
        @('database.dump', 'redis.rdb', 'app-state.tgz', 'SHA256SUMS')
    } else {
        @(
            'database.dump',
            'state.tgz',
            'empty-appendonlydir-before-restore/appendonly.aof.manifest',
            'empty-appendonlydir-before-restore/appendonly.aof.1.base.rdb',
            'empty-appendonlydir-before-restore/appendonly.aof.1.incr.aof',
            'shop-before-api/Caddyfile',
            'shop-before-api/compose.yaml',
            'SHA256SUMS'
        )
    }
    $entries = @(& tar -tzf $payload)
    $hasKeyringManifest = $Kind -eq 'Daily' -and $entries -contains 'keyring-manifest.json'
    if ($Kind -eq 'Daily' -and !$hasKeyringManifest -and !$AllowLegacyWithoutKeyring) {
        throw 'Daily backup has no keyring manifest; pass AllowLegacyWithoutKeyring only for an explicitly paired historical recovery.'
    }
    if ($hasKeyringManifest) {
        $expected = @('database.dump', 'redis.rdb', 'app-state.tgz', 'keyring-manifest.json', 'SHA256SUMS')
    }
    if ($LASTEXITCODE -ne 0 -or @($entries | Where-Object { $_ -notin $expected }).Count -ne 0 -or
        @($expected | Where-Object { $_ -notin $entries }).Count -ne 0) {
        throw 'Backup archive contains unexpected or missing entries.'
    }
    # Public recipient encryption does not authenticate the archive producer.
    # Never let a crafted tar link/traversal write outside this staging folder.
    Add-Type -AssemblyName System.Formats.Tar
    $inputStream=[IO.File]::OpenRead($payload)
    $gzip=[IO.Compression.GZipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
    $reader=[System.Formats.Tar.TarReader]::new($gzip)
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    try {
        while($null -ne ($entry=$reader.GetNextEntry())) {
            if($entry.Name -notin $expected -or !$seen.Add($entry.Name) -or
               $entry.EntryType.ToString() -notin @('RegularFile','V7RegularFile') -or
               $entry.Length -gt 536870912) {throw 'Unsafe or duplicate backup archive entry.'}
            $outputStream=[IO.File]::Open((Join-Path $work $entry.Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write)
            try {$entry.DataStream.CopyTo($outputStream)} finally {$outputStream.Dispose()}
        }
        if($seen.Count -ne $expected.Count) {throw 'Backup archive entries are incomplete.'}
    } finally {$reader.Dispose();$gzip.Dispose();$inputStream.Dispose()}

    $checked = @()
    foreach ($line in (Get-Content -LiteralPath (Join-Path $work 'SHA256SUMS'))) {
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') {
            throw 'Invalid checksum manifest.'
        }
        $name = $Matches[2]
        if ($name -notin $expected -or $name -eq 'SHA256SUMS') {
            throw "Unexpected checksum entry: $name"
        }
        $actual = (Get-FileHash -LiteralPath (Join-Path $work $name) -Algorithm SHA256).Hash
        if ($actual -ine $Matches[1]) { throw "Checksum mismatch: $name" }
        $checked += $name
    }
    if ($checked.Count -ne ($expected.Count - 1) -or
        @($expected | Where-Object { $_ -ne 'SHA256SUMS' -and $_ -notin $checked }).Count -ne 0) {
        throw 'Checksum manifest is incomplete.'
    }
    if ($hasKeyringManifest) {
        if ([string]::IsNullOrWhiteSpace($KeyringArchive) -or
            !(Test-Path -LiteralPath $KeyringArchive -PathType Leaf)) {
            throw 'Daily backup verification requires the separately encrypted keyring archive.'
        }
        $manifest = Get-Content -LiteralPath (Join-Path $work 'keyring-manifest.json') -Raw | ConvertFrom-Json
        if ($manifest.format -cne 'sub2api-keyring-manifest-v1' -or
            $manifest.archive -ne [IO.Path]::GetFileName($KeyringArchive) -or
            $manifest.sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Keyring archive manifest is invalid.'
        }
        $keyringHash = (Get-FileHash -LiteralPath $KeyringArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($keyringHash -cne $manifest.sha256) { throw 'Keyring archive checksum mismatch.' }
        $keyringCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
            (Join-Path $KeyringDirectory 'credential-keyring-recipient.pem'),
            (Join-Path $KeyringDirectory 'credential-keyring-private-key.pem'))
        try {
            $keyringRecipients = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
            [void]$keyringRecipients.Add($keyringCertificate)
            $keyringCms = [Security.Cryptography.Pkcs.EnvelopedCms]::new()
            $keyringCms.Decode([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $KeyringArchive)))
            $keyringCms.Decrypt($keyringRecipients)
            $keyringDocument = [Text.Encoding]::UTF8.GetString($keyringCms.ContentInfo.Content) | ConvertFrom-Json
            if (!$keyringDocument.active_key_id -or !$keyringDocument.lookup_key -or !$keyringDocument.encryption_keys) {
                throw 'Recovered keyring schema is invalid.'
            }
        }
        finally { $keyringCertificate.Dispose() }
    }
    $stateArchive = if ($Kind -eq 'Daily') { 'app-state.tgz' } else { 'state.tgz' }
    & tar -tzf (Join-Path $work $stateArchive) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Application state archive is invalid.' }
    Write-Output "Encrypted backup decrypted and checksums verified: $Archive"
}
finally {
    $certificate.Dispose()
    $resolved = [System.IO.Path]::GetFullPath($work)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (!$resolved.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Temporary backup path escaped the expected directory.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
