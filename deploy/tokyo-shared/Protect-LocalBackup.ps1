param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups')
)

$ErrorActionPreference = 'Stop'
$certificatePath = Join-Path $Directory 'backup-recipient.pem'
$keyPath = Join-Path $Directory 'backup-private-key.pem'
$source = (Resolve-Path -LiteralPath $Archive).Path
$target = "$source.p7m"
$pending = "$target.incomplete"
if ((Test-Path -LiteralPath $target) -or (Test-Path -LiteralPath $pending)) {
    throw 'The encrypted output already exists.'
}

& tar -tzf $source | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Source archive is invalid.' }

Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
    $certificatePath, $keyPath
)
try {
    $plaintext = [System.IO.File]::ReadAllBytes($source)
    $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new($plaintext)
    $algorithm = [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.1.42')
    $cms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new($content, $algorithm)
    $cms.Encrypt([System.Security.Cryptography.Pkcs.CmsRecipient]::new($certificate))
    [System.IO.File]::WriteAllBytes($pending, $cms.Encode())

    $check = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
    $check.Decode([System.IO.File]::ReadAllBytes($pending))
    $recipients = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$recipients.Add($certificate)
    $check.Decrypt($recipients)
    $before = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($plaintext))
    $after = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($check.ContentInfo.Content))
    if ($before -ne $after) { throw 'Encrypted archive did not round-trip byte-for-byte.' }

    [System.IO.File]::Move($pending, $target)
    Write-Output "Local backup encrypted and verified; source retained: $target"
}
finally {
    $certificate.Dispose()
    if (Test-Path -LiteralPath $pending) {
        Remove-Item -LiteralPath $pending
    }
}
