param(
    [Parameter(Mandatory = $true)][string]$Source,
    [string]$RecipientDirectory = (Join-Path $PSScriptRoot 'tokyo-shared/private-backups')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
    (Join-Path $RecipientDirectory 'backup-recipient.pem'),
    (Join-Path $RecipientDirectory 'backup-private-key.pem')
)
try {
    $plain = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Source).Path)
    $cms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new(
        [System.Security.Cryptography.Pkcs.ContentInfo]::new($plain),
        [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.1.42'))
    $cms.Encrypt([System.Security.Cryptography.Pkcs.CmsRecipient]::new($certificate))
    $target = "$Source.p7m"
    if (Test-Path -LiteralPath $target) { throw 'Encrypted output already exists.' }
    [IO.File]::WriteAllBytes($target, $cms.Encode())
    $check = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
    $check.Decode([IO.File]::ReadAllBytes($target))
    $recipients = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$recipients.Add($certificate)
    $check.Decrypt($recipients)
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($plain)) -ne
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($check.ContentInfo.Content))) {
        throw 'Encrypted backup verification failed.'
    }
    Write-Output 'Encrypted release recovery file verified.'
}
finally { $certificate.Dispose() }
