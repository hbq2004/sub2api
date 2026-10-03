param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Encrypted,
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
    (Join-Path $Directory 'backup-recipient.pem'),
    (Join-Path $Directory 'backup-private-key.pem')
)
try {
    $cms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
    $cms.Decode([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Encrypted)))
    $recipients = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$recipients.Add($certificate)
    $cms.Decrypt($recipients)
    $originalHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
    $decryptedHash = [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($cms.ContentInfo.Content)
    )
    if ($originalHash -ne $decryptedHash) {
        throw 'Decrypted backup does not match the original archive.'
    }
    Write-Output "Encrypted backup matches the original byte-for-byte: $Encrypted"
}
finally {
    $certificate.Dispose()
}
