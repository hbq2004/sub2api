param(
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups')
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Directory -Force | Out-Null
$keyPath = Join-Path $Directory 'backup-private-key.pem'
$certificatePath = Join-Path $Directory 'backup-recipient.pem'
if ((Test-Path -LiteralPath $keyPath) -or (Test-Path -LiteralPath $certificatePath)) {
    throw 'A backup recipient already exists. Preserve the existing private key to keep old backups recoverable.'
}

$rsa = [System.Security.Cryptography.RSA]::Create(3072)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Sub2API backup recipient',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddDays(-1),
        [DateTimeOffset]::UtcNow.AddYears(10)
    )
    try {
        [System.IO.File]::WriteAllText($keyPath, $rsa.ExportPkcs8PrivateKeyPem(), [System.Text.Encoding]::ASCII)
        [System.IO.File]::WriteAllText($certificatePath, $certificate.ExportCertificatePem(), [System.Text.Encoding]::ASCII)
    }
    finally {
        $certificate.Dispose()
    }
}
finally {
    $rsa.Dispose()
}

$ownerName = (Get-Acl -LiteralPath $Directory).Owner
$ownerSid = ([System.Security.Principal.NTAccount]::new($ownerName)).Translate(
    [System.Security.Principal.SecurityIdentifier]
)
$ownerGrant = '*'+$ownerSid.Value+':F'
& icacls.exe $keyPath /grant $ownerGrant | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not grant the Windows account access to the recovery key.' }
Write-Output "Private recovery key: $keyPath"
Write-Output "Public recipient certificate: $certificatePath"
