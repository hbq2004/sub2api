param(
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups/keyring-recovery')
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Directory -Force | Out-Null
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
Set-Acl -LiteralPath $Directory -AclObject $acl
$keyPath = Join-Path $Directory 'credential-keyring-private-key.pem'
$certificatePath = Join-Path $Directory 'credential-keyring-recipient.pem'
if ((Test-Path -LiteralPath $keyPath) -or (Test-Path -LiteralPath $certificatePath)) {
    throw 'A credential-keyring recipient already exists; preserve it for historical capsules.'
}

$rsa = [Security.Cryptography.RSA]::Create(3072)
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Sub2API credential keyring recipient', $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(10))
    try {
        [IO.File]::WriteAllText($keyPath, $rsa.ExportPkcs8PrivateKeyPem(), [Text.Encoding]::ASCII)
        [IO.File]::WriteAllText($certificatePath, $certificate.ExportCertificatePem(), [Text.Encoding]::ASCII)
    }
    finally { $certificate.Dispose() }
}
finally { $rsa.Dispose() }

Write-Output "Credential-keyring recipient created under: $Directory"
