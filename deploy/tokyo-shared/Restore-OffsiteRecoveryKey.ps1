param(
    [Parameter(Mandatory = $true)][string]$Encrypted,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $Encrypted -PathType Leaf)) { throw 'Encrypted recovery copy is missing.' }
if (Test-Path -LiteralPath $Output) { throw 'Output already exists; refusing to overwrite it.' }
$package = Get-Content -LiteralPath $Encrypted -Raw | ConvertFrom-Json
if ($package.format -cne 'sub2api-offsite-recovery-key-v1' -or
    $package.cipher -cne 'AES-256-GCM' -or
    $package.kdf -cne 'PBKDF2-HMAC-SHA256' -or
    $package.iterations -ne 600000) {
    throw 'Unsupported recovery copy format.'
}

$passphrase = Read-Host 'Enter the offsite recovery passphrase' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passphrase)
try { $phrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
$salt = [Convert]::FromBase64String($package.salt)
$nonce = [Convert]::FromBase64String($package.nonce)
$tag = [Convert]::FromBase64String($package.tag)
$cipher = [Convert]::FromBase64String($package.ciphertext)
if ($salt.Length -ne 32 -or $nonce.Length -ne 12 -or $tag.Length -ne 16) {
    throw 'Recovery copy parameters are invalid.'
}
$key = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
    $phrase, $salt, 600000, [Security.Cryptography.HashAlgorithmName]::SHA256, 32)
$plain = [byte[]]::new($cipher.Length)
try {
    $aes = [Security.Cryptography.AesGcm]::new($key, 16)
    try { $aes.Decrypt($nonce, $cipher, $tag, $plain) }
    finally { $aes.Dispose() }
    $text = [Text.Encoding]::ASCII.GetString($plain)
    if (!$text.StartsWith('-----BEGIN PRIVATE KEY-----')) { throw 'Decrypted content is not a PKCS#8 private key.' }
    [IO.File]::WriteAllBytes($Output, $plain)
    Write-Output "Recovery key restored to the requested path: $Output"
}
finally {
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($key)
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)
    $phrase = $null
}
