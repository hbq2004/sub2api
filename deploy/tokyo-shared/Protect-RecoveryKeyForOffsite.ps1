param(
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups')
)

$ErrorActionPreference = 'Stop'
$source = Join-Path $Directory 'backup-private-key.pem'
$output = Join-Path $Directory 'backup-private-key.offsite.enc.json'
if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Recovery key is missing.' }
if (Test-Path -LiteralPath $output) { throw 'Encrypted offsite copy already exists.' }

$first = Read-Host 'Enter a new offsite recovery passphrase (store it separately)' -AsSecureString
$second = Read-Host 'Enter the same passphrase again' -AsSecureString
function Convert-SecureInput([securestring]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}
$passphrase = Convert-SecureInput $first
$confirmation = Convert-SecureInput $second
if ($passphrase.Length -lt 20) { throw 'Use an independent passphrase of at least 20 characters.' }
if ($passphrase -cne $confirmation) { throw 'Passphrases do not match.' }

$salt = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
$nonce = [Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
$plain = [IO.File]::ReadAllBytes($source)
$key = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
    $passphrase, $salt, 600000, [Security.Cryptography.HashAlgorithmName]::SHA256, 32)
$cipher = [byte[]]::new($plain.Length)
$tag = [byte[]]::new(16)
$check = [byte[]]::new($plain.Length)
try {
    $aes = [Security.Cryptography.AesGcm]::new($key, 16)
    try {
        $aes.Encrypt($nonce, $plain, $cipher, $tag)
        $aes.Decrypt($nonce, $cipher, $tag, $check)
    }
    finally { $aes.Dispose() }
    if (![Security.Cryptography.CryptographicOperations]::FixedTimeEquals($plain, $check)) {
        throw 'Encrypted recovery key failed round-trip verification.'
    }
    $package = [ordered]@{
        format = 'sub2api-offsite-recovery-key-v1'
        cipher = 'AES-256-GCM'
        kdf = 'PBKDF2-HMAC-SHA256'
        iterations = 600000
        salt = [Convert]::ToBase64String($salt)
        nonce = [Convert]::ToBase64String($nonce)
        tag = [Convert]::ToBase64String($tag)
        ciphertext = [Convert]::ToBase64String($cipher)
    }
    $pending = "$output.incomplete"
    try {
        [IO.File]::WriteAllText($pending, ($package | ConvertTo-Json -Compress), [Text.Encoding]::ASCII)
        [IO.File]::Move($pending, $output)
    }
    finally { if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending } }
    Write-Output "Encrypted recovery copy verified: $output"
}
finally {
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($key)
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($check)
    $passphrase = $null
    $confirmation = $null
}
