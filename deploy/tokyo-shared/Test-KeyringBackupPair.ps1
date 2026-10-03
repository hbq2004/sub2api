param()
$ErrorActionPreference='Stop'
$work=Join-Path ([IO.Path]::GetTempPath()) ('sub2api-backup-pair-'+[guid]::NewGuid().ToString('N'))
$databaseDirectory=Join-Path $work 'database'
$keyringDirectory=Join-Path $work 'keyring'
$payloadDirectory=Join-Path $work 'payload'
New-Item -ItemType Directory -Path $work,$databaseDirectory,$keyringDirectory,$payloadDirectory|Out-Null
$results=@()
function New-FixtureRecipient([string]$Directory,[string]$Prefix) {
    $rsa=[Security.Cryptography.RSA]::Create(2048)
    try {
        $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=synthetic backup fixture',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert=$req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1),[DateTimeOffset]::UtcNow.AddDays(2))
        try {
            [IO.File]::WriteAllText((Join-Path $Directory ($Prefix+'-recipient.pem')),$cert.ExportCertificatePem())
            [IO.File]::WriteAllText((Join-Path $Directory ($Prefix+'-private-key.pem')),$rsa.ExportPkcs8PrivateKeyPem())
        } finally {$cert.Dispose()}
    } finally {$rsa.Dispose()}
}
function Protect-Fixture([byte[]]$Value,[string]$Certificate,[string]$Output) {
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($Certificate))
    try {
        $cms=[Security.Cryptography.Pkcs.EnvelopedCms]::new(
            [Security.Cryptography.Pkcs.ContentInfo]::new($Value),[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.1.42'))
        $cms.Encrypt([Security.Cryptography.Pkcs.CmsRecipient]::new($cert))
        [IO.File]::WriteAllBytes($Output,$cms.Encode())
    } finally {$cert.Dispose()}
}
try {
    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    New-FixtureRecipient $databaseDirectory 'backup'
    New-FixtureRecipient $keyringDirectory 'credential-keyring'
    $keyringArchive=Join-Path $work '20261004T000000Z.keyring.p7m'
    $keyring='{"active_key_id":"synthetic-v1","lookup_key":"synthetic-lookup","encryption_keys":{"synthetic-v1":"synthetic-encryption"}}'
    Protect-Fixture ([Text.Encoding]::UTF8.GetBytes($keyring)) (Join-Path $keyringDirectory 'credential-keyring-recipient.pem') $keyringArchive
    [IO.File]::WriteAllText((Join-Path $payloadDirectory 'database.dump'),'synthetic-database')
    [IO.File]::WriteAllText((Join-Path $payloadDirectory 'redis.rdb'),'synthetic-redis')
    $state=Join-Path $work 'state'
    New-Item -ItemType Directory -Path (Join-Path $state 'data') -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $state '.env'),'SYNTHETIC=fixture')
    & tar -czf (Join-Path $payloadDirectory 'app-state.tgz') -C $state .env data
    if($LASTEXITCODE-ne 0){throw 'Synthetic application archive failed'}
    $manifest=[ordered]@{format='sub2api-keyring-manifest-v1';archive=[IO.Path]::GetFileName($keyringArchive);sha256=(Get-FileHash -LiteralPath $keyringArchive).Hash.ToLowerInvariant()}
    [IO.File]::WriteAllText((Join-Path $payloadDirectory 'keyring-manifest.json'),($manifest|ConvertTo-Json -Compress))
    $names=@('database.dump','redis.rdb','app-state.tgz','keyring-manifest.json')
    $sums=($names|ForEach-Object{(Get-FileHash -LiteralPath (Join-Path $payloadDirectory $_)).Hash.ToLowerInvariant()+'  '+$_})-join "`n"
    [IO.File]::WriteAllText((Join-Path $payloadDirectory 'SHA256SUMS'),$sums+"`n")
    $payload=Join-Path $work 'payload.tgz'
    & tar -czf $payload -C $payloadDirectory @names SHA256SUMS
    if($LASTEXITCODE-ne 0){throw 'Synthetic outer archive failed'}
    $archive=Join-Path $work '20261004T000000Z.p7m'
    Protect-Fixture ([IO.File]::ReadAllBytes($payload)) (Join-Path $databaseDirectory 'backup-recipient.pem') $archive
    $verify=Join-Path $PSScriptRoot 'Test-EncryptedBackup.ps1'
    $common=@('-NoProfile','-NonInteractive','-File',$verify,'-Archive',$archive,'-Directory',$databaseDirectory,'-KeyringDirectory',$keyringDirectory)
    & "$PSHOME/pwsh.exe" @common -KeyringArchive $keyringArchive *> $null
    if($LASTEXITCODE-ne 0){throw 'Correct synthetic pair rejected'}
    $results+='paired-capsules-accepted'
    & "$PSHOME/pwsh.exe" @common *> $null
    if($LASTEXITCODE-eq 0){throw 'Missing keyring capsule accepted'}
    $results+='missing-capsule-rejected'
    [IO.File]::AppendAllText($keyringArchive,'synthetic tamper')
    & "$PSHOME/pwsh.exe" @common -KeyringArchive $keyringArchive *> $null
    if($LASTEXITCODE-eq 0){throw 'Changed capsule accepted'}
    $results+='changed-capsule-rejected'
    [pscustomobject]@{status='passed';checks=$results;realCredentialsUsed=$false}|ConvertTo-Json -Compress
} finally {
    $resolved=[IO.Path]::GetFullPath($work)
    $tmp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    if(!$resolved.StartsWith($tmp,[StringComparison]::OrdinalIgnoreCase)){throw 'Synthetic cleanup escaped temporary storage'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
