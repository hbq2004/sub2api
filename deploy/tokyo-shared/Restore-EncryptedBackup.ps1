param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups'),
    [string]$Docker = (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'),
    [string]$AppImage = '',
    [string]$KeyringArchive = '',
    [string]$CredentialKeyring = '',
    [switch]$TestApplication,
    [switch]$TestPasskeys,
    [switch]$AllowLegacyWithoutKeyring
)

$ErrorActionPreference = 'Stop'
$postgresImage = 'postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873'
$redisImage = 'redis@sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0'
$id = [guid]::NewGuid().ToString('N')
$postgres = "sub2api-restore-pg-$id"
$redis = "sub2api-restore-redis-$id"
$application = "sub2api-restore-app-$id"
$network = "sub2api-restore-net-$id"
$work = Join-Path $Directory "restore-$id"
$started = @()
$networkCreated = $false

if (!(Test-Path -LiteralPath $Docker -PathType Leaf)) { throw 'Docker CLI is missing.' }
if (!(Test-Path -LiteralPath $Archive -PathType Leaf)) { throw 'Encrypted archive is missing.' }
if ($TestPasskeys -and !$TestApplication) { throw 'Passkey configuration requires an application restore test.' }
if ($TestApplication -and [string]::IsNullOrWhiteSpace($AppImage)) {
    throw 'Application restore requires an explicitly selected compatible image.'
}
if ([string]::IsNullOrWhiteSpace($KeyringArchive) -and !$AllowLegacyWithoutKeyring) {
    throw 'Restore requires the separately encrypted keyring archive for this database backup.'
}
if ($TestApplication -and [string]::IsNullOrWhiteSpace($CredentialKeyring)) {
    throw 'Protected application restore requires a separately recovered plaintext keyring path.'
}
if ($TestApplication -and !(Test-Path -LiteralPath $CredentialKeyring -PathType Leaf)) {
    throw 'The recovered credential keyring path does not exist.'
}
$legacyArgs = @()
if ($AllowLegacyWithoutKeyring) { $legacyArgs = @('-AllowLegacyWithoutKeyring') }
& $PSHOME\pwsh.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'Test-EncryptedBackup.ps1') -Archive $Archive -KeyringArchive $KeyringArchive @legacyArgs -Directory $Directory | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Archive verification failed.' }

New-Item -ItemType Directory -Path $work | Out-Null
try {
    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
        (Join-Path $Directory 'backup-recipient.pem'),
        (Join-Path $Directory 'backup-private-key.pem')
    )
    try {
        $cms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
        $cms.Decode([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Archive)))
        $recipients = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        [void]$recipients.Add($certificate)
        $cms.Decrypt($recipients)
        [System.IO.File]::WriteAllBytes((Join-Path $work 'payload.tgz'), $cms.ContentInfo.Content)
    }
    finally { $certificate.Dispose() }

    $recoveryInputs = @('database.dump', 'redis.rdb')
    if ($TestApplication) { $recoveryInputs += 'app-state.tgz' }
    & tar -xzf (Join-Path $work 'payload.tgz') -C $work @recoveryInputs
    if ($LASTEXITCODE -ne 0) { throw 'Cannot extract recovery inputs.' }

    $networkArgs = @('--network', 'none')
    if ($TestApplication) {
        & $Docker network create --internal $network | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot create isolated recovery network.' }
        $networkCreated = $true
        $networkArgs = @('--network', $network)
    }

    & $Docker run -d --rm --name $postgres @networkArgs --tmpfs '/var/lib/postgresql:rw,size=512m' -v "${work}:/restore:ro" -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=sub2api $postgresImage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot start isolated PostgreSQL.' }
    $started += $postgres
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & $Docker exec $postgres pg_isready -U postgres -d sub2api *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (!$ready) { throw 'Isolated PostgreSQL did not become ready.' }
    & $Docker exec $postgres pg_restore -U postgres -d sub2api --no-owner --no-privileges --exit-on-error /restore/database.dump *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Database restore failed.' }
    $tables = & $Docker exec $postgres psql -U postgres -d sub2api -Atqc "select count(*) from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE'"
    if ($LASTEXITCODE -ne 0 -or [int]$tables -lt 1) { throw 'Restored database has no public tables.' }
    if ($TestApplication) {
        $credentialEnvelopes = & $Docker exec $postgres psql -U postgres -d sub2api -Atqc `
            "select count(*) from accounts where credentials ? '__sub2api_credentials'"
        if ($LASTEXITCODE -ne 0 -or $credentialEnvelopes -notmatch '^\d+$') {
            throw 'Cannot verify restored upstream credential format.'
        }
        if ([int]$credentialEnvelopes -gt 0 -and [string]::IsNullOrWhiteSpace($CredentialKeyring)) {
            throw 'Protected upstream credentials require a credential-aware restore with the independently recovered keyring and pinned image. Use the cloud credential rollout recovery procedure.'
        }
    }
    if ($TestPasskeys) {
        & $Docker exec $postgres psql -U postgres -d sub2api -Atqc `
            "insert into settings (key, value) values ('passkey_enabled', 'true') on conflict (key) do update set value = excluded.value" *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot enable Passkeys in the isolated database.' }
    }

    & $Docker run -d --rm --name $redis @networkArgs --tmpfs '/data:rw,size=128m' -v "${work}:/restore:ro" $redisImage redis-server --dir /restore --dbfilename redis.rdb --save '' --appendonly no *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot start isolated Redis.' }
    $started += $redis
    $redisReady = $false
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        & $Docker exec $redis redis-cli ping *> $null
        if ($LASTEXITCODE -eq 0) { $redisReady = $true; break }
        Start-Sleep -Seconds 1
    }
    if (!$redisReady) { throw 'Isolated Redis did not become ready.' }
    $keys = & $Docker exec $redis redis-cli DBSIZE
    if ($LASTEXITCODE -ne 0 -or $keys -notmatch '^\d+$') { throw 'Redis restored data could not be counted.' }

    if ($TestApplication) {
        $state = Join-Path $work 'app-state'
        New-Item -ItemType Directory -Path $state | Out-Null
        $stateArchive = Join-Path $work 'app-state.tgz'
        $stateEntries = @(& tar -tzf $stateArchive)
        if ($LASTEXITCODE -ne 0 -or @($stateEntries | Where-Object {
            $_ -notmatch '^(\./)?(\.env|data(/.*)?)$'
        }).Count -ne 0) { throw 'Application state archive contains unexpected paths.' }
        & tar -xzf $stateArchive -C $state
        if ($LASTEXITCODE -ne 0) { throw 'Cannot extract application state.' }
        $envFile = Join-Path $state '.env'
        $data = Join-Path $state 'data'
        if (!(Test-Path -LiteralPath $envFile -PathType Leaf) -or
            !(Test-Path -LiteralPath $data -PathType Container)) {
            throw 'Application state is missing environment or data.'
        }
        $passkeyArgs = @()
        if ($TestPasskeys) {
            $passkeyArgs = @('-e', 'WEBAUTHN_ENABLED=true', '-e', 'WEBAUTHN_RP_ID=api.zynexus.top',
                '-e', 'WEBAUTHN_RP_ORIGINS=https://api.zynexus.top')
        }
        $keyringArgs = @('-e', 'ACCOUNT_CREDENTIAL_KEYRING_FILE=/run/secrets/upstream-credential-keyring.json',
            '-e', 'ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED=true', '-e', 'ACCOUNT_CREDENTIAL_ALLOW_LEGACY=false',
            '-v', "${CredentialKeyring}:/run/secrets/upstream-credential-keyring.json:ro")
        & $Docker run -d --rm --name $application @networkArgs --env-file $envFile @passkeyArgs @keyringArgs `
            -v "${data}:/app/data" -e AUTO_SETUP=true -e SERVER_HOST=0.0.0.0 `
            -e SERVER_PORT=8080 -e DATABASE_HOST=$postgres -e DATABASE_USER=postgres `
            -e DATABASE_DBNAME=sub2api -e DATABASE_PASSWORD=restore-test `
            -e DATABASE_SSLMODE=disable -e REDIS_HOST=$redis -e REDIS_PASSWORD= `
            $AppImage | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot start isolated Sub2API.' }
        $started += $application
        $appReady = $false
        for ($attempt = 0; $attempt -lt 45; $attempt++) {
            & $Docker exec $redis wget -q -O /dev/null "http://${application}:8080/health" *> $null
            if ($LASTEXITCODE -eq 0) { $appReady = $true; break }
            Start-Sleep -Seconds 1
        }
        if (!$appReady) { throw 'Isolated Sub2API did not pass its health check.' }
        if ($TestPasskeys) {
            $probe = & $Docker exec $redis wget -S -O /dev/null `
                --header='Content-Type: application/json' --post-data='{}' `
                "http://${application}:8080/api/v1/auth/passkey/login/begin" 2>&1
            $httpStatus = [regex]::Matches(($probe -join "`n"), 'HTTP/\d(?:\.\d)? (\d{3})')
            $status = if ($httpStatus.Count) { $httpStatus[$httpStatus.Count - 1].Groups[1].Value } else { 'unknown' }
            if ($LASTEXITCODE -ne 0 -or $status -ne '200') {
                throw "Isolated Passkey begin-login returned HTTP $status."
            }
        }
    }

    if ($TestApplication) {
        Write-Output "Isolated application restore passed: PostgreSQL tables=$tables, Redis keys=$keys, Sub2API health=ok, Passkey begin-login=$([bool]$TestPasskeys)"
        return
    }
    Write-Output "Isolated restore passed: PostgreSQL tables=$tables, Redis keys=$keys"
}
finally {
    for ($i = $started.Count - 1; $i -ge 0; $i--) { & $Docker rm -f $started[$i] *> $null }
    if ($networkCreated) { & $Docker network rm $network *> $null }
    if (Test-Path -LiteralPath $work) {
        $resolvedWork = [IO.Path]::GetFullPath($work)
        $resolvedDirectory = [IO.Path]::GetFullPath($Directory).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (!$resolvedWork.StartsWith($resolvedDirectory, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Restore cleanup target escaped the private staging directory.'
        }
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force
    }
}
