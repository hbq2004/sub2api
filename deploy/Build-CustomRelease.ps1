param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9.-]+$')][string]$Revision,
    [string]$Version = '',
    [switch]$UseLocalProxy
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (!$Version) { $Version = (Get-Content (Join-Path $root 'backend/cmd/server/VERSION') -Raw).Trim() + '-custom' }
if ($Version -notmatch '^[A-Za-z0-9.-]+$') { throw 'Invalid version.' }
$docker = Join-Path $env:LOCALAPPDATA 'Programs/DockerDesktop/resources/bin/docker.exe'
$commit = & git -C $root rev-parse --verify HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the fork base commit.' }
& git -C $root diff --quiet HEAD --
if ($LASTEXITCODE -ne 0) { throw 'Release builds require committed source. Preserve local edits and build from an isolated reviewed branch.' }
$untracked = & git -C $root ls-files --others --exclude-standard
if ($LASTEXITCODE -ne 0 -or $untracked) { throw 'Release builds require a clean source checkout including untracked files.' }
$requiredSources = @(
    'backend/internal/repository/account_credential_protection.go',
    'backend/internal/repository/account_credential_migration.go',
    'backend/internal/pkg/credentialcrypto/protector.go',
    'backend/cmd/credential-migrate/main.go'
)
foreach ($relative in $requiredSources) {
    if (!(Test-Path -LiteralPath (Join-Path $root $relative) -PathType Leaf)) {
        throw "Required credential-protection source is missing: $relative"
    }
}
$image = "sub2api:custom-$Revision"
$date = [DateTime]::UtcNow.ToString('o')
$arguments = @('build', '--platform', 'linux/amd64', '-f', (Join-Path $root 'Dockerfile'),
    '--build-arg', "VERSION=$Version", '--build-arg', "COMMIT=$commit", '--build-arg', "DATE=$date",
    '--label', "org.zynexus.custom-revision=$Revision", '-t', $image)
if ($UseLocalProxy) {
    $arguments += @('--build-arg', 'HTTP_PROXY=http://host.docker.internal:7890',
        '--build-arg', 'HTTPS_PROXY=http://host.docker.internal:7890',
        '--build-arg', 'NODE_USE_ENV_PROXY=1')
}
$arguments += $root
& $docker @arguments
if ($LASTEXITCODE -ne 0) { throw 'Custom image build failed.' }
Write-Output "Built $image. Install and test with Update-Local.ps1 before cloud promotion."
