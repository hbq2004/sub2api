param(
    [string]$Root = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'
$required = @(
    'backend/internal/repository/account_credential_protection.go',
    'backend/internal/repository/account_credential_migration.go',
    'backend/internal/pkg/credentialcrypto/protector.go',
    'backend/cmd/credential-migrate/main.go'
)
$missing = @($required | Where-Object { !(Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf) })
if ($missing.Count) { throw ('Required release source is missing: ' + ($missing -join ', ')) }

$revision = (& git -C $Root rev-parse --verify HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
    throw 'A verifiable Git source revision is required for a release.'
}
& git -C $Root diff --quiet HEAD --
if ($LASTEXITCODE -ne 0) { throw 'Release source has uncommitted changes.' }
$untracked = & git -C $Root ls-files --others --exclude-standard
if ($LASTEXITCODE -ne 0 -or $untracked) { throw 'Release source contains untracked files.' }

[pscustomobject]@{
    sourceRevision = $revision
    requiredSources = $required
    dirtyWorktreeAllowed = $false
} | ConvertTo-Json -Compress
