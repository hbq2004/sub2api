param(
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups'),
    [int]$MaxAgeHours = 1,
    [switch]$RequireTodayAfterSixThirty
)

$ErrorActionPreference = 'Stop'
$markerPath = Join-Path $Directory 'last-verified.json'
if (!(Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    throw 'No verified backup status marker exists.'
}
$marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json -DateKind String
if ($marker.archive -notmatch '^\d{8}T\d{6}Z\.p7m$' -or $marker.sha256 -notmatch '^[0-9a-f]{64}$' -or
    $marker.keyringArchive -notmatch '^\d{8}T\d{6}Z\.keyring\.p7m$' -or
    $marker.keyringSha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Verified backup status marker is invalid.'
}
$verifiedAt = [DateTimeOffset]::Parse($marker.verifiedAtUtc)
if ($RequireTodayAfterSixThirty -and $verifiedAt.LocalDateTime -lt [DateTime]::Today.AddHours(6.5)) {
    throw 'No verified backup was completed after the daily download time.'
}
if (([DateTimeOffset]::UtcNow - $verifiedAt).TotalHours -gt $MaxAgeHours) {
    throw 'Last verified backup is stale.'
}
$archive = Join-Path $Directory $marker.archive
if ($marker.archive -notmatch '^\d{8}T\d{6}Z\.p7m$') { throw 'Backup timestamp is invalid.' }
$snapshotUtc = [DateTimeOffset]::ParseExact(
    ($marker.archive -replace '\.p7m$', ''), "yyyyMMdd'T'HHmmss'Z'", [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal)
if (([DateTimeOffset]::UtcNow - $snapshotUtc).TotalHours -gt $MaxAgeHours) {
    throw 'Backup snapshot is stale; a recent verification cannot replace fresh data.'
}
if (!(Test-Path -LiteralPath $archive -PathType Leaf)) { throw 'Last verified archive is missing.' }
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine $marker.sha256) {
    throw 'Last verified archive hash changed.'
}
$keyringArchive = Join-Path $Directory $marker.keyringArchive
if (!(Test-Path -LiteralPath $keyringArchive -PathType Leaf)) { throw 'Last verified keyring archive is missing.' }
if ((Get-FileHash -LiteralPath $keyringArchive -Algorithm SHA256).Hash -ine $marker.keyringSha256) {
    throw 'Last verified keyring archive hash changed.'
}
Write-Output "Backup verified: $($marker.archive) at $($verifiedAt.ToUniversalTime().ToString('u'))"
