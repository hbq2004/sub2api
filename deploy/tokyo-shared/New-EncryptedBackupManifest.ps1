param(
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups'),
    [string]$Output = (Join-Path $Directory 'encrypted-backup-manifest.json')
)

$ErrorActionPreference = 'Stop'
$entries = @(Get-ChildItem -LiteralPath $Directory -File -Filter '*.p7m' | Sort-Object Name | ForEach-Object {
    $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
    [pscustomobject]@{
        name = $_.Name
        bytes = $_.Length
        sha256 = $hash.Hash.ToLowerInvariant()
        modifiedUtc = $_.LastWriteTimeUtc.ToString('o')
    }
})
if ($entries.Count -eq 0) { throw 'No encrypted backup archives found.' }
$document = [pscustomobject]@{
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    containsSecretValues = $false
    archives = $entries
}
$pending = "$Output.incomplete"
$document | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $pending -Encoding utf8
Move-Item -LiteralPath $pending -Destination $Output -Force
Write-Output "Encrypted backup manifest created: $Output ($($entries.Count) archives)"
