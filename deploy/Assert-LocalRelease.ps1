param([string]$ImageID = '')

$ErrorActionPreference = 'Stop'
$receipt = Get-Content -LiteralPath (Join-Path $PSScriptRoot '.local-release.json') -Raw | ConvertFrom-Json
if (!$receipt.passed -or $receipt.imageID -notmatch '^sha256:[a-f0-9]{64}$') {
    throw 'No successfully tested local release exists. Run Update-Local.ps1.'
}
if ($ImageID -and $receipt.imageID -ne $ImageID) { throw 'This image has not passed local installation and regression.' }
$docker = Join-Path $env:LOCALAPPDATA 'Programs/DockerDesktop/resources/bin/docker.exe'
$actual = & $docker inspect sub2api --format '{{.Image}}'
if ($LASTEXITCODE -ne 0 -or $actual.Trim() -ne $receipt.imageID) {
    throw 'The local running container differs from the tested release.'
}
$label = & $docker image inspect $receipt.imageID --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
if ($LASTEXITCODE -ne 0 -or $label.Trim() -notmatch '^[0-9a-f]{40}$') {
    throw 'The tested image is missing an immutable source revision label.'
}
$health = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 5
$settings = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/v1/settings/public' -TimeoutSec 5
if ($health.status -ne 'ok' -or $settings.data.version -ne $receipt.version) {
    throw 'The local application is not healthy on the tested version.'
}
$report = Get-Content -LiteralPath $receipt.reportPath -Raw | ConvertFrom-Json
if (!$report.passed -or $report.imageID -ne $receipt.imageID -or $report.sourceRevision -ne $label.Trim() -or
    $report.protection.accounts -ne $report.protection.encrypted_accounts -or
    $report.protection.redeem_codes -ne $report.protection.protected_codes) {
    throw 'Local schema, encryption or regression acceptance is missing.'
}
Write-Output "Local release gate passed: $($receipt.version) $($receipt.imageID)"
