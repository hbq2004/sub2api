param(
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups')
)

$ErrorActionPreference = 'Stop'
& $PSHOME\pwsh.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'Check-BackupStatus.ps1') -Directory $Directory -MaxAgeHours 1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    try {
        & $PSHOME\pwsh.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'Send-BackupAlert.ps1') -Reason DailyCheckFailed | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SMTP alert delivery failed.' }
    }
    catch { throw 'Backup check failed and email delivery was unavailable.' }
    throw 'Daily backup download or archive verification failed.'
}
Write-Output 'Backup download and archive verification are healthy.'
