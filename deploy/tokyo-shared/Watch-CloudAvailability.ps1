param([switch]$SyntheticOutage, [switch]$TestNotification,
    [string]$StateFile=(Join-Path $PSScriptRoot 'private-backups/independent-availability-state.json'))
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'CloudAvailability.psm1') -Force
$state=if (Test-Path -LiteralPath $StateFile) {
    Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json -AsHashtable
} else { New-CloudAvailabilityState }
$healthy=$false
if (!$SyntheticOutage) {
    try {
        $reply=Invoke-RestMethod -Uri 'https://api.zynexus.top/health' -TimeoutSec 8 -MaximumRedirection 0
        $healthy=$reply.status -eq 'ok'
    } catch { $healthy=$false }
}
$send={param($reason)
    if ($TestNotification) { $reason+='Test' }
    & $PSHOME\pwsh.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'Send-BackupAlert.ps1') -Reason $reason *> $null
    if ($LASTEXITCODE -ne 0) { throw 'independent-notification-failed' }
}
$state=Update-CloudAvailabilityState -State $state -Healthy $healthy -Notify $send
$pending=$StateFile+'.incomplete'
$state | ConvertTo-Json -Compress | Set-Content -LiteralPath $pending -Encoding utf8
Move-Item -LiteralPath $pending -Destination $StateFile -Force
[pscustomobject]@{healthy=$healthy;failures=$state.failures;alerted=$state.alerted;
    recoveryPending=$state.recoveryPending;notificationError=$state.notificationError;
    syntheticOutage=[bool]$SyntheticOutage;testNotification=[bool]$TestNotification;
    containsSecretValues=$false} | ConvertTo-Json -Compress
if ($state.notificationError) { exit 1 }
