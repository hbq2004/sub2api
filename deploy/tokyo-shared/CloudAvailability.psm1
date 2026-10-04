function New-CloudAvailabilityState {
    @{ failures=0; alerted=$false; recoveryPending=$false; lastAttemptUtc=$null;
       lastSuccessUtc=$null; lastNotificationUtc=$null; lastNotification=$null;
       notificationError=$false; containsSecretValues=$false }
}

function Update-CloudAvailabilityState {
    param([hashtable]$State, [bool]$Healthy, [scriptblock]$Notify,
        [DateTimeOffset]$Now=[DateTimeOffset]::UtcNow, [int]$FailureThreshold=3)
    $State.lastAttemptUtc=$Now.ToString('o')
    $State.notificationError=$false
    $reason=$null
    if ($Healthy) {
        $State.failures=0
        $State.lastSuccessUtc=$Now.ToString('o')
        if ($State.alerted -or $State.recoveryPending) { $reason='HostRecovered'; $State.recoveryPending=$true }
    } else {
        $State.failures=[int]$State.failures+1
        $reminderDue=(!$State.lastNotificationUtc -or ($Now-[DateTimeOffset]::Parse($State.lastNotificationUtc)).TotalMinutes -ge 60)
        if ($State.failures -ge $FailureThreshold -and (!$State.alerted -or $reminderDue)) { $reason='HostUnavailable' }
    }
    if ($reason) {
        try {
            & $Notify $reason | Out-Null
            $State.lastNotification=$reason
            $State.lastNotificationUtc=$Now.ToString('o')
            if ($reason -eq 'HostUnavailable') { $State.alerted=$true }
            else { $State.alerted=$false; $State.recoveryPending=$false }
        } catch { $State.notificationError=$true }
    }
    $State
}

Export-ModuleMember -Function New-CloudAvailabilityState,Update-CloudAvailabilityState
