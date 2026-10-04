param(
    [string]$IdentityFile = 'D:\Downloads\Chrome\zynexus_shop_tokyo.pem',
    [string]$KnownHostsFile = 'C:\Users\hbq\.ssh\known_hosts',
    [string]$HostAddress = '43.165.175.45',
    [string]$RemoteUser = 'ubuntu',
    [string]$StateDirectory = (Join-Path $PSScriptRoot 'private-backups'),
    [decimal]$HourlyUsageThresholdUSD = 5,
    [int]$LoginFailuresThreshold = 5,
    [int]$CooldownMinutes = 60,
    [ValidateRange(60, 10080)][int]$MinimumWindowMinutes = 65,
    [string]$SampleJson,
    [string]$AlertScript = (Join-Path $PSScriptRoot 'Send-BackupAlert.ps1'),
    [switch]$RecordSample,
    [switch]$NoSend
)

$ErrorActionPreference = 'Stop'
if ($HourlyUsageThresholdUSD -le 0 -or $LoginFailuresThreshold -le 0 -or $CooldownMinutes -le 0) {
    throw 'All monitor thresholds must be positive.'
}

$now = [DateTimeOffset]::UtcNow
$statePath = Join-Path $StateDirectory 'security-monitor-state.json'
$state = @{schemaVersion=2;lastSent=@{};lastSuccessUtc=$null;lastAttemptUtc=$now.ToString('o');lastErrorCategory=$null;notificationStatus='not-needed'}
if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    try {
        $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($previous.schemaVersion -eq 2) {
            if ($previous.lastSuccessUtc) { $state.lastSuccessUtc = [DateTimeOffset]::Parse($previous.lastSuccessUtc).ToString('o') }
            foreach ($entry in $previous.lastSent.PSObject.Properties) {
                if ($entry.Name -in @('UsageSpike','LoginFailures','SecurityQueryFailed','MonitorStale')) {
                    $state.lastSent[$entry.Name] = [DateTimeOffset]::Parse($entry.Value).ToString('o')
                }
            }
        } else {
            foreach ($entry in $previous.PSObject.Properties) {
                if ($entry.Name -in @('UsageSpike','LoginFailures')) {
                    $state.lastSent[$entry.Name] = [DateTimeOffset]::Parse($entry.Value).ToString('o')
                }
            }
        }
    } catch { throw 'Security monitor state is invalid; inspect it locally.' }
}
$windowStart = $now.AddMinutes(-$MinimumWindowMinutes)
$stale = $false
if ($state.lastSuccessUtc) {
    $lastSuccess = [DateTimeOffset]::Parse($state.lastSuccessUtc)
    if ($lastSuccess -gt $now.AddMinutes(5)) { throw 'Security monitor cursor is in the future.' }
    $stale = ($now - $lastSuccess).TotalMinutes -gt 120
    if ($lastSuccess.AddMinutes(-5) -lt $windowStart) { $windowStart = $lastSuccess.AddMinutes(-5) }
}
function Save-MonitorState {
    if ($NoSend -or ($SampleJson -and !$RecordSample)) { return }
    [void][IO.Directory]::CreateDirectory($StateDirectory)
    $pending = "$statePath.incomplete"
    $state | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $pending -Encoding utf8
    Move-Item -LiteralPath $pending -Destination $statePath -Force
}
function Send-MonitorSignal([string]$Reason) {
    if ($NoSend -or ($SampleJson -and !$RecordSample)) { return }
    if ($state.lastSent.ContainsKey($Reason) -and
        ($now - [DateTimeOffset]::Parse($state.lastSent[$Reason])).TotalMinutes -lt $CooldownMinutes) {
        return
    }
    & "$PSHOME\pwsh.exe" -NoProfile -NonInteractive -File $AlertScript -Reason $Reason -Directory $StateDirectory *> $null
    if ($LASTEXITCODE -ne 0) {
        $state.notificationStatus = 'failed'
        $state.lastErrorCategory = 'notification-failed'
        Save-MonitorState
        throw 'Security monitor notification failed; status recorded locally.'
    }
    $state.lastSent[$Reason] = $now.ToString('o')
    $state.notificationStatus = 'sent'
}
$queryFailed = $false
try {
if ($SampleJson) {
    $sample = $SampleJson | ConvertFrom-Json
} else {
    if (!(Test-Path -LiteralPath $IdentityFile -PathType Leaf) -or
        !(Test-Path -LiteralPath $KnownHostsFile -PathType Leaf)) {
        throw 'SSH identity or known-hosts file is missing.'
    }
    $windowLiteral = $windowStart.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
    $endLiteral = $now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
    $sql = @"
BEGIN READ ONLY;
SET LOCAL statement_timeout = '30s';
SELECT json_build_object(
  'hourly_usd', COALESCE((SELECT ROUND(SUM(actual_cost)::numeric, 2)
    FROM usage_logs WHERE created_at > TIMESTAMPTZ '$endLiteral' - INTERVAL '1 hour'
      AND created_at <= TIMESTAMPTZ '$endLiteral'), 0),
  'failed_logins_window', (SELECT COUNT(*) FROM audit_logs
    WHERE created_at > TIMESTAMPTZ '$windowLiteral' AND created_at <= TIMESTAMPTZ '$endLiteral'
      AND action IN ('auth.login', 'auth.login.2fa')
      AND status_code BETWEEN 400 AND 499)
);
ROLLBACK;
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sql))
    $remoteCommand = "printf '%s' '$encoded' | base64 -d | sudo -n docker exec -i -u postgres sub2api-postgres psql -X -v ON_ERROR_STOP=1 -U sub2api -d sub2api -Atq -f -"
    $sshOptions = @(
        '-i', $IdentityFile,
        '-o', "UserKnownHostsFile=$KnownHostsFile",
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=15'
    )
    $raw = & ssh @sshOptions "$RemoteUser@$HostAddress" $remoteCommand 2>$null
    if ($LASTEXITCODE -ne 0 -or !$raw) { throw 'Security signal query failed.' }
    $sample = ($raw -join '') | ConvertFrom-Json
}

$loginFailures = $sample.failed_logins_window
if ($null -eq $loginFailures) { $loginFailures = $sample.failed_logins_15m }
if ($null -eq $sample.hourly_usd -or $null -eq $loginFailures -or
    [decimal]$sample.hourly_usd -lt 0 -or [decimal]$loginFailures -lt 0 -or
    [decimal]$loginFailures -ne [math]::Truncate([decimal]$loginFailures)) {
    throw 'Security signal query returned invalid values.'
}
} catch { $queryFailed = $true }
if ($queryFailed) {
    $state.lastErrorCategory = 'query-failed'
    Save-MonitorState
    Send-MonitorSignal 'SecurityQueryFailed'
    Save-MonitorState
    throw 'Security signal query failed; status recorded locally.'
}

$alerts = @()
if ([decimal]$sample.hourly_usd -ge $HourlyUsageThresholdUSD) { $alerts += 'UsageSpike' }
if ([decimal]$loginFailures -ge $LoginFailuresThreshold) { $alerts += 'LoginFailures' }
if ($stale) { $alerts += 'MonitorStale' }
foreach ($reason in $alerts) {
    Send-MonitorSignal $reason
}
$state.lastSuccessUtc = $now.ToString('o')
Save-MonitorState
Write-Output ([pscustomobject]@{schemaVersion=2;hourly_usd=[decimal]$sample.hourly_usd;
    failed_logins_window=[decimal]$loginFailures;windowStartUtc=$windowStart.ToString('o');
    windowEndUtc=$now.ToString('o');windowMinutes=[math]::Ceiling(($now-$windowStart).TotalMinutes);
    alerts=$alerts;noSend=[bool]$NoSend;heartbeatRecorded=(!$NoSend -and (!$SampleJson -or $RecordSample))} | ConvertTo-Json -Compress)
