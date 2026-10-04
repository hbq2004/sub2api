param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Test', 'DailyCheckFailed', 'UsageSpike', 'LoginFailures', 'SecurityQueryFailed', 'MonitorStale', 'HostUnavailable', 'HostRecovered', 'HostUnavailableTest', 'HostRecoveredTest')]
    [string]$Reason,
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups')
)

$ErrorActionPreference = 'Stop'
$settingsPath = Join-Path $Directory 'mail-settings.json'
$credentialPath = Join-Path $Directory 'smtp-credential.xml'
if (!(Test-Path -LiteralPath $settingsPath -PathType Leaf) -or
    !(Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
    throw 'SMTP settings or authorization code are not configured.'
}
$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
if ($settings.sender -notmatch '^[^@\s]+@qq\.com$' -or
    $settings.recipient -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    throw 'Mail settings contain an invalid address.'
}
$credential = Import-Clixml -LiteralPath $credentialPath
if ($credential -isnot [pscredential] -or $credential.UserName -ne $settings.sender) {
    throw 'SMTP credential does not match the configured sender.'
}

$labels = @{
    HostUnavailable = 'independent observer cannot reach the cloud API after three consecutive checks'
    HostRecovered = 'independent observer confirms cloud API recovery'
    HostUnavailableTest = 'TEST: independent outage notification; production was not interrupted'
    HostRecoveredTest = 'TEST: independent recovery notification; production was not interrupted'
    Test = 'SMTP test'
    DailyCheckFailed = 'daily encrypted backup download or verification failed'
    UsageSpike = 'hourly API usage exceeded the alert threshold'
    LoginFailures = 'recent login failures exceeded the alert threshold'
    SecurityQueryFailed = 'security signal query failed; inspect monitor heartbeat and SSH access'
    MonitorStale = 'security monitoring resumed after more than two hours without a successful poll'
}
$message = [System.Net.Mail.MailMessage]::new()
$client = [System.Net.Mail.SmtpClient]::new('smtp.qq.com', 587)
try {
    $message.From = [System.Net.Mail.MailAddress]::new($settings.sender)
    [void]$message.To.Add($settings.recipient)
    $prefix = if ($Reason -eq 'DailyCheckFailed') { 'Sub2API backup alert' } else { 'Sub2API alert' }
    $message.Subject = "${prefix}: $($labels[$Reason])"
    $message.Body = "Sub2API monitor: $($labels[$Reason]). Check the administrator usage and audit views. For backup alerts, also check both Windows scheduled tasks and the encrypted backup directory. Time: $([DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz'))."
    $client.EnableSsl = $true
    $client.UseDefaultCredentials = $false
    $client.Credentials = $credential.GetNetworkCredential()
    $client.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
    $client.Timeout = 15000
    try { $client.Send($message) }
    catch {
        $category = $_.Exception.GetType().Name
        if ($_.Exception -is [System.Net.Mail.SmtpException]) {
            $category += " status=$($_.Exception.StatusCode)"
        }
        if ($_.Exception.InnerException) {
            $category += " inner=$($_.Exception.InnerException.GetType().Name)"
        }
        throw "QQ Mail SMTP delivery failed ($category); check SMTP service and authorization locally."
    }
    Write-Output "SMTP alert sent: $Reason"
}
finally {
    $message.Dispose()
    $client.Dispose()
}
