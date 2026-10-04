param(
    [string]$Directory = (Join-Path $PSScriptRoot 'private-backups'),
    [switch]$SendTest
)

$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'Windows DPAPI is required for this credential file.' }
$settingsPath = Join-Path $Directory 'mail-settings.json'
if (!(Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw 'Private mail settings are missing.'
}
$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
if ($settings.sender -notmatch '^[^@\s]+@qq\.com$') { throw 'Invalid QQ Mail sender.' }

$code = Read-Host 'Enter QQ Mail SMTP authorization code' -AsSecureString
if ($code.Length -eq 0) { throw 'SMTP authorization code is empty.' }
$credential = [pscredential]::new($settings.sender, $code)
$credentialPath = Join-Path $Directory 'smtp-credential.xml'
$credential | Export-Clixml -LiteralPath $credentialPath
$account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $credentialPath /inheritance:r /grant:r "${account}:F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict SMTP credential file access.' }
Write-Output 'SMTP authorization code saved for the current Windows user.'
if ($SendTest) {
    & $PSHOME\pwsh.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'Send-BackupAlert.ps1') -Reason Test
    if ($LASTEXITCODE -ne 0) { throw 'Test email was not delivered.' }
}
