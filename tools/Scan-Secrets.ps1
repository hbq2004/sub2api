param(
    [ValidateSet('staged', 'history')]
    [string]$Mode = 'staged',
    [string]$Gitleaks = 'gitleaks',
    [string]$Repo = (Join-Path $PSScriptRoot '..')
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $Repo).Path
$template = Join-Path $PSScriptRoot 'gitleaks-location.tmpl'
$config = Join-Path $PSScriptRoot '..\.gitleaks.toml'

if (!(Get-Command $Gitleaks -ErrorAction SilentlyContinue) -and !(Test-Path -LiteralPath $Gitleaks)) {
    throw 'Gitleaks was not found. Pass the path to the verified local executable with -Gitleaks.'
}
if ($Mode -eq 'history' -and (& git -C $repo rev-parse --is-shallow-repository) -eq 'true') {
    throw 'History is shallow; full-history scan cannot be claimed.'
}

Push-Location $repo
try {
    $arguments = @(
        'git', '--no-banner', '--no-color', '--log-level', 'error', '--redact=100',
        '--ignore-gitleaks-allow', '--gitleaks-ignore-path', 'NUL',
        '--config', $config, '--report-format', 'template',
        '--report-template', $template, '--report-path', '-', '--timeout', '120'
    )
    if ($Mode -eq 'staged') { $arguments += '--staged' }
    else { $arguments += '--log-opts=--all --full-history' }
    $arguments += '.'

    $oldGitEnvironment = @{
        Global = $env:GIT_CONFIG_GLOBAL
        Count = $env:GIT_CONFIG_COUNT
        Key0 = $env:GIT_CONFIG_KEY_0
        Value0 = $env:GIT_CONFIG_VALUE_0
        Key1 = $env:GIT_CONFIG_KEY_1
        Value1 = $env:GIT_CONFIG_VALUE_1
    }
    $env:GIT_CONFIG_GLOBAL = '/dev/null'
    $env:GIT_CONFIG_COUNT = '2'
    $env:GIT_CONFIG_KEY_0 = 'core.excludesfile'
    $env:GIT_CONFIG_VALUE_0 = '/dev/null'
    $env:GIT_CONFIG_KEY_1 = 'safe.directory'
    $env:GIT_CONFIG_VALUE_1 = $repo
    try { $findings = & $Gitleaks @arguments }
    finally {
        $env:GIT_CONFIG_GLOBAL = $oldGitEnvironment.Global
        $env:GIT_CONFIG_COUNT = $oldGitEnvironment.Count
        $env:GIT_CONFIG_KEY_0 = $oldGitEnvironment.Key0
        $env:GIT_CONFIG_VALUE_0 = $oldGitEnvironment.Value0
        $env:GIT_CONFIG_KEY_1 = $oldGitEnvironment.Key1
        $env:GIT_CONFIG_VALUE_1 = $oldGitEnvironment.Value1
    }
    $scanExit = $LASTEXITCODE
    if ($scanExit -notin @(0, 1)) { throw "Gitleaks failed with exit code $scanExit." }

    $count = 0
    foreach ($line in $findings) {
        if ($line -match '^([^|\r\n]+)\|([^|\r\n]+)\|(\d+)\|([^|\r\n]*)$') {
            $count++
            Write-Output ("{0}|{1}|{2}|{3}" -f $Matches[1], $Matches[2], $Matches[3], $Matches[4])
        } elseif ($line.Trim()) {
            throw 'Gitleaks output did not match the location-only report format.'
        }
    }
    [Console]::Error.WriteLine("Secret scan mode=$Mode findings=$count (locations only)")
    if ($scanExit -eq 1 -and $count -eq 0) {
        throw 'Gitleaks reported findings without usable location metadata.'
    }
    exit $scanExit
} finally {
    Pop-Location
}
