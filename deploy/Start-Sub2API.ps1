param(
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$deployDirectory = $PSScriptRoot
$composeFile = Join-Path $deployDirectory 'docker-compose.local.yml'
$composeSyncFile = Join-Path $deployDirectory 'docker-compose.local-sync.yml'
$siteUrl = 'http://127.0.0.1:8080/'
$healthUrl = 'http://127.0.0.1:8080/health'
$syncHealthUrl = 'http://127.0.0.1:8769/health'
$syncScript = Join-Path $deployDirectory 'local-cloud-sync-server.mjs'

function Test-Sub2APIHealth {
    try {
        $response = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 3
        return $response.status -eq 'ok'
    }
    catch {
        return $false
    }
}

function Test-LocalCloudSyncHealth {
    try {
        $response = Invoke-RestMethod -Uri $syncHealthUrl -TimeoutSec 3
        return $response.status -eq 'ok' -and $response.service -eq 'sub2api-local-cloud-sync'
    }
    catch {
        return $false
    }
}

function Test-DockerEngine([string]$dockerCli) {
    try {
        # A stopped daemon writes to stderr. That is an expected probe result,
        # even when the launcher uses Stop for real errors.
        $ErrorActionPreference = 'Continue'
        & $dockerCli info --format '{{.ServerVersion}}' 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Show-LaunchError([string]$message) {
    Write-Error $message -ErrorAction Continue
    $shell = New-Object -ComObject WScript.Shell
    [void]$shell.Popup($message, 0, 'Sub2API 启动失败', 16)
}

try {
    if (-not (Test-Sub2APIHealth)) {
        $dockerCli = @(
            (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'),
            (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe')
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $dockerCli) {
            $dockerCli = (Get-Command docker.exe -ErrorAction SilentlyContinue).Source
        }
        if (-not $dockerCli) {
            throw '找不到 Docker 命令。请先安装 Docker Desktop。'
        }

        if (-not (Test-DockerEngine $dockerCli)) {
            $dockerDesktop = @(
                (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'),
                (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe')
            ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            if (-not $dockerDesktop) {
                throw 'Docker 引擎未运行，且找不到 Docker Desktop。'
            }
            if (-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)) {
                Start-Process -FilePath $dockerDesktop -WindowStyle Hidden
            }
            $deadline = (Get-Date).AddMinutes(3)
            do {
                Start-Sleep -Seconds 3
                $engineReady = Test-DockerEngine $dockerCli
            } until ($engineReady -or (Get-Date) -ge $deadline)
            if (-not $engineReady) {
                throw '等待 Docker Desktop 启动超时。请检查 Docker Desktop 是否正常运行。'
            }
        }

        Push-Location $deployDirectory
        try {
            & $dockerCli compose -f $composeFile -f $composeSyncFile up -d
            if ($LASTEXITCODE -ne 0) {
                throw 'Docker Compose 启动失败。请检查 Docker Desktop 和部署配置。'
            }
        }
        finally {
            Pop-Location
        }

        $deadline = (Get-Date).AddMinutes(2)
        while (-not (Test-Sub2APIHealth) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
        }
        if (-not (Test-Sub2APIHealth)) {
            throw 'Sub2API 在两分钟内未通过健康检查。请检查容器日志。'
        }
    }

    if (-not (Test-LocalCloudSyncHealth)) {
        $nodeCli = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
        if (-not $nodeCli) {
            throw '找不到 Node.js。云端同步按钮需要 Node.js 20 或更高版本。'
        }
        Start-Process -FilePath $nodeCli -ArgumentList ('"{0}"' -f $syncScript) -WorkingDirectory (Split-Path $deployDirectory -Parent) -WindowStyle Hidden
        $syncDeadline = (Get-Date).AddSeconds(15)
        while (-not (Test-LocalCloudSyncHealth) -and (Get-Date) -lt $syncDeadline) {
            Start-Sleep -Milliseconds 500
        }
        if (-not (Test-LocalCloudSyncHealth)) {
            throw '本地云端同步服务未能启动。请检查端口 8769 和 Node.js。'
        }
    }

    if (-not $NoBrowser) {
        Start-Process $siteUrl
    }
}
catch {
    Show-LaunchError $_.Exception.Message
    exit 1
}
