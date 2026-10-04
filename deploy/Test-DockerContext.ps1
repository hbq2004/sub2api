param(
    [string]$Docker = 'docker'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('sub2api-docker-context-' + [guid]::NewGuid().ToString('N'))
$output = Join-Path $fixture 'output'
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $root '.dockerignore') -Destination (Join-Path $fixture '.dockerignore')
    Set-Content -LiteralPath (Join-Path $fixture 'Dockerfile.context') -Value @('FROM scratch', 'COPY . /probe') -Encoding ascii
    $safe = Join-Path $fixture 'backend/src'
    $secretA = Join-Path $fixture 'deploy/private-credentials'
    $secretB = Join-Path $fixture 'private-credentials'
    $secretC = Join-Path $fixture 'deploy/tokyo-shared/private-backups'
    New-Item -ItemType Directory -Path $safe,$secretA,$secretB,$secretC -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $safe 'fixture.go') -Value 'package fixture' -Encoding ascii
    Set-Content -LiteralPath (Join-Path $secretA 'fixture.env') -Value 'SYNTHETIC=fixture' -Encoding ascii
    Set-Content -LiteralPath (Join-Path $secretB 'local-runtime.env') -Value 'SYNTHETIC=fixture' -Encoding ascii
    Set-Content -LiteralPath (Join-Path $secretC 'fixture.pem') -Value 'SYNTHETIC=fixture' -Encoding ascii

    & $Docker buildx build --file (Join-Path $fixture 'Dockerfile.context') --output ("type=local,dest={0}" -f $output) $fixture *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic Docker context build failed.' }
    if (!(Test-Path -LiteralPath (Join-Path $output 'probe/backend/src/fixture.go'))) {
        throw 'A safe source fixture was unexpectedly excluded.'
    }
    $forbidden = @(
        'probe/deploy/private-credentials/fixture.env',
        'probe/private-credentials/local-runtime.env',
        'probe/deploy/tokyo-shared/private-backups/fixture.pem'
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $output $_) }
    if ($forbidden.Count) { throw ('Secret-shaped files entered the Docker context: ' + ($forbidden -join ', ')) }
    Write-Output 'Synthetic Docker context gate passed.'
}
finally {
    $resolved = [IO.Path]::GetFullPath($fixture)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (!$resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture cleanup escaped temporary storage.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
