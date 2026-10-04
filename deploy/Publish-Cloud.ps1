param([switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
& $PSHOME\pwsh.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'Assert-LocalRelease.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Local release gate refused cloud promotion.' }
$arguments = @((Join-Path $PSScriptRoot 'publish-cloud-release.mjs'))
if ($CheckOnly) { $arguments += '--check-only' }
& (Get-Command node.exe -ErrorAction Stop).Source @arguments
exit $LASTEXITCODE
