param(
    [Parameter(Mandatory = $true)][string]$Image,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [switch]$TestOnly
)

$ErrorActionPreference = 'Stop'
$node = (Get-Command node.exe -ErrorAction Stop).Source
$arguments = @((Join-Path $PSScriptRoot 'update-local-release.mjs'),
    '--image', $Image, '--version', $ExpectedVersion)
if ($TestOnly) { $arguments += '--test-only' }
& $node @arguments
exit $LASTEXITCODE
