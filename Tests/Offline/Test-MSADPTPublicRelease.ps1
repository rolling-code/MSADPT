[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Failures = New-Object 'System.Collections.Generic.List[object]'

function Add-Failure {
    param([string]$Gate,[string]$Detail)
    $Failures.Add([pscustomobject]@{
        Gate = $Gate
        Detail = $Detail
    })
}

$RequiredFiles = @(
    'README.md',
    '.gitignore',
    'Invoke-MSADPT.ps1',
    'Catalogs\module-registry.json',
    'Catalogs\attack-surface-coverage.json',
    'Schemas\stage-status.schema.json',
    'Tests\Offline\Test-MSADPTPublicRelease.ps1'
)

foreach ($RelativePath in $RequiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot $RelativePath) -PathType Leaf)) {
        Add-Failure -Gate 'RequiredFile' -Detail $RelativePath
    }
}

$ForbiddenDirectories = @(
    'Engagements','Sessions','Backups','evidence','evidence-archive',
    'reasoning','state','archive','Generated','Results'
)
foreach ($Directory in @(Get-ChildItem -LiteralPath $RepositoryRoot -Directory -Recurse)) {
    if ($Directory.Name -in $ForbiddenDirectories) {
        Add-Failure -Gate 'ForbiddenDirectory' -Detail $Directory.FullName
    }
}

$PowerShellFiles = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -File -Recurse |
        Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') }
)
foreach ($File in $PowerShellFiles) {
    $Tokens = $null
    $ParseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $File.FullName,
        [ref]$Tokens,
        [ref]$ParseErrors
    )

    foreach ($ParseError in [object[]]@($ParseErrors)) {
        Add-Failure -Gate 'PowerShellParse' -Detail ($File.FullName + ': ' + $ParseError.Message)
    }
}

try {
    $Registry = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Catalogs\module-registry.json') -Raw |
        ConvertFrom-Json -ErrorAction Stop

    foreach ($Module in @($Registry.Modules)) {
        $EntryPoint = [string]$Module.EntryPoint
        if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot $EntryPoint) -PathType Leaf)) {
            Add-Failure -Gate 'RegistryEntryPoint' -Detail $EntryPoint
        }
    }
}
catch {
    Add-Failure -Gate 'ModuleRegistry' -Detail $_.Exception.Message
}

foreach ($JsonRelativePath in @(
    'Catalogs\attack-surface-coverage.json',
    'Schemas\stage-status.schema.json'
)) {
    try {
        $null = Get-Content -LiteralPath (Join-Path $RepositoryRoot $JsonRelativePath) -Raw |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Add-Failure -Gate 'JsonDocument' -Detail ($JsonRelativePath + ': ' + $_.Exception.Message)
    }
}

$GitIgnore = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.gitignore') -Raw
foreach ($RequiredPattern in @(
    'Engagements/',
    'evidence/',
    '*.pfx',
    '*.p12',
    '*.key',
    '*.kdbx'
)) {
    if ($GitIgnore -notmatch [regex]::Escape($RequiredPattern)) {
        Add-Failure -Gate 'GitIgnore' -Detail $RequiredPattern
    }
}

$Readme = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'README.md') -Raw
foreach ($ReadmeCommand in @(
    'Invoke-MSADPT.ps1',
    'Test-MSADPTPublicRelease.ps1'
)) {
    if ($Readme -notmatch [regex]::Escape($ReadmeCommand)) {
        Add-Failure -Gate 'ReadmeCommand' -Detail $ReadmeCommand
    }
}

# The release test intentionally defines blocked-value detection fragments.
# Exclude this file from its own content scan to prevent self-detection.
$ThisTestPath = (Resolve-Path -LiteralPath $PSCommandPath).Path
$TextFiles = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -File -Recurse |
        Where-Object {
            $_.FullName -ne $ThisTestPath -and
            (
                $_.Extension -in @('.ps1','.psm1','.psd1','.json','.md','.txt','.csv') -or
                $_.Name -eq '.gitignore'
            )
        }
)

$BlockedFragments = @(
    ('Mario' + '\s+' + 'Contestabile'),
    ('m' + 'contestabile'),
    ('DELL' + '-3S0K184'),
    ('aim' + 'fire\.net'),
    ('scrap' + 'metal\.net'),
    ('aimrg' + '(?:-my)?\.sharepoint\.com'),
    ('American' + '\s+' + 'Iron')
)
$BlockedPattern = '(?i)' + ($BlockedFragments -join '|')

foreach ($File in $TextFiles) {
    $Text = Get-Content -LiteralPath $File.FullName -Raw
    if ($Text -match $BlockedPattern) {
        Add-Failure -Gate 'Sanitization' -Detail $File.FullName
    }
}

$FailureRows = [object[]]$Failures.ToArray()
[pscustomobject]@{
    Status = if ($FailureRows.Count -eq 0) { 'Passed' } else { 'Failed' }
    RepositoryRoot = $RepositoryRoot
    FailureCount = $FailureRows.Count
    Failures = $FailureRows
    ReadyForGit = ($FailureRows.Count -eq 0)
}