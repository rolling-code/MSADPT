<#
.SYNOPSIS
Validates the public MSADPT source tree while permitting Git-ignored runtime data.

.DESCRIPTION
Validates required source files, tracked-file safety, PowerShell parsing, registry entry points,
JSON documents, README commands, Git-ignore protections, and organization-specific identifiers.

Git-ignored runtime data such as Engagements and local backup directories are not treated as public
source. The test still fails if forbidden runtime or credential artifacts are tracked by Git.

.NOTES
Version: 1.1.0
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$TestVersion = '1.1.0'
$Failures = New-Object 'System.Collections.Generic.List[object]'

function Add-Failure {
    param(
        [string]$Gate,
        [string]$Detail
    )

    $Failures.Add([pscustomobject][ordered]@{
        Gate = $Gate
        Detail = $Detail
    })
}

function Get-NormalizedGitPath {
    param([string]$Path)
    return $Path.Replace('\', '/').TrimStart('./')
}

if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "RepositoryRootMissing: $RepositoryRoot"
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$GitDirectory = Join-Path $RepositoryRoot '.git'
if (-not (Test-Path -LiteralPath $GitDirectory -PathType Container)) {
    Add-Failure -Gate 'GitRepository' -Detail "Git metadata directory is missing: $GitDirectory"
}

$RequiredFiles = @(
    'README.md',
    '.gitignore',
    'Invoke-MSADPT.ps1',
    'Catalogs\module-registry.json',
    'Catalogs\attack-surface-coverage.json',
    'Schemas\stage-status.schema.json',
    'Tests\Offline\Test-MSADPTPublicRelease.ps1',
    'Tests\Offline\Test-MSADPTQuickAudit.ps1'
)

foreach ($RelativePath in $RequiredFiles) {
    $FullPath = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        Add-Failure -Gate 'RequiredFile' -Detail $RelativePath
    }
}

$TrackedPaths = @()
try {
    $TrackedPaths = @(
        & git -C $RepositoryRoot ls-files |
            ForEach-Object { Get-NormalizedGitPath -Path ([string]$_) }
    )
}
catch {
    Add-Failure -Gate 'GitTrackedFileInventory' -Detail $_.Exception.Message
}

$TrackedLookup = @{}
foreach ($TrackedPath in $TrackedPaths) {
    $TrackedLookup[$TrackedPath.ToLowerInvariant()] = $true
}

$ForbiddenTrackedDirectoryPattern = '(^|/)(Engagements|Sessions|Backups|evidence|evidence-archive|reasoning|state|archive|Generated|Results)(/|$)'
$ForbiddenTrackedExtensionPattern = '(?i)\.(pfx|p12|key|pem|ppk|kdbx|kirbi|ccache)$'
$ForbiddenTrackedNamePattern = '(?i)(^|/)(console-transcript\.txt|session-events\.jsonl|session-state\.json|engagement-state\.json|module-execution-ledger\.json|next-decision\.json|preflight-report\.json)$'

foreach ($TrackedPath in $TrackedPaths) {
    if ($TrackedPath -match $ForbiddenTrackedDirectoryPattern) {
        Add-Failure -Gate 'TrackedRuntimePath' -Detail $TrackedPath
    }
    if ($TrackedPath -match $ForbiddenTrackedExtensionPattern) {
        Add-Failure -Gate 'TrackedSensitiveExtension' -Detail $TrackedPath
    }
    if ($TrackedPath -match $ForbiddenTrackedNamePattern) {
        Add-Failure -Gate 'TrackedRuntimeRecord' -Detail $TrackedPath
    }
}

$GitIgnorePath = Join-Path $RepositoryRoot '.gitignore'
if (Test-Path -LiteralPath $GitIgnorePath -PathType Leaf) {
    $GitIgnore = Get-Content -LiteralPath $GitIgnorePath -Raw
    foreach ($RequiredPattern in @(
        'Engagements/',
        'evidence/',
        '*.pfx',
        '*.p12',
        '*.key',
        '*.kdbx',
        '.quick-audit-backup-*/',
        'module-integration-contracts.json',
        'quick-audit-integration-summary.json'
    )) {
        if ($GitIgnore -notmatch [regex]::Escape($RequiredPattern)) {
            Add-Failure -Gate 'GitIgnore' -Detail $RequiredPattern
        }
    }
}

# Validate PowerShell source that is tracked, plus untracked source files that are not Git-ignored.
$PowerShellFiles = New-Object 'System.Collections.Generic.List[IO.FileInfo]'
foreach ($TrackedPath in $TrackedPaths) {
    if ([IO.Path]::GetExtension($TrackedPath) -notin @('.ps1','.psm1','.psd1')) {
        continue
    }

    $FullPath = Join-Path $RepositoryRoot $TrackedPath
    if (Test-Path -LiteralPath $FullPath -PathType Leaf) {
        $PowerShellFiles.Add((Get-Item -LiteralPath $FullPath))
    }
}

$UntrackedSourcePaths = @(
    & git -C $RepositoryRoot ls-files --others --exclude-standard |
        ForEach-Object { Get-NormalizedGitPath -Path ([string]$_) } |
        Where-Object { [IO.Path]::GetExtension($_) -in @('.ps1','.psm1','.psd1') }
)
foreach ($RelativePath in $UntrackedSourcePaths) {
    $FullPath = Join-Path $RepositoryRoot $RelativePath
    if (Test-Path -LiteralPath $FullPath -PathType Leaf) {
        $PowerShellFiles.Add((Get-Item -LiteralPath $FullPath))
    }
}

$SeenPowerShellFiles = @{}
foreach ($File in [object[]]$PowerShellFiles.ToArray()) {
    $Key = $File.FullName.ToLowerInvariant()
    if ($SeenPowerShellFiles.ContainsKey($Key)) {
        continue
    }
    $SeenPowerShellFiles[$Key] = $true

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

$RegistryPath = Join-Path $RepositoryRoot 'Catalogs\module-registry.json'
if (Test-Path -LiteralPath $RegistryPath -PathType Leaf) {
    try {
        $Registry = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json -ErrorAction Stop
        foreach ($Module in @($Registry.Modules)) {
            $EntryPoint = [string]$Module.EntryPoint
            if ([string]::IsNullOrWhiteSpace($EntryPoint)) {
                Add-Failure -Gate 'RegistryEntryPoint' -Detail ("Entry point missing for module: " + [string]$Module.ModuleId)
                continue
            }

            $EntryPointPath = Join-Path $RepositoryRoot $EntryPoint
            if (-not (Test-Path -LiteralPath $EntryPointPath -PathType Leaf)) {
                Add-Failure -Gate 'RegistryEntryPoint' -Detail $EntryPoint
            }
        }
    }
    catch {
        Add-Failure -Gate 'ModuleRegistry' -Detail $_.Exception.Message
    }
}

foreach ($JsonRelativePath in @(
    'Catalogs\attack-surface-coverage.json',
    'Schemas\stage-status.schema.json'
)) {
    $JsonPath = Join-Path $RepositoryRoot $JsonRelativePath
    if (-not (Test-Path -LiteralPath $JsonPath -PathType Leaf)) {
        continue
    }

    try {
        $null = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Add-Failure -Gate 'JsonDocument' -Detail ($JsonRelativePath + ': ' + $_.Exception.Message)
    }
}

$ReadmePath = Join-Path $RepositoryRoot 'README.md'
if (Test-Path -LiteralPath $ReadmePath -PathType Leaf) {
    $Readme = Get-Content -LiteralPath $ReadmePath -Raw
    foreach ($ReadmeCommand in @(
        'Invoke-MSADPT.ps1',
        'Test-MSADPTPublicRelease.ps1',
        'Test-MSADPTQuickAudit.ps1'
    )) {
        if ($Readme -notmatch [regex]::Escape($ReadmeCommand)) {
            Add-Failure -Gate 'ReadmeCommand' -Detail $ReadmeCommand
        }
    }
}

# The validator intentionally constructs blocked-value detection fragments.
# Exclude this validator from its own sanitization scan.
$CurrentTestPath = (Resolve-Path -LiteralPath $PSCommandPath).Path
$SourceTextPaths = New-Object 'System.Collections.Generic.List[string]'
foreach ($TrackedPath in $TrackedPaths) {
    $Extension = [IO.Path]::GetExtension($TrackedPath)
    if ($Extension -in @('.ps1','.psm1','.psd1','.json','.md','.txt','.csv') -or [IO.Path]::GetFileName($TrackedPath) -eq '.gitignore') {
        $SourceTextPaths.Add($TrackedPath)
    }
}
foreach ($RelativePath in @(
    & git -C $RepositoryRoot ls-files --others --exclude-standard |
        ForEach-Object { Get-NormalizedGitPath -Path ([string]$_) }
)) {
    $Extension = [IO.Path]::GetExtension($RelativePath)
    if ($Extension -in @('.ps1','.psm1','.psd1','.json','.md','.txt','.csv') -or [IO.Path]::GetFileName($RelativePath) -eq '.gitignore') {
        $SourceTextPaths.Add($RelativePath)
    }
}

$BlockedFragments = @(
    ('Mar' + 'io' + '\s+' + 'Contesta' + 'bile'),
    ('m' + 'contestabile'),
    ('DELL' + '-3S0K184'),
    ('aim' + 'fire\.net'),
    ('scrap' + 'metal\.net'),
    ('aimrg' + '(?:-my)?\.sharepoint\.com'),
    ('American' + '\s+' + 'Iron')
)
$BlockedPattern = '(?i)' + ($BlockedFragments -join '|')
$SeenTextPaths = @{}

foreach ($RelativePath in [object[]]$SourceTextPaths.ToArray()) {
    $FullPath = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        continue
    }
    if ((Resolve-Path -LiteralPath $FullPath).Path -eq $CurrentTestPath) {
        continue
    }

    $Key = $FullPath.ToLowerInvariant()
    if ($SeenTextPaths.ContainsKey($Key)) {
        continue
    }
    $SeenTextPaths[$Key] = $true

    $Text = Get-Content -LiteralPath $FullPath -Raw
    if ($Text -match $BlockedPattern) {
        Add-Failure -Gate 'Sanitization' -Detail $FullPath
    }
}

$FailureRows = [object[]]$Failures.ToArray()
[pscustomobject][ordered]@{
    TestVersion = $TestVersion
    Status = if ($FailureRows.Count -eq 0) { 'Passed' } else { 'Failed' }
    RepositoryRoot = $RepositoryRoot
    TrackedFileCount = $TrackedPaths.Count
    ParsedPowerShellFileCount = $SeenPowerShellFiles.Count
    FailureCount = $FailureRows.Count
    Failures = $FailureRows
    RuntimeDirectoriesAllowedWhenIgnored = $true
    ReadyForGit = ($FailureRows.Count -eq 0)
}