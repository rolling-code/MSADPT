<#
.SYNOPSIS
Discovers or builds normalized MSADPT report sections and assembles one unified offline HTML report.

.DESCRIPTION
Accepts one or more engagement directories, discovers supported collection evidence, invokes known
offline report-section adapters when normalized sections are missing or explicitly rebuilt, validates
that every selected module is unique, and calls the unified report assembler.

No Active Directory, network, Git, or external service is contacted. Existing collection evidence is
reused. Unknown collection families are reported but are not executed or inferred.

.NOTES
Version: 1.0.9
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$EngagementDirectory,

    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,

    [string]$OutputDirectory,

    [string]$ReportName,

    [ValidateSet('Fail','Newest')]
    [string]$DuplicateModulePolicy = 'Newest',

    [switch]$ForceRebuildSections,
    [switch]$OpenReport,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.14'
function Write-Status {
    param(
        [ValidateSet('INFO','PLAN','DISCOVER','BUILD','VALIDATE','PASS','WARN','REPORT')]
        [string]$State,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($NoColor) {
        Write-Host ('[{0,-8}] {1}' -f $State, $Message)
    }
    else {
        Write-Host ('[{0,-8}] {1}' -f $State, $Message) -ForegroundColor $Color
    }
}

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }

    return [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}

function Test-FileSet {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string[]]$RelativePath
    )

    foreach ($Relative in $RelativePath) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $Relative) -PathType Leaf)) {
            return $false
        }
    }

    return $true
}

function Invoke-OfflineAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Contract,
        [Parameter(Mandatory = $true)][string]$CollectionDirectory
    )

    $AdapterPath = Join-Path $RepositoryRoot ([string]$Contract.AdapterPath)
    if (-not (Test-Path -LiteralPath $AdapterPath -PathType Leaf)) {
        throw ('Adapter not found for {0}: {1}' -f $Contract.ModuleId,$AdapterPath)
    }

    $Tokens = $null
    $ParseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $AdapterPath,
        [ref]$Tokens,
        [ref]$ParseErrors
    )

    if (@($ParseErrors).Count -gt 0) {
        throw "Adapter parser failure [$AdapterPath]: $(@($ParseErrors | ForEach-Object { $_.Message }) -join '; ')"
    }

    Write-Status -State BUILD -Message ("Building {0} from {1}." -f $Contract.ModuleId,$CollectionDirectory) -Color Cyan

    if ($Contract.ModuleId -eq 'Analyze-MSADPTManagedSecretsAndGmsaRetrieval') {
        $CollectionRoot = Split-Path -Parent $CollectionDirectory
        $GmsaDirectory = @(Get-ChildItem -LiteralPath $CollectionRoot -Directory -Filter 'GmsaRetrievalPrincipals-*' -ErrorAction Stop | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
        if (@($GmsaDirectory).Count -ne 1) {
            throw "Sibling gMSA collection not found under: $CollectionRoot"
        }
        $AdapterOutput = & $AdapterPath `
            -ManagedSecretsCollectionDirectory $CollectionDirectory `
            -GmsaCollectionDirectory $GmsaDirectory[0].FullName `
            -RepositoryRoot $RepositoryRoot `
            -Mode Analyze `
            -Profile Standalone `
            -NoColor:$NoColor
    }
    else {
        $AdapterOutput = & $AdapterPath `
            -CollectionDirectory $CollectionDirectory `
            -RepositoryRoot $RepositoryRoot `
            -Mode Analyze `
            -Profile Standalone `
            -NoColor:$NoColor
    }

    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw ('Adapter exited with code {0}: {1}' -f $LASTEXITCODE,$AdapterPath)
    }

    $Result = @($AdapterOutput | Where-Object {
        $_ -is [psobject] -and
        $null -ne $_.PSObject.Properties['ReportSectionJsonPath']
    } | Select-Object -Last 1)

    if (@($Result).Count -ne 1) {
        throw "Adapter did not return one report-section result: $AdapterPath"
    }

    $SectionPath = [string]$Result[0].ReportSectionJsonPath
    if (-not (Test-Path -LiteralPath $SectionPath -PathType Leaf)) {
        throw "Adapter result section was not created: $SectionPath"
    }

    return $SectionPath
}

$RepositoryRoot = Resolve-FullPath -Path $RepositoryRoot
if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "Repository root not found: $RepositoryRoot"
}

$ResolvedEngagementDirectories = @(
    foreach ($Directory in $EngagementDirectory) {
        $Resolved = Resolve-FullPath -Path $Directory
        if (-not (Test-Path -LiteralPath $Resolved -PathType Container)) {
            throw "Engagement directory not found: $Resolved"
        }
        $Resolved
    }
) | Select-Object -Unique

if (@($ResolvedEngagementDirectories).Count -eq 0) {
    throw 'At least one engagement directory is required.'
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $ResolvedEngagementDirectories[0] 'reports'
}
$OutputDirectory = Resolve-FullPath -Path $OutputDirectory
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

if ([string]::IsNullOrWhiteSpace($ReportName)) {
    $ReportName = 'MSADPT-Unified-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
}

$AssemblerPath = Join-Path $RepositoryRoot 'Tools\New-MSADPTUnifiedReport-v1.0.3.ps1'
$ReportingModulePath = Join-Path $RepositoryRoot 'Common\MSADPT.Reporting.psm1'
foreach ($RequiredPath in @($AssemblerPath,$ReportingModulePath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Required reporting component not found: $RequiredPath"
    }
}
Import-Module $ReportingModulePath -Force -ErrorAction Stop

$Contracts = @(
    [pscustomobject][ordered]@{
        ModuleId = 'Analyze-MSADPTManagedSecretsAndGmsaRetrieval'
        Family = 'ManagedSecretsExposure'
        CollectionNamePattern = 'ManagedSecretsExposure-*'
        RequiredRawFiles = @('evidence-manifest.json')
        AdapterPath = 'Modules\ObjectControl\New-MSADPTManagedSecretsAndGmsaReportSection-v1.0.9.ps1'
        SectionRelativePath = 'Analysis\managed-secrets-gmsa-report-section.json'
    }
    [pscustomobject][ordered]@{
        ModuleId = 'Collect-MSADPTAuthenticationPolicySecurity'
        Family = 'AuthenticationPolicySecurity'
        CollectionNamePattern = 'AuthenticationPolicySecurity-*'
        RequiredRawFiles = @(
            'Raw\authentication-policy-context.json'
            'Raw\authentication-policies.json'
            'Raw\authentication-policy-silos.json'
            'Raw\protected-users-membership.json'
            'Raw\operational-errors.json'
        )
        AdapterPath = 'Modules\AuthenticationPolicySecurity\New-MSADPTAuthenticationPolicyReportSection-v1.0.4.ps1'
        SectionRelativePath = 'Analysis\authentication-policy-report-section.json'
    }
    [pscustomobject][ordered]@{
        ModuleId = 'Collect-MSADPTADReplicationTopology'
        Family = 'ADReplicationTopology'
        CollectionNamePattern = 'ADReplicationTopology*'
        RequiredRawFiles = @(
            'Raw\\collection-plan.json'
            'Raw\\domain-controllers.json'
            'Raw\\replication-failures.json'
            'Raw\\operational-errors.json'
        )
        AdapterPath = 'Modules\\ADHealth\\New-MSADPTADReplicationTopologyReportSection-v1.0.1.ps1'
        SectionRelativePath = 'Analysis\\ad-replication-topology-report-section.json'
    }
    [pscustomobject][ordered]@{
        ModuleId = 'Collect-MSADPTADTrustSecurity'
        Family = 'ADTrustSecurity'
        CollectionNamePattern = 'ADTrustSecurity-*'
        RequiredRawFiles = @(
            'Raw\trust-context.json'
            'Raw\ad-trusts.json'
            'Raw\trusted-domain-objects.json'
            'Raw\foreign-security-principals.json'
            'Raw\operational-errors.json'
        )
        AdapterPath = 'Modules\ADTrustSecurity\New-MSADPTADTrustSecurityReportSection-v1.0.1.ps1'
        SectionRelativePath = 'Analysis\ad-trust-security-report-section.json'
    }
)

Write-Status -State INFO -Message "Repository: $RepositoryRoot" -Color Cyan
Write-Status -State INFO -Message "Output: $OutputDirectory" -Color Cyan
Write-Status -State INFO -Message 'Network activity: None; directory changes: None.' -Color Green
Write-Status -State PLAN -Message ("Engagement roots: {0}" -f ($ResolvedEngagementDirectories -join '; ')) -Color Cyan
Write-Status -State PLAN -Message ("Known adapters: {0}" -f (($Contracts.ModuleId) -join ', ')) -Color Cyan

$CollectionCandidates = [Collections.Generic.List[object]]::new()
foreach ($Root in $ResolvedEngagementDirectories) {
    Write-Status -State DISCOVER -Message "Scanning $Root for supported collection evidence." -Color Cyan

    $RawDirectories = @(
        Get-ChildItem -LiteralPath $Root -Directory -Recurse -ErrorAction Stop |
            Where-Object { $_.Name -eq 'Raw' }
    )

    foreach ($RawDirectory in $RawDirectories) {
        $CollectionDirectory = Split-Path -Parent $RawDirectory.FullName
        foreach ($Contract in $Contracts) {
            if (($([IO.Path]::GetFileName($CollectionDirectory)) -like [string]$Contract.CollectionNamePattern) -and (Test-FileSet -Directory $CollectionDirectory -RelativePath $Contract.RequiredRawFiles)) {
                $CollectionCandidates.Add([pscustomobject][ordered]@{
                    ModuleId = [string]$Contract.ModuleId
                    Family = [string]$Contract.Family
                    CollectionDirectory = $CollectionDirectory
                    SectionPath = Join-Path $CollectionDirectory ([string]$Contract.SectionRelativePath)
                    Contract = $Contract
                })
            }
        }
    }
}

$UniqueCandidateKeys = @{}
$UniqueCandidates = [Collections.Generic.List[object]]::new()
foreach ($Candidate in $CollectionCandidates) {
    $Key = '{0}|{1}' -f $Candidate.ModuleId,$Candidate.CollectionDirectory
    if (-not $UniqueCandidateKeys.ContainsKey($Key)) {
        $UniqueCandidateKeys[$Key] = $true
        $UniqueCandidates.Add($Candidate)
    }
}

if (@($UniqueCandidates).Count -eq 0) {
    throw 'No supported collection evidence was discovered under the supplied engagement directories.'
}

Write-Status -State DISCOVER -Message ("Discovered {0} supported collection candidates." -f @($UniqueCandidates).Count) -Color Green

# Select one collection per module before invoking any adapter. This prevents an older or
# incomplete collection from failing the workflow when a newer complete collection exists.
$SelectedCandidates = [Collections.Generic.List[object]]::new()
foreach ($Group in @($UniqueCandidates | Group-Object ModuleId)) {
    if (@($Group.Group).Count -eq 1) {
        $SelectedCandidates.Add($Group.Group[0])
        continue
    }

    if ($DuplicateModulePolicy -eq 'Fail') {
        $DuplicatePaths = @($Group.Group | ForEach-Object { $_.CollectionDirectory }) -join '; '
        throw "Duplicate collection candidates for moduleId '$($Group.Name)'. Paths: $DuplicatePaths"
    }

    $RankedCandidates = @(
        foreach ($Candidate in $Group.Group) {
            $ManifestPath = Join-Path $Candidate.CollectionDirectory 'evidence-manifest.json'
            $ManifestVersion = [version]'0.0'
            $CompletedUtc = [datetime]::MinValue

            if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
                try {
                    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop |
                        ConvertFrom-Json -ErrorAction Stop
                    if ($Manifest.PSObject.Properties['ModuleVersion']) {
                        try { $ManifestVersion = [version][string]$Manifest.ModuleVersion } catch { $ManifestVersion = [version]'0.0' }
                    }
                    if ($Manifest.PSObject.Properties['CompletedUtc']) {
                        try { $CompletedUtc = [datetime][string]$Manifest.CompletedUtc } catch { $CompletedUtc = [datetime]::MinValue }
                    }
                }
                catch {
                    Write-Status -State WARN -Message ("Manifest ranking failed for {0}: {1}" -f $ManifestPath,$_.Exception.Message) -Color Yellow
                }
            }

            $DirectoryVersion = [version]'0.0'
            $DirectoryName = [IO.Path]::GetFileName([string]$Candidate.CollectionDirectory)
            if ($DirectoryName -match '-v(?<version>\d+(?:\.\d+){1,3})$') {
                try { $DirectoryVersion = [version]$Matches.version } catch { $DirectoryVersion = [version]'0.0' }
            }
            [pscustomobject][ordered]@{
                Candidate = $Candidate
                DirectoryVersion = $DirectoryVersion
                ManifestVersion = $ManifestVersion
                CompletedUtc = $CompletedUtc
                CollectionWriteUtc = (Get-Item -LiteralPath $Candidate.CollectionDirectory).LastWriteTimeUtc
            }
        }
    )

    $Selected = @(
        $RankedCandidates |
            Sort-Object `
                @{ Expression = { $_.DirectoryVersion }; Descending = $true }, `
                @{ Expression = { $_.ManifestVersion }; Descending = $true }, `
                @{ Expression = { $_.CompletedUtc }; Descending = $true }, `
                @{ Expression = { $_.CollectionWriteUtc }; Descending = $true }, `
                @{ Expression = { $_.Candidate.CollectionDirectory }; Descending = $true } |
            Select-Object -First 1
    )[0]

    $SelectedCandidates.Add($Selected.Candidate)
    Write-Status -State WARN -Message ("Multiple collections for '{0}': selected {1} (directory version {2}, manifest version {3}, completed {4:o})." -f $Group.Name,$Selected.Candidate.CollectionDirectory,$Selected.DirectoryVersion,$Selected.ManifestVersion,$Selected.CompletedUtc) -Color Yellow
}

Write-Status -State DISCOVER -Message ("Selected {0} collection candidates before adapter execution." -f @($SelectedCandidates).Count) -Color Green

$BuiltSectionPaths = [Collections.Generic.List[string]]::new()
$AdapterActions = [Collections.Generic.List[object]]::new()
foreach ($Candidate in $SelectedCandidates) {
    $SectionExists = Test-Path -LiteralPath $Candidate.SectionPath -PathType Leaf
    $Action = if ($ForceRebuildSections) {
        'Rebuilt'
    }
    elseif ($SectionExists) {
        'Reused'
    }
    else {
        'Built'
    }

    if ($ForceRebuildSections -or -not $SectionExists) {
        $SectionPath = Invoke-OfflineAdapter `
            -Contract $Candidate.Contract `
            -CollectionDirectory $Candidate.CollectionDirectory
    }
    else {
        $SectionPath = $Candidate.SectionPath
        Write-Status -State BUILD -Message ("Reusing {0}." -f $SectionPath) -Color Gray
    }

    $BuiltSectionPaths.Add((Resolve-FullPath -Path $SectionPath))
    $AdapterActions.Add([pscustomobject][ordered]@{
        moduleId = $Candidate.ModuleId
        collectionDirectory = $Candidate.CollectionDirectory
        sectionPath = (Resolve-FullPath -Path $SectionPath)
        action = $Action
    })
}

$SectionRecords = [Collections.Generic.List[object]]::new()
foreach ($Path in $BuiltSectionPaths) {
    $Section = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $Validation = Test-MSADPTReportSection -Section $Section
    if (-not $Validation.valid) {
        throw "Invalid normalized section '$Path': $($Validation.errors -join '; ')"
    }

    $SectionRecords.Add([pscustomobject][ordered]@{
        moduleId = [string]$Section.moduleId
        generatedUtc = [string]$Section.generatedUtc
        path = $Path
    })
}

$SelectedSectionPaths = [Collections.Generic.List[string]]::new()
foreach ($Group in @($SectionRecords | Group-Object moduleId)) {
    if (@($Group).Count -eq 1) {
        $SelectedSectionPaths.Add([string]$Group.Group[0].path)
        continue
    }

    if ($DuplicateModulePolicy -eq 'Fail') {
        $DuplicatePaths = @($Group.Group | ForEach-Object { $_.path }) -join '; '
        throw "Duplicate moduleId '$($Group.Name)' discovered. Use separate engagement roots or -DuplicateModulePolicy Newest. Paths: $DuplicatePaths"
    }

    $Selected = @(
        $Group.Group |
            Sort-Object @{ Expression = {
                try { [datetime]$_.generatedUtc } catch { [datetime]::MinValue }
            }; Descending = $true }, @{ Expression = { $_.path }; Descending = $true } |
            Select-Object -First 1
    )

    $SelectedSectionPaths.Add([string]$Selected[0].path)
    Write-Status -State WARN -Message ("Duplicate moduleId '{0}': selected newest section {1}." -f $Group.Name,$Selected[0].path) -Color Yellow
}

Write-Status -State VALIDATE -Message ("Selected {0} unique normalized sections." -f @($SelectedSectionPaths).Count) -Color Green
Write-Status -State BUILD -Message 'Invoking unified report assembler.' -Color Cyan

$AssemblerOutput = & $AssemblerPath `
    -SectionPath @($SelectedSectionPaths) `
    -OutputDirectory $OutputDirectory `
    -ReportName $ReportName `
    -RepositoryRoot $RepositoryRoot `
    -OpenReport:$OpenReport `
    -NoColor:$NoColor

if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "Unified report assembler exited with code $LASTEXITCODE."
}

$AssemblerResult = @($AssemblerOutput | Where-Object {
    $_ -is [psobject] -and
    $null -ne $_.PSObject.Properties['HtmlReportPath']
} | Select-Object -Last 1)

if (@($AssemblerResult).Count -ne 1) {
    throw 'Unified report assembler did not return one report result.'
}

$RunManifestPath = Join-Path $OutputDirectory (($ReportName -replace '[^A-Za-z0-9._-]','-') + '-build-manifest.json')
$RunManifest = [pscustomobject][ordered]@{
    schemaVersion = '1.0'
    builderVersion = $Version
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    repositoryRoot = $RepositoryRoot
    engagementDirectories = $ResolvedEngagementDirectories
    duplicateModulePolicy = $DuplicateModulePolicy
    forceRebuildSections = [bool]$ForceRebuildSections
    discoveredCollectionCount = @($UniqueCandidates).Count
    selectedCollectionCount = @($SelectedCandidates).Count
    selectedSectionCount = @($SelectedSectionPaths).Count
    adapterActions = @($AdapterActions)
    selectedSectionPaths = @($SelectedSectionPaths)
    unifiedReport = [pscustomobject][ordered]@{
        htmlReportPath = [string]$AssemblerResult[0].HtmlReportPath
        jsonIndexPath = [string]$AssemblerResult[0].JsonIndexPath
        validationPath = [string]$AssemblerResult[0].ValidationPath
        sectionCount = [int]$AssemblerResult[0].SectionCount
        findingCount = [int]$AssemblerResult[0].FindingCount
    }
    networkActivity = 'None'
    directoryChanges = 'None'
}

ConvertTo-Json -InputObject $RunManifest -Depth 16 |
    Set-Content -LiteralPath $RunManifestPath -Encoding UTF8
$null = Get-Content -LiteralPath $RunManifestPath -Raw |
    ConvertFrom-Json -ErrorAction Stop

Write-Status -State PASS -Message ("Report workflow completed: discovered={0}; selectedCollections={1}; sections={2}; findings={3}." -f @($UniqueCandidates).Count,@($SelectedCandidates).Count,$AssemblerResult[0].SectionCount,$AssemblerResult[0].FindingCount) -Color Green
Write-Status -State REPORT -Message ([string]$AssemblerResult[0].HtmlReportPath) -Color Cyan

[pscustomobject][ordered]@{
    Status = 'Completed'
    Version = $Version
    EngagementDirectoryCount = @($ResolvedEngagementDirectories).Count
    DiscoveredCollectionCount = @($UniqueCandidates).Count
    SelectedCollectionCount = @($SelectedCandidates).Count
    SelectedSectionCount = @($SelectedSectionPaths).Count
    SectionCount = [int]$AssemblerResult[0].SectionCount
    FindingCount = [int]$AssemblerResult[0].FindingCount
    CompletedCount = [int]$AssemblerResult[0].CompletedCount
    CompletedWithLimitationsCount = [int]$AssemblerResult[0].CompletedWithLimitationsCount
    FailedCount = [int]$AssemblerResult[0].FailedCount
    HtmlReportPath = [string]$AssemblerResult[0].HtmlReportPath
    JsonIndexPath = [string]$AssemblerResult[0].JsonIndexPath
    ValidationPath = [string]$AssemblerResult[0].ValidationPath
    BuildManifestPath = $RunManifestPath
    NetworkActivity = 'None'
    DirectoryChanges = 'None'
}
