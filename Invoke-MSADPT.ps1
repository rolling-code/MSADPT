<#
.SYNOPSIS
Runs or plans an MSADPT assessment.

.DESCRIPTION
The Quick profile provides the first operational read-only audit workflow. It performs local
preflight, announces the live Active Directory query plan, collects a Kerberos/SPN baseline,
collects domain-controller directory metadata using the selected bootstrap DC, updates normalized
stage state and coverage, and writes a consolidated HTML report.

Resume mode reuses completed, manifest-backed evidence and does not repeat completed collectors.
No Kerberos tickets are requested. No passwords are collected. No directory or remote system is
modified.

.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Plan','Audit','Analyze','Resume')]
    [string]$Mode,

    [ValidateSet('Quick')]
    [string]$Profile = 'Quick',

    [string]$EngagementDirectory,
    [string]$Server,
    [PSCredential]$Credential,
    [switch]$NoColor,
    [switch]$ForceRerun,
    [switch]$IncludePatchState,
    [switch]$RetryIncompletePatchTargets
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$OrchestratorVersion = '1.0.0'
$Root = $PSScriptRoot

function Show {
    param(
        [string]$State,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $Text = '[{0,-12}] {1}' -f $State,$Message
    if ($NoColor) { Write-Host $Text }
    else { Write-Host $Text -ForegroundColor $Color }
}

function Write-JsonDocument {
    param(
        [string]$Path,
        [object]$Value,
        [int]$Depth = 30
    )

    $Parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $Parent -Force | Out-Null

    if ($Value -is [System.Array] -and @($Value).Count -eq 0) {
        [IO.File]::WriteAllText(
            $Path,
            "[]`r`n",
            (New-Object Text.UTF8Encoding($false))
        )
    }
    else {
        $Value |
            ConvertTo-Json -Depth $Depth |
            Set-Content -LiteralPath $Path -Encoding UTF8
    }

    $null = Get-Content -LiteralPath $Path -Raw |
        ConvertFrom-Json -ErrorAction Stop
}

function Get-SafeProperty {
    param([object]$Object,[string]$Name,[object]$Default = $null)

    if ($null -eq $Object) { return $Default }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $Default }
    return $Property.Value
}

function New-StageStatus {
    param(
        [string]$ModuleId,
        [string]$ModuleVersion,
        [string]$Disposition = 'NotStarted'
    )

    return [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        ModuleId = $ModuleId
        ModuleVersion = $ModuleVersion
        Disposition = $Disposition
        StartedUtc = $null
        CompletedUtc = $null
        Stages = [pscustomobject][ordered]@{
            PlanningSucceeded = $null
            DiscoverySucceeded = $null
            NetworkOperationSucceeded = $null
            AcquisitionSucceeded = $null
            ParsingSucceeded = $null
            SemanticAnalysisSucceeded = $null
            BehavioralValidationSucceeded = $null
            ImpactReproduced = $null
            CleanupAttempted = $null
            CleanupVerified = $null
            EvidenceWritten = $null
            ManifestVerified = $null
        }
        Result = $null
        Error = $null
    }
}

function Test-Manifest {
    param([string]$ManifestPath,[string]$BaseDirectory)

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $false }
    try {
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ([string](Get-SafeProperty $Manifest 'Status') -ne 'Completed') { return $false }
        foreach ($FileRecord in @((Get-SafeProperty $Manifest 'Files' @()))) {
            $Name = [string](Get-SafeProperty $FileRecord 'Name')
            if ([string]::IsNullOrWhiteSpace($Name)) { continue }
            $Candidate = Join-Path $BaseDirectory $Name
            if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) { return $false }
            $ExpectedHash = [string](Get-SafeProperty $FileRecord 'SHA256')
            if (-not [string]::IsNullOrWhiteSpace($ExpectedHash)) {
                $ActualHash = (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash
                if ($ActualHash -ne $ExpectedHash) { return $false }
            }
        }
        return $true
    }
    catch {
        return $false
    }
}

function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

$RegistryPath = Join-Path $Root 'Catalogs\module-registry.json'
$CoverageCatalogPath = Join-Path $Root 'Catalogs\attack-surface-coverage.json'
$Registry = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json -ErrorAction Stop
$CoverageCatalog = Get-Content -LiteralPath $CoverageCatalogPath -Raw | ConvertFrom-Json -ErrorAction Stop
$Integrated = @($Registry.Modules | Where-Object { $_.OrchestrationState -eq 'Integrated' })
$Standalone = @($Registry.Modules | Where-Object { $_.OrchestrationState -eq 'AvailableStandalone' })

$QuickModuleIds = @(
    'Invoke-MSADPTKerberosSPNBaselineCollection',
    'Complete-MSADPTKerberosSPNBaseline',
    'Invoke-MSADPTDomainControllerEnumeration'
)
$QuickModules = @($Registry.Modules | Where-Object { $_.ModuleId -in $QuickModuleIds })

Show -State 'START' -Message "MSADPT v$OrchestratorVersion mode=$Mode profile=$Profile" -Color Cyan
Show -State 'SAFETY' -Message 'Quick Audit performs read-only AD queries only. No ticket request, password collection, remote execution, or directory change.' -Color Yellow

if ($Mode -eq 'Plan') {
    Show -State 'PREFLIGHT' -Message 'Local checks: PowerShell, ActiveDirectory module, registry, catalog, and writeable engagement path.' -Color DarkCyan
    Show -State 'NETWORK' -Message 'Targets: current AD domain and one writable DC selected by AD discovery or -Server.' -Color DarkCyan
    Show -State 'PROTOCOLS' -Message 'ADWS/LDAP through the ActiveDirectory module using the current identity or -Credential.' -Color DarkCyan
    Show -State 'MODULES' -Message ($QuickModuleIds -join ', ') -Color DarkCyan
    Show -State 'CHANGES' -Message 'Remote changes=None; local changes=engagement evidence, state, and HTML report.' -Color DarkCyan
    if ($IncludePatchState) {
        Show -State 'PATCHPLAN' -Message 'After DC inventory: Remote Registry over SMB/RPC (TCP 445, 135, dynamic RPC); CIM fallback over WSMan (TCP 5985/5986).' -Color Magenta
        Show -State 'PATCHSAFE' -Message 'Patch stage is read-only; service starts=None; registry writes=None; patch installation=None; restart=None.' -Color Magenta
    }
    [pscustomobject][ordered]@{
        Status = 'Passed'
        Mode = 'Plan'
        Profile = $Profile
        RegistryModuleCount = [int]$Registry.ModuleCount
        IntegratedModuleCount = $Integrated.Count
        StandaloneModuleCount = $Standalone.Count
        QuickModuleCount = $QuickModules.Count
        AttackFamilyCount = @($CoverageCatalog.Families).Count
        LiveModulesExecuted = 0
    }
    return
}

if ([string]::IsNullOrWhiteSpace($EngagementDirectory)) {
    $EngagementDirectory = Join-Path $Root ('Engagements\MSADPT-Quick-Audit-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
elseif (-not [IO.Path]::IsPathRooted($EngagementDirectory)) {
    $EngagementDirectory = Join-Path $Root $EngagementDirectory
}
$EngagementDirectory = [IO.Path]::GetFullPath($EngagementDirectory)
foreach ($Name in @('evidence','analysis','reports','state','errors')) {
    New-Item -ItemType Directory -Path (Join-Path $EngagementDirectory $Name) -Force | Out-Null
}

$LedgerPath = Join-Path $EngagementDirectory 'state\coverage-ledger.json'
$ExecutionPlanPath = Join-Path $EngagementDirectory 'state\execution-plan.json'
$EngagementStatePath = Join-Path $EngagementDirectory 'state\engagement-state.json'
$StageDirectory = Join-Path $EngagementDirectory 'state\stages'
New-Item -ItemType Directory -Path $StageDirectory -Force | Out-Null

$Preflight = [pscustomobject][ordered]@{
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    PowerShellEdition = [string]$PSVersionTable.PSEdition
    ActiveDirectoryModuleAvailable = ($null -ne (Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1))
    RepositoryRoot = $Root
    EngagementDirectory = $EngagementDirectory
    RegistryLoaded = ($null -ne $Registry)
    CoverageCatalogLoaded = ($null -ne $CoverageCatalog)
}

if (-not $Preflight.ActiveDirectoryModuleAvailable -and $Mode -in @('Audit','Resume')) {
    throw 'PreflightFailed: ActiveDirectory PowerShell module is unavailable.'
}

$Plan = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Mode = $Mode
    Profile = $Profile
    IncludePatchState = [bool]$IncludePatchState
    CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Server = if ([string]::IsNullOrWhiteSpace($Server)) { 'AutoDiscoverWritableDomainController' } else { $Server }
    Authentication = if ($null -eq $Credential) { 'CurrentWindowsIdentity' } else { 'SuppliedPSCredential' }
    NetworkOperations = @(
        [pscustomobject]@{Module='KerberosSPNBaselineCollection';Target='Current domain and selected writable DC';Protocol='ADWS/LDAP';Ports='Environment-defined AD service ports';Operation='Read-only AD user, computer, domain, forest, and DC queries'},
        [pscustomobject]@{Module='DomainControllerEnumeration';Target='Selected bootstrap DC';Protocol='ADWS/LDAP';Ports='Environment-defined AD service ports';Operation='Read-only domain-controller and computer-object metadata queries'}
    )
    RemoteChanges = 'None'
    TicketRequests = 'None'
    PasswordMaterial = 'None'
    LocalChanges = @('Create engagement directories','Write JSON and CSV evidence','Write stage records','Write consolidated HTML report')
}
Write-JsonDocument -Path $ExecutionPlanPath -Value $Plan

Show -State 'IDENTITY' -Message "Identity=$($Plan.CurrentIdentity)" -Color DarkCyan
Show -State 'NETWORK' -Message 'Kerberos baseline: current domain plus selected writable DC over ADWS/LDAP.' -Color Magenta
Show -State 'NETWORK' -Message 'DC inventory: selected bootstrap DC over ADWS/LDAP.' -Color Magenta
Show -State 'CHANGES' -Message 'Remote changes=None; ticket requests=None; password material=None.' -Color Magenta

if ($Mode -eq 'Analyze') {
    Show -State 'ANALYZE' -Message 'Analyze mode processes existing Quick Audit evidence only.' -Color Yellow
}

$KerberosDirectory = Join-Path $EngagementDirectory 'evidence\KerberosSPNBaseline'
$KerberosManifest = Join-Path $KerberosDirectory 'evidence-manifest.json'
$KerberosSummary = Join-Path $KerberosDirectory 'kerberos-spn-baseline-summary.json'
$DcEvidenceDirectory = Join-Path $EngagementDirectory 'evidence\DomainControllerEnumeration'
$DcJson = Join-Path $DcEvidenceDirectory 'domain-controller-details.json'

$KerberosStagePath = Join-Path $StageDirectory 'kerberos-spn-baseline.json'
$DcStagePath = Join-Path $StageDirectory 'domain-controller-enumeration.json'
$PatchStateDirectory = Join-Path $EngagementDirectory 'evidence\DomainControllerPatchState'
$PatchStateManifest = Join-Path $PatchStateDirectory 'evidence-manifest.json'
$PatchStateSummary = Join-Path $PatchStateDirectory 'patch-state-summary.json'
$PatchStateApplicability = Join-Path $PatchStateDirectory 'ad-vulnerability-applicability.json'
$PatchStagePath = Join-Path $StageDirectory 'domain-controller-patch-state.json'
$PatchReused = $false
$PatchExecuted = $false
$PatchResult = $null
$Errors = New-Object 'System.Collections.Generic.List[object]'
$LiveModulesExecuted = 0
$SkippedModules = 0
$BootstrapServer = $Server
$KerberosResult = $null
$DcResult = $null

$KerberosComplete = (
    -not $ForceRerun -and
    (Test-Path -LiteralPath $KerberosSummary -PathType Leaf) -and
    (Test-Manifest -ManifestPath $KerberosManifest -BaseDirectory $KerberosDirectory)
)

if ($Mode -eq 'Analyze' -and -not $KerberosComplete) {
    throw 'AnalyzeModeEvidenceMissing: completed Kerberos baseline evidence was not found.'
}

if ($KerberosComplete) {
    $SkippedModules++
    $KerberosSummaryObject = Get-Content -LiteralPath $KerberosSummary -Raw | ConvertFrom-Json -ErrorAction Stop
    $SummaryServer = [string](Get-SafeProperty (Get-SafeProperty $KerberosSummaryObject 'Domain') 'Server')
    if (-not [string]::IsNullOrWhiteSpace($SummaryServer)) {
        $BootstrapServer = $SummaryServer
    }
    $KerberosStage = New-StageStatus -ModuleId 'Invoke-MSADPTKerberosSPNBaselineCollection' -ModuleVersion '0.1.1' -Disposition 'Collected'
    $KerberosStage.Stages.PlanningSucceeded = $true
    $KerberosStage.Stages.AcquisitionSucceeded = $true
    $KerberosStage.Stages.ParsingSucceeded = $true
    $KerberosStage.Stages.SemanticAnalysisSucceeded = $true
    $KerberosStage.Stages.EvidenceWritten = $true
    $KerberosStage.Stages.ManifestVerified = $true
    $KerberosStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $KerberosStage.Result = $KerberosSummaryObject.Counts
    Write-JsonDocument -Path $KerberosStagePath -Value $KerberosStage
    Show -State 'REUSE' -Message 'Kerberos/SPN baseline evidence and manifest verified. Collection skipped.' -Color Green
}
elseif ($Mode -in @('Audit','Resume')) {
    $KerberosStage = New-StageStatus -ModuleId 'Invoke-MSADPTKerberosSPNBaselineCollection' -ModuleVersion '0.1.1' -Disposition 'Planned'
    $KerberosStage.StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $KerberosStage.Stages.PlanningSucceeded = $true
    Write-JsonDocument -Path $KerberosStagePath -Value $KerberosStage

    try {
        if (Test-Path -LiteralPath $KerberosDirectory) {
            $Existing = @(Get-ChildItem -LiteralPath $KerberosDirectory -Force -ErrorAction SilentlyContinue)
            if ($Existing.Count -gt 0) {
                $Archive = $KerberosDirectory + '.superseded-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
                Move-Item -LiteralPath $KerberosDirectory -Destination $Archive
            }
        }
        New-Item -ItemType Directory -Path $KerberosDirectory -Force | Out-Null

        $CollectorPath = Join-Path $Root 'Modules\Kerberos\Invoke-MSADPTKerberosSPNBaselineCollection-v0.1.1.ps1'
        $CollectorParams = @{
            OutputDirectory = $KerberosDirectory
            NoColor = $NoColor
        }
        if (-not [string]::IsNullOrWhiteSpace($Server)) { $CollectorParams.Server = $Server }
        if ($null -ne $Credential) { $CollectorParams.Credential = $Credential }

        Show -State 'RUN' -Message 'Running read-only Kerberos/SPN baseline collection.' -Color Yellow
        $KerberosResult = & $CollectorPath @CollectorParams
        $LiveModulesExecuted++
        $BootstrapServer = [string](Get-SafeProperty $KerberosResult 'DomainController')

        $ManifestValid = Test-Manifest -ManifestPath $KerberosManifest -BaseDirectory $KerberosDirectory
        $KerberosStage.Disposition = if ($ManifestValid) { 'Collected' } else { 'Inconclusive' }
        $KerberosStage.Stages.DiscoverySucceeded = $true
        $KerberosStage.Stages.NetworkOperationSucceeded = $true
        $KerberosStage.Stages.AcquisitionSucceeded = $true
        $KerberosStage.Stages.ParsingSucceeded = $true
        $KerberosStage.Stages.SemanticAnalysisSucceeded = $true
        $KerberosStage.Stages.BehavioralValidationSucceeded = $false
        $KerberosStage.Stages.ImpactReproduced = $false
        $KerberosStage.Stages.EvidenceWritten = $true
        $KerberosStage.Stages.ManifestVerified = $ManifestValid
        $KerberosStage.Result = $KerberosResult
        $KerberosStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Write-JsonDocument -Path $KerberosStagePath -Value $KerberosStage
    }
    catch {
        $CollectorError = $_.Exception.Message
        $CoreEvidence = @(
            'kerberos-directory-objects.json',
            'kerberos-directory-objects.csv',
            'spn-inventory.json',
            'spn-inventory.csv'
        )
        $CanComplete = @($CoreEvidence | Where-Object { Test-Path -LiteralPath (Join-Path $KerberosDirectory $_) -PathType Leaf }).Count -eq $CoreEvidence.Count

        if ($CanComplete) {
            try {
                Show -State 'RECOVER' -Message 'Core Kerberos evidence exists. Running local completion without repeating AD collection.' -Color Yellow
                $CompletionPath = Join-Path $Root 'Modules\Kerberos\Complete-MSADPTKerberosSPNBaseline-v0.1.2.ps1'
                $KerberosResult = & $CompletionPath -OutputDirectory $KerberosDirectory -NoColor:$NoColor
                $ManifestValid = Test-Manifest -ManifestPath $KerberosManifest -BaseDirectory $KerberosDirectory
                $KerberosStage.Disposition = if ($ManifestValid) { 'Collected' } else { 'Inconclusive' }
                $KerberosStage.Stages.NetworkOperationSucceeded = $true
                $KerberosStage.Stages.AcquisitionSucceeded = $true
                $KerberosStage.Stages.ParsingSucceeded = $true
                $KerberosStage.Stages.SemanticAnalysisSucceeded = $true
                $KerberosStage.Stages.EvidenceWritten = $true
                $KerberosStage.Stages.ManifestVerified = $ManifestValid
                $KerberosStage.Result = $KerberosResult
                $KerberosStage.Error = "Collector post-processing failed and was recovered locally: $CollectorError"
                $KerberosStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                Write-JsonDocument -Path $KerberosStagePath -Value $KerberosStage
            }
            catch {
                $KerberosStage.Disposition = 'Failed'
                $KerberosStage.Error = $_.Exception.Message
                $KerberosStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                Write-JsonDocument -Path $KerberosStagePath -Value $KerberosStage
                $Errors.Add([pscustomobject]@{Module='KerberosSPNBaseline';Stage='CollectionAndCompletion';Error=$_.Exception.Message})
            }
        }
        else {
            $KerberosStage.Disposition = 'Failed'
            $KerberosStage.Error = $CollectorError
            $KerberosStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Write-JsonDocument -Path $KerberosStagePath -Value $KerberosStage
            $Errors.Add([pscustomobject]@{Module='KerberosSPNBaseline';Stage='Collection';Error=$CollectorError})
        }
    }
}

if ([string]::IsNullOrWhiteSpace($BootstrapServer) -and (Test-Path -LiteralPath $KerberosSummary)) {
    $SummaryObject = Get-Content -LiteralPath $KerberosSummary -Raw | ConvertFrom-Json
    $SummaryServer = [string](Get-SafeProperty (Get-SafeProperty $SummaryObject 'Domain') 'Server')
    if (-not [string]::IsNullOrWhiteSpace($SummaryServer)) {
        $BootstrapServer = $SummaryServer
    }
}

$EngagementState = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    EngagementDirectory = $EngagementDirectory
    Profile = $Profile
    BootstrapServer = $BootstrapServer
    UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
}
Write-JsonDocument -Path $EngagementStatePath -Value $EngagementState

$DcComplete = (-not $ForceRerun -and (Test-Path -LiteralPath $DcJson -PathType Leaf))
if ($DcComplete) {
    $SkippedModules++
    $DcRows = @(Get-Content -LiteralPath $DcJson -Raw | ConvertFrom-Json)
    $DcStage = New-StageStatus -ModuleId 'Invoke-MSADPTDomainControllerEnumeration' -ModuleVersion 'unversioned' -Disposition 'Collected'
    $DcStage.Stages.PlanningSucceeded = $true
    $DcStage.Stages.AcquisitionSucceeded = $true
    $DcStage.Stages.ParsingSucceeded = $true
    $DcStage.Stages.SemanticAnalysisSucceeded = $true
    $DcStage.Stages.EvidenceWritten = $true
    $DcStage.Stages.ManifestVerified = $false
    $DcStage.Result = [pscustomobject]@{TargetCount=$DcRows.Count;EvidencePath=$DcJson}
    $DcStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Write-JsonDocument -Path $DcStagePath -Value $DcStage
    Show -State 'REUSE' -Message 'Domain-controller evidence exists. Collection skipped.' -Color Green
}
elseif ($Mode -in @('Audit','Resume') -and -not [string]::IsNullOrWhiteSpace($BootstrapServer)) {
    $DcStage = New-StageStatus -ModuleId 'Invoke-MSADPTDomainControllerEnumeration' -ModuleVersion 'unversioned' -Disposition 'Planned'
    $DcStage.StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $DcStage.Stages.PlanningSucceeded = $true
    Write-JsonDocument -Path $DcStagePath -Value $DcStage

    try {
        Show -State 'RUN' -Message "Collecting read-only DC metadata through $BootstrapServer." -Color Yellow
        $DcCollectorPath = Join-Path $Root 'Modules\DomainControllers\Invoke-MSADPTDomainControllerEnumeration.ps1'
        $DcParams = @{EngagementPath=$EngagementDirectory}
        if ($null -ne $Credential) { $DcParams.Credential = $Credential }
        $DcResult = & $DcCollectorPath @DcParams
        $LiveModulesExecuted++

        $DcStage.Disposition = 'Collected'
        $DcStage.Stages.DiscoverySucceeded = $true
        $DcStage.Stages.NetworkOperationSucceeded = $true
        $DcStage.Stages.AcquisitionSucceeded = $true
        $DcStage.Stages.ParsingSucceeded = $true
        $DcStage.Stages.SemanticAnalysisSucceeded = $true
        $DcStage.Stages.BehavioralValidationSucceeded = $false
        $DcStage.Stages.ImpactReproduced = $false
        $DcStage.Stages.EvidenceWritten = (Test-Path -LiteralPath $DcJson)
        $DcStage.Stages.ManifestVerified = $false
        $DcStage.Result = $DcResult
        $DcStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Write-JsonDocument -Path $DcStagePath -Value $DcStage
    }
    catch {
        $DcStage.Disposition = 'Failed'
        $DcStage.Error = $_.Exception.Message
        $DcStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Write-JsonDocument -Path $DcStagePath -Value $DcStage
        $Errors.Add([pscustomobject]@{Module='DomainControllerEnumeration';Stage='Collection';Error=$_.Exception.Message})
    }
}
elseif ($Mode -in @('Audit','Resume')) {
    $Errors.Add([pscustomobject]@{Module='DomainControllerEnumeration';Stage='Planning';Error='Bootstrap server unavailable because Kerberos discovery did not complete.'})
}

# PATCH-STAGE-BEGIN
if ($IncludePatchState) {
    $PatchComplete = (
        -not $ForceRerun -and
        (Test-Path -LiteralPath $PatchStateSummary -PathType Leaf) -and
        (Test-Path -LiteralPath $PatchStateApplicability -PathType Leaf) -and
        (Test-Manifest -ManifestPath $PatchStateManifest -BaseDirectory $PatchStateDirectory)
    )

    if ($PatchComplete -and -not $RetryIncompletePatchTargets) {
        $SkippedModules++
        $PatchReused = $true
        $PatchSummaryObject = Get-Content -LiteralPath $PatchStateSummary -Raw | ConvertFrom-Json -ErrorAction Stop
        $PatchStage = New-StageStatus -ModuleId 'Invoke-MSADPTDomainControllerPatchState' -ModuleVersion '0.1.0' -Disposition 'Collected'
        $PatchStage.Stages.PlanningSucceeded = $true
        $PatchStage.Stages.AcquisitionSucceeded = $true
        $PatchStage.Stages.ParsingSucceeded = $true
        $PatchStage.Stages.SemanticAnalysisSucceeded = $true
        $PatchStage.Stages.EvidenceWritten = $true
        $PatchStage.Stages.ManifestVerified = $true
        $PatchStage.Result = $PatchSummaryObject
        $PatchStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Write-JsonDocument -Path $PatchStagePath -Value $PatchStage
        Show -State 'REUSE' -Message 'Domain-controller patch-state evidence and manifest verified. Collection skipped.' -Color Green
    }
    elseif ($Mode -in @('Audit','Resume') -and (Test-Path -LiteralPath $DcJson -PathType Leaf)) {
        $PatchStage = New-StageStatus -ModuleId 'Invoke-MSADPTDomainControllerPatchState' -ModuleVersion '0.1.0' -Disposition 'Planned'
        $PatchStage.StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
        $PatchStage.Stages.PlanningSucceeded = $true
        Write-JsonDocument -Path $PatchStagePath -Value $PatchStage
        try {
            if (Test-Path -LiteralPath $PatchStateDirectory -PathType Container) {
                $ExistingPatchFiles = @(Get-ChildItem -LiteralPath $PatchStateDirectory -File -ErrorAction SilentlyContinue)
                if ($ExistingPatchFiles.Count -gt 0) {
                    $PatchArchive = $PatchStateDirectory + '.superseded-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
                    Move-Item -LiteralPath $PatchStateDirectory -Destination $PatchArchive
                }
            }
            Show -State 'PATCH' -Message 'Running optional read-only domain-controller patch-state collection.' -Color Yellow
            $PatchCollector = Join-Path $Root 'Modules\VulnerabilityIntelligence\Invoke-MSADPTDomainControllerPatchState-v0.1.0.ps1'
            $PatchParameters = @{
                DomainControllerEvidencePath = $DcJson
                OutputDirectory = $PatchStateDirectory
                NoColor = $NoColor
            }
            if ($null -ne $Credential) { $PatchParameters.Credential = $Credential }
            $PatchResult = & $PatchCollector @PatchParameters
            $PatchExecuted = $true
            $LiveModulesExecuted++
            $PatchManifestValid = Test-Manifest -ManifestPath $PatchStateManifest -BaseDirectory $PatchStateDirectory
            $PatchStage.Disposition = if ($PatchManifestValid) { 'Collected' } else { 'Inconclusive' }
            $PatchStage.Stages.NetworkOperationSucceeded = $true
            $PatchStage.Stages.AcquisitionSucceeded = $true
            $PatchStage.Stages.ParsingSucceeded = $true
            $PatchStage.Stages.SemanticAnalysisSucceeded = $true
            $PatchStage.Stages.BehavioralValidationSucceeded = $false
            $PatchStage.Stages.ImpactReproduced = $false
            $PatchStage.Stages.EvidenceWritten = $true
            $PatchStage.Stages.ManifestVerified = $PatchManifestValid
            $PatchStage.Result = $PatchResult
            $PatchStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Write-JsonDocument -Path $PatchStagePath -Value $PatchStage
        }
        catch {
            $PatchStage.Disposition = 'Inconclusive'
            $PatchStage.Error = $_.Exception.Message
            $PatchStage.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Write-JsonDocument -Path $PatchStagePath -Value $PatchStage
            $Errors.Add([pscustomobject]@{Module='DomainControllerPatchState';Stage='Collection';Error=$_.Exception.Message})
        }
    }
    elseif ($Mode -eq 'Analyze' -and -not $PatchComplete) {
        $Errors.Add([pscustomobject]@{Module='DomainControllerPatchState';Stage='Analysis';Error='Patch-state evidence is unavailable for offline analysis.'})
    }
}
# PATCH-STAGE-END
$KerberosStageObject = if (Test-Path -LiteralPath $KerberosStagePath) { Get-Content -LiteralPath $KerberosStagePath -Raw | ConvertFrom-Json } else { $null }
$DcStageObject = if (Test-Path -LiteralPath $DcStagePath) { Get-Content -LiteralPath $DcStagePath -Raw | ConvertFrom-Json } else { $null }
$PatchStageObject = if (Test-Path -LiteralPath $PatchStagePath) { Get-Content -LiteralPath $PatchStagePath -Raw | ConvertFrom-Json } else { $null }
$ErrorRows = [object[]]$Errors.ToArray()
$ErrorsPath = Join-Path $EngagementDirectory 'errors\operational-errors.json'
Write-JsonDocument -Path $ErrorsPath -Value $ErrorRows

$KerberosDisposition = [string](Get-SafeProperty $KerberosStageObject 'Disposition' 'NotStarted')
$DcDisposition = [string](Get-SafeProperty $DcStageObject 'Disposition' 'NotStarted')
$CoverageRows = @(
    [pscustomobject][ordered]@{Id='Identity.Kerberos';Name='Kerberos and Identity';State=if($KerberosDisposition -eq 'Collected'){'Collected'}else{$KerberosDisposition};Evidence=@($KerberosSummary,$KerberosManifest);Limitations=@('No ticket request or password validation performed.')},
    [pscustomobject][ordered]@{Id='Identity.Delegation';Name='Delegation';State=if($KerberosDisposition -eq 'Collected'){'CandidateDetected'}else{$KerberosDisposition};Evidence=@($KerberosSummary);Limitations=@('Configuration candidates require separate behavioral validation.')},
    [pscustomobject][ordered]@{Id='DomainControllers';Name='Domain Controller Inventory';State=$DcDisposition;Evidence=@($DcJson);Limitations=@('Directory metadata only; no service probing or remote execution.')},
[pscustomobject][ordered]@{Id='PatchIntelligence';Name='Current AD Vulnerabilities';State=if(-not $IncludePatchState){'NotStarted'}elseif($null -ne $PatchStageObject){[string]$PatchStageObject.Disposition}else{'Inconclusive'};Evidence=@($PatchStateSummary,$PatchStateApplicability);Limitations=@('Patch build assessment only; prerequisites and impact are evaluated separately.')}
)
foreach ($Family in @($CoverageCatalog.Families)) {
    if ($Family.Id -notin @('Identity.Kerberos','Identity.Delegation')) {
        $CoverageRows += [pscustomobject][ordered]@{Id=$Family.Id;Name=$Family.Name;State='NotStarted';Evidence=@();Limitations=@('Not included in Quick profile.')}
    }
}
$Ledger = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Mode = $Mode
    Profile = $Profile
    BootstrapServer = $BootstrapServer
    AttackFamilies = $CoverageRows
    Modules = @($KerberosStageObject,$DcStageObject,$PatchStageObject | Where-Object { $null -ne $_ })
    OperationalErrorCount = $ErrorRows.Count
}
Write-JsonDocument -Path $LedgerPath -Value $Ledger

$KerberosCounts = $null
if (Test-Path -LiteralPath $KerberosSummary) {
    $KerberosCounts = Get-SafeProperty (Get-Content -LiteralPath $KerberosSummary -Raw | ConvertFrom-Json) 'Counts'
}
$PatchSummaryObjectForReport = $null
$PatchApplicabilityRowsForReport = @()
if ($IncludePatchState -and (Test-Path -LiteralPath $PatchStateSummary -PathType Leaf)) {
    $PatchSummaryObjectForReport = Get-Content -LiteralPath $PatchStateSummary -Raw | ConvertFrom-Json -ErrorAction Stop
}
if ($IncludePatchState -and (Test-Path -LiteralPath $PatchStateApplicability -PathType Leaf)) {
    $PatchApplicabilityRowsForReport = @(Get-Content -LiteralPath $PatchStateApplicability -Raw | ConvertFrom-Json -ErrorAction Stop)
}
$PatchHtml = '<div class="card">Patch-state collection was not selected.</div>'
if ($IncludePatchState) {
    $PatchTableRows = ($PatchApplicabilityRowsForReport | Sort-Object CVE,HostName | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (Convert-HtmlText $_.HostName),(Convert-HtmlText $_.CVE),(Convert-HtmlText $_.Name),(Convert-HtmlText $_.PatchDisposition),(Convert-HtmlText $_.OverallDisposition)
    }) -join "`n"
    if ([string]::IsNullOrWhiteSpace($PatchTableRows)) { $PatchTableRows = '<tr><td colspan="5">No patch applicability evidence available.</td></tr>' }
    $PatchHtml = '<div class="card"><b>Targets:</b> {0}<br><b>Full builds:</b> {1}<br><b>Patched assessments:</b> {2}<br><b>Potentially affected builds:</b> {3}<br><b>Unknown assessments:</b> {4}<br><b>Method-attempt errors:</b> {5}</div><table><tr><th>Host</th><th>CVE</th><th>Name</th><th>Patch disposition</th><th>Overall disposition</th></tr>{6}</table>' -f (Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'TargetCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'FullBuildCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'PatchedBuildDetectedCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'PotentiallyAffectedBuildCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'PatchStateUnknownCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'OperationalErrorCount' 0)),$PatchTableRows
}
$DcCount = 0
if (Test-Path -LiteralPath $DcJson) { $DcCount = @(Get-Content -LiteralPath $DcJson -Raw | ConvertFrom-Json).Count }

$CoverageHtml = ($CoverageRows | ForEach-Object {
    '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Convert-HtmlText $_.Name),(Convert-HtmlText $_.State),(Convert-HtmlText ($_.Limitations -join '; '))
}) -join "`n"
$ErrorHtml = ($ErrorRows | ForEach-Object {
    '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Convert-HtmlText $_.Module),(Convert-HtmlText $_.Stage),(Convert-HtmlText $_.Error)
}) -join "`n"
if ([string]::IsNullOrWhiteSpace($ErrorHtml)) { $ErrorHtml = '<tr><td colspan="3">None</td></tr>' }

$ReportPath = Join-Path $EngagementDirectory 'reports\MSADPT-Quick-Audit.html'
$Html = @"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT Quick Audit</title>
<style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body>
<h1>MSADPT Quick Audit</h1>
<div class="card"><b>Mode:</b> $(Convert-HtmlText $Mode)<br><b>Profile:</b> Quick<br><b>Bootstrap DC:</b> $(Convert-HtmlText $BootstrapServer)<br><b>Live modules executed:</b> $LiveModulesExecuted<br><b>Modules reused:</b> $SkippedModules<br><b>Operational errors:</b> $($ErrorRows.Count)<br><b>Remote changes:</b> None<br><b>Ticket requests:</b> None</div>
<h2>Quick Results</h2>
<div class="card"><b>Domain controllers inventoried:</b> $DcCount<br><b>SPN records:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'SpnRecords' 0))<br><b>User-owned SPNs:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'UserSpnRecords' 0))<br><b>Duplicate SPN groups:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'DuplicateSpnGroups' 0))<br><b>AS-REP candidates:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'AsRepCandidates' 0))<br><b>Kerberoast candidates:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'KerberoastCandidates' 0))<br><b>Delegation candidates:</b> $(Convert-HtmlText (([int](Get-SafeProperty $KerberosCounts 'UnconstrainedDelegationCandidates' 0))+([int](Get-SafeProperty $KerberosCounts 'ConstrainedDelegationCandidates' 0))+([int](Get-SafeProperty $KerberosCounts 'RbcdCandidates' 0))))</div>
<h2>Coverage</h2><table><tr><th>Attack family</th><th>State</th><th>Limitations</th></tr>$CoverageHtml</table>
<h2>Current AD Vulnerabilities</h2>$PatchHtml
<h2>Operational Errors</h2><table><tr><th>Module</th><th>Stage</th><th>Error</th></tr>$ErrorHtml</table>
<h2>Evidence</h2><ul><li><a href="../state/execution-plan.json">Execution plan</a></li><li><a href="../state/coverage-ledger.json">Coverage ledger</a></li><li><a href="../evidence/KerberosSPNBaseline/kerberos-spn-baseline-summary.json">Kerberos summary</a></li><li><a href="../evidence/DomainControllerEnumeration/domain-controller-details.json">Domain-controller inventory</a></li><li><a href="../errors/operational-errors.json">Operational errors</a></li></ul>
<p class="note">Configuration and static candidates are leads. Quick Audit does not request tickets, test passwords, authenticate to discovered services, or reproduce security impact.</p></body></html>
"@
[IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

$OverallStatus = if ($ErrorRows.Count -eq 0) { 'Passed' } elseif ($LiveModulesExecuted -gt 0 -or $SkippedModules -gt 0) { 'PassedWithErrors' } else { 'Failed' }
Show -State 'REPORT' -Message $ReportPath -Color Cyan
Show -State 'DONE' -Message "Status=$OverallStatus; live=$LiveModulesExecuted; reused=$SkippedModules; errors=$($ErrorRows.Count)." -Color Green

[pscustomobject][ordered]@{
    Status = $OverallStatus
    Mode = $Mode
    Profile = $Profile
    EngagementDirectory = $EngagementDirectory
    BootstrapServer = $BootstrapServer
    RegistryModuleCount = [int]$Registry.ModuleCount
    IntegratedModuleCount = $Integrated.Count
    StandaloneModuleCount = $Standalone.Count
    LiveModulesExecuted = $LiveModulesExecuted
    ReusedModuleCount = $SkippedModules
    OperationalErrorCount = $ErrorRows.Count
    PatchStateIncluded = [bool]$IncludePatchState
    PatchStateExecuted = [bool]$PatchExecuted
    PatchStateReused = [bool]$PatchReused
    CoverageLedgerPath = $LedgerPath
    ExecutionPlanPath = $ExecutionPlanPath
    HtmlReportPath = $ReportPath
}