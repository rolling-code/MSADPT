<#
.SYNOPSIS
Runs or plans an MSADPT assessment.

.DESCRIPTION
The Quick profile provides the bounded operational workflow. The Full profile automatically selects every currently first-class integrated read-only assessment family and preserves explicit gating for behavioral validators. It performs local
preflight, announces the live Active Directory query plan, collects a Kerberos/SPN baseline,
collects domain-controller directory metadata using the selected bootstrap DC, updates normalized
stage state and coverage, and writes a consolidated HTML report.

Resume mode reuses completed, manifest-backed evidence and does not repeat completed collectors.
No Kerberos tickets are requested. No passwords are collected. No directory or remote system is
modified.

.NOTES
Version: 1.7.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Plan','Audit','Analyze','Resume')]
    [string]$Mode,

    [ValidateSet('Quick','Full')]
    [string]$Profile = 'Quick',

    [string]$EngagementDirectory,
    [string]$Server,
    [PSCredential]$Credential,
    [switch]$NoColor,
    [switch]$ForceRerun,
    [switch]$IncludePatchState,
    [switch]$IncludeKerberosCrypto,
    [switch]$IncludeKdcTelemetry,
    [switch]$RetryIncompletePatchTargets,
    [switch]$IncludeADCS,
    [switch]$IncludeADDns,
    [switch]$IncludeSMB,
    [string]$SMBNmapXmlPath,
    [switch]$EnableBehavioralValidation
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$OrchestratorVersion = '1.7.0'
$Root = $PSScriptRoot

# Full automatically selects every assessment family that currently has a validated first-class
# orchestration contract. Behavioral changes remain controlled by EnableBehavioralValidation.
if ($Profile -eq 'Full') {
    $IncludePatchState = $true
    $IncludeKerberosCrypto = $true
    $IncludeKdcTelemetry = $true
    $IncludeADCS = $true
    $IncludeADDns = $true
    $IncludeSMB = $true
}

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
$IntegratedOptional = @($Registry.Modules | Where-Object { $_.OrchestrationState -eq 'IntegratedOptional' })

$QuickModuleIds = @(
    'Invoke-MSADPTKerberosSPNBaselineCollection',
    'Complete-MSADPTKerberosSPNBaseline',
    'Invoke-MSADPTKerberosCryptographicPosture',
    'Invoke-MSADPTDomainControllerEnumeration',
    'Invoke-MSADPTADDnsSecurity'
)
$QuickModules = @($Registry.Modules | Where-Object { $_.ModuleId -in $QuickModuleIds })

Show -State 'START' -Message "MSADPT v$OrchestratorVersion mode=$Mode profile=$Profile" -Color Cyan
$SafetyMessage = if ($IncludeADDns -and $EnableBehavioralValidation) { "$Profile Audit includes one bounded temporary AD DNS object create-read-delete-verify operation. No retained record, ticket request, password collection, or remote execution." } else { "$Profile Audit performs read-only AD queries only. No ticket request, password collection, remote execution, or directory change." }
Show -State 'SAFETY' -Message $SafetyMessage -Color Yellow

if ($Mode -eq 'Plan') {
    Show -State 'PREFLIGHT' -Message 'Local checks: PowerShell, ActiveDirectory module, registry, catalog, and writeable engagement path.' -Color DarkCyan
    Show -State 'NETWORK' -Message 'Targets: current AD domain and one writable DC selected by AD discovery or -Server.' -Color DarkCyan
    Show -State 'PROTOCOLS' -Message 'ADWS/LDAP through the ActiveDirectory module using the current identity or -Credential.' -Color DarkCyan
    Show -State 'MODULES' -Message ($QuickModuleIds -join ', ') -Color DarkCyan
    Show -State 'CHANGES' -Message 'Remote changes=None; local changes=engagement evidence, state, and HTML report.' -Color DarkCyan
    if ($IncludeADCS) {
        Show -State 'ADCSPLAN' -Message 'AD CS configuration: selected bootstrap DC over ADWS/LDAP; enterprise CA and template objects, publication, and template ACLs; current identity or -Credential.' -Color Magenta
        Show -State 'ADCSPORTS' -Message 'ADWS/LDAP through the ActiveDirectory module; ports are environment-defined AD service ports. No direct CA RPC, HTTP, SMB, certificate, or private-key operation.' -Color Magenta
        Show -State 'ADCSSAFE' -Message 'Read-only directory queries only; timeout behavior is provided by the ActiveDirectory module; remote changes=None; enrollment=None; authentication with certificates=None.' -Color Magenta
        Show -State 'ADCSLOCAL' -Message 'Local output: ADCSConfigurationCollection evidence, offline facts/correlation, stage state, coverage ledger, and consolidated HTML.' -Color Magenta
    }
    if ($IncludeADDns) {
        Show -State 'DNSPLAN' -Message 'AD-integrated DNS: selected writable DC over LDAP TCP/389 or LDAPS TCP/636; RootDSE and DNS partition discovery.' -Color Magenta
        $DnsSafetyMessage = if ($EnableBehavioralValidation) { 'Bounded validation: create one unique dnsNode, read it back, delete it, and verify absence. No prompt and no retained record.' } else { 'Read-only zone discovery. Behavioral validation not selected.' }
        Show -State 'DNSSAFE' -Message $DnsSafetyMessage -Color Magenta
    }
    if ($IncludeSMB) {
        Show -State 'SMBPLAN' -Message 'Targets: discovered domain controllers; TCP/445 reachability, SMB signing posture, nonadministrative share enumeration, SYSVOL/NETLOGON classification, and bounded file-name metadata discovery.' -Color Magenta
        Show -State 'SMBSAFE' -Message 'Read-only SMB assessment. Content reads=None; write tests=None; credential capture=None; relay attempts=None; remote execution=None.' -Color Magenta
        Show -State 'SMBINPUT' -Message 'Optional input: -SMBNmapXmlPath <Nmap XML>. If omitted, MSADPT looks for MSADPT-SMB-Discovery.xml in the repository root.' -Color Magenta
        Show -State 'SMBHINT' -Message 'MSADPT does not run Nmap. Example: nmap -n -Pn -p 445 --open --reason -iL .\MSADPT-Targets.txt -oA .\MSADPT-SMB-Discovery' -Color DarkYellow
    }
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
        OptionalIntegratedModuleCount = $IntegratedOptional.Count
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
        [pscustomobject]@{Module='KerberosSPNBaselineCollection';Target='Current domain and selected writable DC';Protocol='ADWS/LDAP';Ports='Environment-defined AD service ports';Operation='Read-only AD user, computer, domain, forest, and DC queries'}
        [pscustomobject]@{Module='DomainControllerEnumeration';Target='Selected bootstrap DC';Protocol='ADWS/LDAP';Ports='Environment-defined AD service ports';Operation='Read-only domain-controller and computer-object metadata queries'}
        if($IncludeADDns){
            [pscustomobject]@{
                Module='ADDnsSecurity'
                Target='Selected writable DC and AD-integrated DNS zone'
                Protocol='LDAP or LDAPS'
                Ports='TCP/389 or TCP/636'
                Authentication=if($null-eq$Credential){'CurrentWindowsIdentity'}else{'SuppliedPSCredential'}
                Operation=if($EnableBehavioralValidation){'Temporary dnsNode create-read-resolve-delete-verify'}else{'Read-only zone, ACL, and inventory discovery'}
                RemoteChanges=if($EnableBehavioralValidation){'One temporary dnsNode; mandatory deletion and absence verification'}else{'None'}
            }
        }
    )
    ADCSNetworkOperation = if ($IncludeADCS) { [pscustomobject]@{Module='ADCSConfigurationCollection';Target='Configuration partition through selected bootstrap DC';Protocol='ADWS/LDAP';Ports='Environment-defined AD service ports';Authentication=if($null-eq$Credential){'CurrentWindowsIdentity'}else{'SuppliedPSCredential'};Timeout='ActiveDirectory module default';Operation='Read-only enterprise CA, template publication, template attributes, and template ACL queries';RemoteChanges='None'} } else { $null }
    SMBNetworkOperation = if ($IncludeSMB) { [pscustomobject]@{Module='SMBFullAssessment';Target='Discovered domain controllers';Protocol='SMB';Ports='TCP/445';Authentication=if($null-eq$Credential){'CurrentWindowsIdentity'}else{'SuppliedPSCredential'};Operation='TCP reachability, SMB signing posture, share inventory, SYSVOL/NETLOGON classification, bounded filename metadata';ContentReads='None';RemoteChanges='None';RelayAttempts='None';RemoteExecution='None'} } else { $null }
    RemoteChanges = if($IncludeADDns -and $EnableBehavioralValidation){'One temporary AD DNS dnsNode, automatically deleted and verified absent'}else{'None'}
    TicketRequests = 'None'
    PasswordMaterial = 'None'
    LocalChanges = @('Create engagement directories','Write JSON and CSV evidence','Write stage records','Write consolidated HTML report')
}
Write-JsonDocument -Path $ExecutionPlanPath -Value $Plan

Show -State 'IDENTITY' -Message "Identity=$($Plan.CurrentIdentity)" -Color DarkCyan
Show -State 'NETWORK' -Message 'Kerberos baseline: current domain plus selected writable DC over ADWS/LDAP.' -Color Magenta
Show -State 'NETWORK' -Message 'DC inventory: selected bootstrap DC over ADWS/LDAP.' -Color Magenta
Show -State 'CHANGES' -Message "Remote changes=$($Plan.RemoteChanges); ticket requests=None; password material=None." -Color Magenta

if ($Mode -eq 'Analyze') {
    Show -State 'ANALYZE' -Message 'Analyze mode processes existing Quick Audit evidence only.' -Color Yellow
}

$KerberosDirectory = Join-Path $EngagementDirectory 'evidence\KerberosSPNBaseline'
$KerberosManifest = Join-Path $KerberosDirectory 'evidence-manifest.json'
$KerberosSummary = Join-Path $KerberosDirectory 'kerberos-spn-baseline-summary.json'
$DcEvidenceDirectory = Join-Path $EngagementDirectory 'evidence\DomainControllerEnumeration'
$DcJson = Join-Path $DcEvidenceDirectory 'domain-controller-details.json'

$KerberosStagePath = Join-Path $StageDirectory 'kerberos-spn-baseline.json'
$KerberosCryptoDirectory = Join-Path $EngagementDirectory 'analysis\KerberosEncryptionPrioritization'
$KerberosCryptoSummary = Join-Path $KerberosCryptoDirectory 'kerberos-encryption-correlation-summary.json'
$KerberosCryptoReview = Join-Path $KerberosCryptoDirectory 'kerberos-prioritized-account-review.json'
$KerberosCryptoManifest = Join-Path $EngagementDirectory 'analysis\KerberosCryptographicPosture\bundle-execution-manifest.json'
$KerberosCryptoStagePath = Join-Path $StageDirectory 'kerberos-cryptographic-posture.json'
$DcStagePath = Join-Path $StageDirectory 'domain-controller-enumeration.json'
$PatchStateDirectory = Join-Path $EngagementDirectory 'evidence\DomainControllerPatchState'
$PatchStateManifest = Join-Path $PatchStateDirectory 'evidence-manifest.json'
$PatchStateSummary = Join-Path $PatchStateDirectory 'patch-state-summary.json'
$PatchStateApplicability = Join-Path $PatchStateDirectory 'ad-vulnerability-applicability.json'
$PatchStagePath = Join-Path $StageDirectory 'domain-controller-patch-state.json'
$ADCSDirectory = Join-Path $EngagementDirectory 'evidence\ADCSConfigurationCollection'
$ADCSManifest = Join-Path $ADCSDirectory 'evidence-manifest.json'
$ADCSTemplateConfiguration = Join-Path $ADCSDirectory 'certificate-template-configuration.json'
$ADCSTemplateAccess = Join-Path $ADCSDirectory 'certificate-template-access.csv'
$ADCSAnalysisDirectory = Join-Path $EngagementDirectory 'analysis\ADCSOfflineEvidenceToCandidate'
$ADCSAnalysisManifest = Join-Path $ADCSAnalysisDirectory 'evidence-manifest.json'
$ADCSSummary = Join-Path $ADCSAnalysisDirectory 'adcs-offline-pipeline-summary.json'
$ADCSCandidates = Join-Path $ADCSAnalysisDirectory 'Correlation\adcs-technique-candidates.json'
$ADCSStagePath = Join-Path $StageDirectory 'adcs-read-only-assessment.json'
$ADDnsDirectory = Join-Path $EngagementDirectory 'analysis\ADDnsSecurity'
$ADDnsSummary = Join-Path $ADDnsDirectory 'ad-dns-security-summary.json'
$ADDnsStagePath = Join-Path $StageDirectory 'ad-dns-security.json'
$SMBDirectory = Join-Path $EngagementDirectory 'evidence\SMBFullAssessment'
$SMBCollectorDirectory = Join-Path $SMBDirectory 'Collector'
$SMBManifest = Join-Path $SMBCollectorDirectory 'evidence-manifest.json'
$SMBSummary = Join-Path $SMBCollectorDirectory 'smb-share-pivot-summary.json'
$SMBStagePath = Join-Path $StageDirectory 'smb-full-assessment.json'
$SMBNmapImportDirectory = Join-Path $SMBDirectory 'NmapImport'
$SMBNmapImportSummary = Join-Path $SMBNmapImportDirectory 'nmap-smb-import-summary.json'
$SMBMergedTargetList = Join-Path $SMBDirectory 'smb-merged-targets.txt'
$ADDnsExecuted = $false
$ADDnsReused = $false
$ADCSExecuted = $false
$ADCSReused = $false
$ADCSResult = $null
$SMBExecuted = $false
$SMBReused = $false
$SMBResult = $null
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

        $CollectorPath = Join-Path $Root 'Modules\Kerberos\Invoke-MSADPTKerberosSPNBaselineCollection-v0.1.2.ps1'
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

# ADDNS-STAGE-BEGIN
if ($IncludeADDns) {
    $ADDnsComplete = $false
    if(-not $ForceRerun -and (Test-Path -LiteralPath $ADDnsSummary -PathType Leaf)){
        try{
            $PriorADDns=Get-Content -LiteralPath $ADDnsSummary -Raw|ConvertFrom-Json -ErrorAction Stop
            $PriorValidation=Get-Content -LiteralPath (Join-Path $EngagementDirectory 'evidence\ADDnsSecurity\ad-dns-write-validation.json') -Raw|ConvertFrom-Json -ErrorAction Stop
            $PriorCleanup=Get-Content -LiteralPath (Join-Path $EngagementDirectory 'evidence\ADDnsSecurity\ad-dns-cleanup-manifest.json') -Raw|ConvertFrom-Json -ErrorAction Stop
            $ADDnsComplete=([string]$PriorADDns.ModuleVersion -eq '0.2.2' -and [string]$PriorADDns.Disposition -in @('BehaviorallyValidated','NotDetected','CandidateDetected') -and ((-not [bool]$PriorValidation.WriteSucceeded) -or [bool]$PriorCleanup.Verified))
        }catch{$ADDnsComplete=$false}
    }
    if ($ADDnsComplete) {
        $SkippedModules++
        $ADDnsReused = $true
        $ADDnsResult = Get-Content -LiteralPath $ADDnsSummary -Raw | ConvertFrom-Json -ErrorAction Stop
        Write-JsonDocument -Path $ADDnsStagePath -Value ([pscustomobject][ordered]@{Module='ADDnsSecurity';Status='Reused';Disposition=[string]$ADDnsResult.Disposition;Result=$ADDnsResult;CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')})
        Show -State 'REUSE' -Message 'AD-integrated DNS evidence verified. Collection and validation skipped.' -Color Green
    }
    elseif ($Mode -in @('Audit','Resume')) {
        try {
            $DnsRunner = Join-Path $Root 'Modules\ADDnsSecurity\Invoke-MSADPTADDnsSecurity.ps1'
            $DnsParams = @{EngagementDirectory=$EngagementDirectory;Server=$BootstrapServer;EnableBehavioralValidation=[bool]$EnableBehavioralValidation;NoColor=$NoColor}
            if ($null -ne $Credential) { $DnsParams.Credential=$Credential }
            $ADDnsResult = & $DnsRunner @DnsParams
            $ADDnsExecuted = $true
            $LiveModulesExecuted++
            Write-JsonDocument -Path $ADDnsStagePath -Value ([pscustomobject][ordered]@{Module='ADDnsSecurity';Status='Completed';Disposition=[string]$ADDnsResult.Disposition;Result=$ADDnsResult;CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')})
        }
        catch {
            $Errors.Add([pscustomobject]@{Module='ADDnsSecurity';Stage='DiscoveryOrValidation';Error=$_.Exception.Message})
            Write-JsonDocument -Path $ADDnsStagePath -Value ([pscustomobject]@{Module='ADDnsSecurity';Status='Failed';Disposition='Inconclusive';Error=$_.Exception.Message})
        }
    }
}
# ADDNS-STAGE-END
if ($IncludeSMB) {
    $ReuseSMB = $Mode -eq 'Resume' -and -not $ForceRerun -and (Test-Manifest -ManifestPath $SMBManifest -ExpectedStatus @('Completed','CompletedWithErrors')) -and (Test-Path -LiteralPath $SMBSummary -PathType Leaf)
    if ($ReuseSMB) {
        $SMBResult = Get-Content -LiteralPath $SMBSummary -Raw | ConvertFrom-Json -ErrorAction Stop
        $SMBReused = $true
        $SkippedModules++
        Show -State 'REUSE' -Message 'SMB evidence and manifest verified. Collection skipped.' -Color Cyan
    }
    else {
        if (Test-Path -LiteralPath $SMBDirectory -PathType Container) { Remove-Item -LiteralPath $SMBDirectory -Recurse -Force }
        $SMBModule = Join-Path $Root 'Modules\SMB\Invoke-MSADPTSMBSharePivotAssessment-v0.1.1.ps1'
        if (-not (Test-Path -LiteralPath $SMBModule -PathType Leaf)) { throw "SMBModuleMissing: $SMBModule" }
        Show -State 'SMB' -Message 'Assessing domain-controller TCP/445 reachability, SMB signing, shares, SYSVOL/NETLOGON, and bounded filename metadata.' -Color Cyan
        $RequestedNmapPath=$SMBNmapXmlPath
        if([string]::IsNullOrWhiteSpace($RequestedNmapPath)){
            $ConventionalPath=Join-Path $Root 'MSADPT-SMB-Discovery.xml'
            if(Test-Path -LiteralPath $ConventionalPath -PathType Leaf){$RequestedNmapPath=$ConventionalPath}
        }
        $MergedTargets=New-Object 'Collections.Generic.List[string]'
        if(Test-Path -LiteralPath $DcJson -PathType Leaf){
            foreach($Dc in @(Get-Content -LiteralPath $DcJson -Raw|ConvertFrom-Json)){
                foreach($PropertyName in @('HostName','DNSHostName','Name')){
                    $Property=$Dc.PSObject.Properties[$PropertyName]
                    if($null-ne$Property-and-not[string]::IsNullOrWhiteSpace([string]$Property.Value)){$MergedTargets.Add([string]$Property.Value);break}
                }
            }
        }
        if(-not[string]::IsNullOrWhiteSpace($RequestedNmapPath)){
            $ResolvedNmapPath=if([IO.Path]::IsPathRooted($RequestedNmapPath)){$RequestedNmapPath}else{Join-Path (Get-Location) $RequestedNmapPath}
            if(-not(Test-Path -LiteralPath $ResolvedNmapPath -PathType Leaf)){throw "SMBNmapXmlPathNotFound: $ResolvedNmapPath"}
            Show -State 'SMBINPUT' -Message "Importing operator-generated Nmap XML: $ResolvedNmapPath" -Color Cyan
            $Importer=Join-Path $Root 'Modules\SMB\Import-MSADPTNmapSMBTargets.ps1'
            $ImportResult=& $Importer -NmapXmlPath $ResolvedNmapPath -OutputDirectory $SMBNmapImportDirectory
            foreach($Target in @($ImportResult.Targets)){$MergedTargets.Add([string]$Target)}
            Show -State 'SMBIMPORT' -Message "Confirmed-open TCP/445 targets imported=$($ImportResult.ConfirmedOpenTcp445TargetCount); rejected host records=$($ImportResult.RejectedHostRecordCount)." -Color Cyan
        }else{
            Show -State 'SMBINPUT' -Message 'No local Nmap XML was supplied or found. Continuing with discovered domain controllers.' -Color DarkYellow
            Show -State 'SMBHINT' -Message 'To extend scope: nmap -n -Pn -p 445 --open --reason -iL .\MSADPT-Targets.txt -oA .\MSADPT-SMB-Discovery' -Color DarkYellow
            Show -State 'SMBPATH' -Message 'Place MSADPT-SMB-Discovery.xml in the repository root or supply -SMBNmapXmlPath.' -Color DarkYellow
        }
        $FinalTargets=@($MergedTargets|Where-Object{-not[string]::IsNullOrWhiteSpace($_)}|Sort-Object -Unique)
        if($FinalTargets.Count-eq0){throw 'SMBTargetSetEmpty: no domain-controller or confirmed-open Nmap target was available.'}
        $FinalTargets|Set-Content -LiteralPath $SMBMergedTargetList -Encoding UTF8
        Show -State 'SMBSCOPE' -Message "Final deduplicated SMB target count=$($FinalTargets.Count)." -Color Cyan
        foreach($FinalTarget in $FinalTargets){Show -State 'SMBTARGET' -Message "$FinalTarget TCP/445" -Color DarkCyan}
        $SMBArguments = @{TargetListPath=$SMBMergedTargetList;Server=$BootstrapServer;OutputDirectory=$SMBCollectorDirectory;SkipNmap=$true;NoColor=[bool]$NoColor}
        if ($null -ne $Credential) { $SMBArguments.Credential=$Credential }
        $SMBOutput = @(& $SMBModule @SMBArguments)
        $SMBResult = @($SMBOutput | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['PackageIdentity'] -and [string]$_.PackageIdentity -eq 'MSADPT-SMB-SHARE-PIVOT-ASSESSMENT' }) | Select-Object -Last 1
        if ($null -eq $SMBResult) { throw 'SMBTerminalResultMissing' }
        $SMBExecuted = $true
        $LiveModulesExecuted++
        $FatalOrchestrationErrorCount += [int](Get-SafeProperty $SMBResult 'OperationalErrorCount' 0)
    }
    Write-JsonDocument -Path $SMBStagePath -Value ([pscustomobject][ordered]@{Module='SMBFullAssessment';Status=if($SMBReused){'Reused'}else{'Completed'};Disposition=if([int](Get-SafeProperty $SMBResult 'SigningOptionalOrDisabledCount' 0)-gt0 -or [int](Get-SafeProperty $SMBResult 'InterestingFileNameLeadCount' 0)-gt0){'CandidateDetected'}else{'Collected'};Result=$SMBResult;CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')})
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
# ADCS-STAGE-BEGIN
if ($IncludeADCS) {
    $ADCSComplete = (-not $ForceRerun -and (Test-Path -LiteralPath $ADCSSummary -PathType Leaf) -and (Test-Manifest -ManifestPath $ADCSManifest -BaseDirectory $ADCSDirectory) -and (Test-Manifest -ManifestPath $ADCSAnalysisManifest -BaseDirectory $ADCSAnalysisDirectory))
    if ($ADCSComplete) {
        $SkippedModules += 2
        $ADCSReused = $true
        $ADCSResult = Get-Content -LiteralPath $ADCSSummary -Raw | ConvertFrom-Json -ErrorAction Stop
        $ReusedADCSCandidates = @()
        if (Test-Path -LiteralPath $ADCSCandidates -PathType Leaf) {
            $ReusedADCSCandidates = @(Get-Content -LiteralPath $ADCSCandidates -Raw | ConvertFrom-Json -ErrorAction Stop)
        }
        $ReusedADCSDisposition = if ($ReusedADCSCandidates.Count -gt 0) { 'CandidateDetected' } else { 'Collected' }
        $ADCSStage = New-StageStatus -ModuleId 'MSADPTQuickAuditADCS' -ModuleVersion '1.0.0' -Disposition $ReusedADCSDisposition
        $ADCSStage.Stages.PlanningSucceeded=$true; $ADCSStage.Stages.AcquisitionSucceeded=$true; $ADCSStage.Stages.ParsingSucceeded=$true; $ADCSStage.Stages.SemanticAnalysisSucceeded=$true; $ADCSStage.Stages.EvidenceWritten=$true; $ADCSStage.Stages.ManifestVerified=$true
        $ADCSStage.Result=$ADCSResult; $ADCSStage.CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Write-JsonDocument -Path $ADCSStagePath -Value $ADCSStage
        Show -State 'REUSE' -Message 'AD CS collection and offline-correlation manifests verified. Zero-query reuse selected.' -Color Green
    }
    elseif ($Mode -in @('Audit','Resume')) {
        $ADCSStage = New-StageStatus -ModuleId 'MSADPTQuickAuditADCS' -ModuleVersion '1.0.0' -Disposition 'Planned'
        $ADCSStage.StartedUtc=(Get-Date).ToUniversalTime().ToString('o'); $ADCSStage.Stages.PlanningSucceeded=$true
        Write-JsonDocument -Path $ADCSStagePath -Value $ADCSStage
        try {
            Show -State 'ADCS' -Message "Collecting read-only AD CS directory configuration through $BootstrapServer." -Color Yellow
            $Collector = Join-Path $Root 'Modules\ADCS\Invoke-MSADPTADCSConfigurationCollection.ps1'
            $CollectorParams=@{EngagementPath=$EngagementDirectory}; if($null-ne$Credential){$CollectorParams.Credential=$Credential}
            $CollectionOutput=@(& $Collector @CollectorParams); $LiveModulesExecuted++; $ADCSExecuted=$true
            if(-not(Test-Manifest -ManifestPath $ADCSManifest -BaseDirectory $ADCSDirectory)){throw 'ADCSCollectionManifestValidationFailed'}
            Show -State 'ADCS' -Message 'Correlating AD CS evidence offline against the ESC1 through ESC16 prerequisite catalog.' -Color Yellow
            $Pipeline=Join-Path $Root 'Analysis\ADCS\Invoke-MSADPTADCSEndToEndOfflineAnalysis.ps1'
            $PipelineParams=@{FactBuilderPath=(Join-Path $Root 'Analysis\ADCS\Convert-MSADPTADCSEvidenceToFacts.ps1');CorrelationEnginePath=(Join-Path $Root 'Analysis\ADCS\Invoke-MSADPTADCSPrerequisiteCorrelation.ps1');CatalogPath=(Join-Path $Root 'Catalogs\ADCS\adcs-technique-prerequisites-v1.0.0.json');TemplateConfigurationPath=$ADCSTemplateConfiguration;TemplateAccessPath=$ADCSTemplateAccess;OutputRoot=$ADCSAnalysisDirectory;NoColor=$NoColor}
            $PipelineOutput=@(& $Pipeline @PipelineParams); $LiveModulesExecuted++
            $ADCSResult=@($PipelineOutput|Where-Object{$null-ne$_ -and $null-ne$_.PSObject.Properties['pipelineVersion'] -and [string]$_.status -eq 'Completed'}|Select-Object -Last 1)
            if($ADCSResult.Count -eq 0){throw 'ADCSPipelineTerminalResultMissing'}; $ADCSResult=$ADCSResult[0]
            $ManifestValid=Test-Manifest -ManifestPath $ADCSAnalysisManifest -BaseDirectory $ADCSAnalysisDirectory
            $ADCSStage.Disposition=if($ManifestValid){'CandidateDetected'}else{'Inconclusive'}
            $ADCSStage.Stages.DiscoverySucceeded=$true; $ADCSStage.Stages.NetworkOperationSucceeded=$true; $ADCSStage.Stages.AcquisitionSucceeded=$true; $ADCSStage.Stages.ParsingSucceeded=$true; $ADCSStage.Stages.SemanticAnalysisSucceeded=$true; $ADCSStage.Stages.BehavioralValidationSucceeded=$false; $ADCSStage.Stages.ImpactReproduced=$false; $ADCSStage.Stages.EvidenceWritten=$true; $ADCSStage.Stages.ManifestVerified=$ManifestValid
            $ADCSStage.Result=$ADCSResult; $ADCSStage.CompletedUtc=(Get-Date).ToUniversalTime().ToString('o'); Write-JsonDocument -Path $ADCSStagePath -Value $ADCSStage
        } catch {
            $ADCSStage.Disposition='Inconclusive'; $ADCSStage.Error=$_.Exception.Message; $ADCSStage.CompletedUtc=(Get-Date).ToUniversalTime().ToString('o'); Write-JsonDocument -Path $ADCSStagePath -Value $ADCSStage
            $Errors.Add([pscustomobject]@{Module='QuickAuditADCS';Stage='CollectionOrOfflineCorrelation';Error=$_.Exception.Message})
        }
    }
    elseif ($Mode -eq 'Analyze' -and -not $ADCSComplete) { $Errors.Add([pscustomobject]@{Module='QuickAuditADCS';Stage='Analysis';Error='Manifest-backed AD CS evidence is unavailable for offline analysis.'}) }
}
# ADCS-STAGE-END
$KerberosCryptoResult=$null
$KerberosCryptoComplete=(-not $ForceRerun -and (Test-Path -LiteralPath $KerberosCryptoSummary -PathType Leaf) -and (Test-Path -LiteralPath $KerberosCryptoReview -PathType Leaf))
if($IncludeKerberosCrypto){
 if($KerberosCryptoComplete){$SkippedModules++;$KerberosCryptoResult=Get-Content $KerberosCryptoSummary -Raw|ConvertFrom-Json;Write-JsonDocument $KerberosCryptoStagePath ([pscustomobject][ordered]@{Module='KerberosCryptographicPosture';Status='Reused';Disposition=[string]$KerberosCryptoResult.OverallDisposition;CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')})}
 elseif($Mode -ne 'Analyze'){try{$runner=Join-Path $Root 'Modules\KerberosCryptographicPosture\Invoke-MSADPTKerberosCryptographicPosture.ps1';$kp=@{EngagementDirectory=$EngagementDirectory;Server=$BootstrapServer;IncludeKdcTelemetry=[bool]$IncludeKdcTelemetry;NoColor=$NoColor};if($null-ne$Credential){$kp.Credential=$Credential};$KerberosCryptoResult=&$runner @kp;$LiveModulesExecuted++;Write-JsonDocument $KerberosCryptoStagePath ([pscustomobject][ordered]@{Module='KerberosCryptographicPosture';Status='Completed';Disposition=[string]$KerberosCryptoResult.OverallDisposition;Result=$KerberosCryptoResult;CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')})}catch{$Errors.Add([pscustomobject]@{Module='KerberosCryptographicPosture';Stage='CollectionAndAnalysis';Error=$_.Exception.Message});Write-JsonDocument $KerberosCryptoStagePath ([pscustomobject]@{Module='KerberosCryptographicPosture';Status='Failed';Disposition='Inconclusive';Error=$_.Exception.Message})}}
}
$KerberosStageObject = if (Test-Path -LiteralPath $KerberosStagePath) { Get-Content -LiteralPath $KerberosStagePath -Raw | ConvertFrom-Json } else { $null }

if ($IncludeKerberosCrypto -and (Test-Path -LiteralPath $KerberosCryptoSummary -PathType Leaf) -and $LiveModulesExecuted -eq 0) {
    Show -State 'REUSE' -Message 'Kerberos cryptographic-posture evidence verified. Collection skipped.' -Color Green
}
$DcStageObject = if (Test-Path -LiteralPath $DcStagePath) { Get-Content -LiteralPath $DcStagePath -Raw | ConvertFrom-Json } else { $null }
$ADCSStageObject = if (Test-Path -LiteralPath $ADCSStagePath) { Get-Content -LiteralPath $ADCSStagePath -Raw | ConvertFrom-Json } else { $null }
$ADDnsStageObject = if (Test-Path -LiteralPath $ADDnsStagePath) { Get-Content -LiteralPath $ADDnsStagePath -Raw | ConvertFrom-Json } else { $null }
$PatchStageObject = if (Test-Path -LiteralPath $PatchStagePath) { Get-Content -LiteralPath $PatchStagePath -Raw | ConvertFrom-Json } else { $null }
$PatchMethodErrorCount = 0
if ($IncludePatchState -and (Test-Path -LiteralPath $PatchStateSummary -PathType Leaf)) {
    $PatchMethodErrorSummary = Get-Content -LiteralPath $PatchStateSummary -Raw | ConvertFrom-Json -ErrorAction Stop
    $PatchMethodErrorCount = [int](Get-SafeProperty $PatchMethodErrorSummary 'OperationalErrorCount' 0)
}
$ErrorRows = [object[]]$Errors.ToArray()
$ErrorsPath = Join-Path $EngagementDirectory 'errors\operational-errors.json'
Write-JsonDocument -Path $ErrorsPath -Value $ErrorRows

$KerberosDisposition = [string](Get-SafeProperty $KerberosStageObject 'Disposition' 'NotStarted')
$DcDisposition = [string](Get-SafeProperty $DcStageObject 'Disposition' 'NotStarted')
$CoverageRows = @(
    [pscustomobject][ordered]@{Id='Identity.Kerberos';Name='Kerberos and Identity';State=if($KerberosDisposition -eq 'Collected'){'Collected'}else{$KerberosDisposition};Evidence=@($KerberosSummary,$KerberosManifest);Limitations=@('No ticket request or password validation performed.')},
    [pscustomobject][ordered]@{Id='Identity.Kerberos.Cryptography';Name='Kerberos Cryptographic Posture';State=if(-not $IncludeKerberosCrypto){'NotStarted'}elseif(Test-Path $KerberosCryptoSummary){(Get-Content $KerberosCryptoSummary -Raw|ConvertFrom-Json).OverallDisposition}else{'Inconclusive'};Evidence=@($KerberosCryptoSummary,$KerberosCryptoReview);Limitations=@('Static capability does not prove observed RC4 use; KDC telemetry may be unavailable.')},
    [pscustomobject][ordered]@{Id='Identity.Delegation';Name='Delegation';State=if($KerberosDisposition -eq 'Collected'){'CandidateDetected'}else{$KerberosDisposition};Evidence=@($KerberosSummary);Limitations=@('Configuration candidates require separate behavioral validation.')},
    [pscustomobject][ordered]@{Id='DomainControllers';Name='Domain Controller Inventory';State=$DcDisposition;Evidence=@($DcJson);Limitations=@('Directory metadata only; no service probing or remote execution.')},
    [pscustomobject][ordered]@{Id='ADCS';Name='Active Directory Certificate Services';State=if(-not $IncludeADCS){'NotStarted'}elseif($null-ne$ADCSStageObject){[string]$ADCSStageObject.Disposition}else{'Inconclusive'};Evidence=@($ADCSSummary,$ADCSCandidates,$ADCSManifest,$ADCSAnalysisManifest);Limitations=@('Prerequisite correlation only. No certificate enrollment, certificate authentication, relay, private-key access, template modification, or CA modification was performed.')},
    [pscustomobject][ordered]@{Id='NameResolution.ADDns';Name='AD-Integrated DNS';State=if(-not $IncludeADDns){'NotStarted'}elseif($null-ne$ADDnsStageObject){[string]$ADDnsStageObject.Disposition}else{'Inconclusive'};Evidence=@($ADDnsSummary);Limitations=@('DNS write capability does not prove relay, credential capture, privilege escalation, or domain compromise.')},
    [pscustomobject][ordered]@{Id='PatchIntelligence';Name='Current AD Vulnerabilities';State=if(-not $IncludePatchState){'NotStarted'}elseif($null -ne $PatchStageObject){[string]$PatchStageObject.Disposition}else{'Inconclusive'};Evidence=@($PatchStateSummary,$PatchStateApplicability);Limitations=@('Patch build assessment only; prerequisites and impact are evaluated separately.')}
)
foreach ($Family in @($CoverageCatalog.Families)) {
    if ($Family.Id -notin @('Identity.Kerberos','Identity.Delegation','ADCS')) {
        $CoverageRows += [pscustomobject][ordered]@{Id=$Family.Id;Name=$Family.Name;State='NotStarted';Evidence=@();Limitations=@(if($Profile -eq 'Quick'){'Not included in Quick profile.'}else{'No validated first-class Full-profile orchestration contract is currently available for this family.'})}
    }
}
# Ensure the authoritative SMB stage supersedes any generic NotStarted row.
if($IncludeSMB){
    $CoverageRows=@($CoverageRows|Where-Object{[string]$_.Id-ne'SMB.Files'})
    $SMBState=if($null-eq$SMBResult){'Inconclusive'}elseif([int](Get-SafeProperty $SMBResult 'SigningOptionalOrDisabledCount' 0)-gt0-or[int](Get-SafeProperty $SMBResult 'InterestingFileNameLeadCount' 0)-gt0){'CandidateDetected'}elseif([int](Get-SafeProperty $SMBResult 'OperationalErrorCount' 0)-gt0-and[int](Get-SafeProperty $SMBResult 'ShareCount' 0)-eq0){'Inconclusive'}else{'Collected'}
    $CoverageRows+=[pscustomobject][ordered]@{Id='SMB.Files';Name='SMB and file exposure';State=$SMBState;Evidence=@($SMBSummary,$SMBManifest,$SMBNmapImportSummary,$SMBMergedTargetList);Limitations=@('Domain controllers are always included. Operator-supplied Nmap XML extends scope only for hosts where TCP/445 is explicitly open. Share enumeration errors and zero returned shares do not prove absence. No write test, relay attempt, or remote execution occurred.')}
}
$Ledger = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Mode = $Mode
    Profile = $Profile
    BootstrapServer = $BootstrapServer
    AttackFamilies = $CoverageRows
    Modules = @($KerberosStageObject,$DcStageObject,$PatchStageObject,$ADCSStageObject,$ADDnsStageObject | Where-Object { $null -ne $_ })
    OperationalErrorCount = $ErrorRows.Count
    NonFatalCollectionMethodErrorCount = $PatchMethodErrorCount
    TotalRecordedOperationalIssueCount = ($ErrorRows.Count + $PatchMethodErrorCount)
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
$FatalOrchestrationErrorCount = $ErrorRows.Count
$NonFatalCollectionMethodErrorCount = $PatchMethodErrorCount
$TotalRecordedOperationalIssueCount = $FatalOrchestrationErrorCount + $NonFatalCollectionMethodErrorCount
$PatchHtml = '<div class="card">Patch-state collection was not selected.</div>'
if ($IncludePatchState) {
    $PatchTableRows = ($PatchApplicabilityRowsForReport | Sort-Object CVE,HostName | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (Convert-HtmlText $_.HostName),(Convert-HtmlText $_.CVE),(Convert-HtmlText $_.Name),(Convert-HtmlText $_.PatchDisposition),(Convert-HtmlText $_.OverallDisposition)
    }) -join "`n"
    if ([string]::IsNullOrWhiteSpace($PatchTableRows)) { $PatchTableRows = '<tr><td colspan="5">No patch applicability evidence available.</td></tr>' }
    $PatchHtml = '<div class="card"><b>Targets:</b> {0}<br><b>Full builds:</b> {1}<br><b>Patched assessments:</b> {2}<br><b>Potentially affected builds:</b> {3}<br><b>Unknown assessments:</b> {4}<br><b>Method-attempt errors:</b> {5}</div><table><tr><th>Host</th><th>CVE</th><th>Name</th><th>Patch disposition</th><th>Overall disposition</th></tr>{6}</table>' -f (Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'TargetCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'FullBuildCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'PatchedBuildDetectedCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'PotentiallyAffectedBuildCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'PatchStateUnknownCount' 0)),(Convert-HtmlText (Get-SafeProperty $PatchSummaryObjectForReport 'OperationalErrorCount' 0)),$PatchTableRows
}
$ADCSHtml = '<div class="card">AD CS collection was not selected.</div>'
$SMBHtml = if ($IncludeSMB -and $null -ne $SMBResult) {
    '<div class="card"><b>Targets:</b> {0}<br><b>TCP/445 reachable:</b> {1}<br><b>Signing optional or disabled:</b> {2}<br><b>Shares:</b> {3}<br><b>Accessible share roots:</b> {4}<br><b>Filename metadata entries:</b> {5}<br><b>Interesting filename leads:</b> {6}<br><b>Nmap XML import:</b> Optional operator-supplied evidence; see linked import summary when present.<br><b>Content reads:</b> None<br><b>Remote changes:</b> None<br><b>Relay attempts:</b> None</div><ul><li><a href="../evidence/SMBFullAssessment/Collector/smb-share-pivot-summary.json">SMB summary</a></li><li><a href="../evidence/SMBFullAssessment/Collector/smb-share-inventory.json">Share inventory</a></li><li><a href="../evidence/SMBFullAssessment/Collector/smb-signing-evidence.json">SMB signing evidence</a></li><li><a href="../evidence/SMBFullAssessment/Collector/evidence-manifest.json">Evidence manifest</a></li></ul>' -f @((Get-SafeProperty $SMBResult 'TargetCount' 0),(Get-SafeProperty $SMBResult 'Tcp445ReachableCount' 0),(Get-SafeProperty $SMBResult 'SigningOptionalOrDisabledCount' 0),(Get-SafeProperty $SMBResult 'ShareCount' 0),(Get-SafeProperty $SMBResult 'AccessibleShareCount' 0),(Get-SafeProperty $SMBResult 'MetadataEntryCount' 0),(Get-SafeProperty $SMBResult 'InterestingFileNameLeadCount' 0))
} else { '<div class="card">SMB assessment was not selected.</div>' }

if ($IncludeADCS) {
    $CandidateRows=@(); if(Test-Path -LiteralPath $ADCSCandidates -PathType Leaf){$CandidateRows=@(Get-Content -LiteralPath $ADCSCandidates -Raw|ConvertFrom-Json -ErrorAction Stop)}
    $ADCSRows=($CandidateRows|Sort-Object @{Expression={ if ([string]$_.Technique -match '^ESC(\d+)$') { [int]$Matches[1] } else { [int]::MaxValue } }},Technique|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}/{4}</td><td>{5}</td></tr>' -f (Convert-HtmlText $_.Technique),(Convert-HtmlText $_.Title),(Convert-HtmlText $_.Disposition),(Convert-HtmlText $_.SatisfiedRequiredCount),(Convert-HtmlText $_.RequiredCount),(Convert-HtmlText $_.SafeFollowUp)}) -join "`n"
    if([string]::IsNullOrWhiteSpace($ADCSRows)){$ADCSRows='<tr><td colspan="6">No AD CS candidate evidence available.</td></tr>'}
    $ADCSHtml='<div class="card"><b>Scope:</b> Read-only AD CS directory configuration and offline ESC1-ESC16 prerequisite correlation.<br><b>Automatic enrollment:</b> None<br><b>Certificate authentication:</b> None<br><b>Private-key access:</b> None<br><b>Remote changes:</b> None</div><table><tr><th>Technique</th><th>Title</th><th>Disposition</th><th>Facts</th><th>Recommended validation</th></tr>{0}</table>' -f $ADCSRows
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

$ReportFileName=if($Profile -eq 'Full'){'MSADPT-Full-Audit.html'}else{'MSADPT-Quick-Audit.html'}
$ReportPath = Join-Path $EngagementDirectory ('reports\'+$ReportFileName)
$ADDnsReportDisposition = if ($null -ne $ADDnsStageObject) { [string]$ADDnsStageObject.Disposition } else { 'NotStarted' }
$ADDnsAuthorizationBreadth=if($null-ne$ADDnsStageObject -and $null-ne$ADDnsStageObject.Result){[string](Get-SafeProperty $ADDnsStageObject.Result 'AuthorizationBreadth' 'Unknown')}else{'Unknown'}
$ADDnsBroadWrite=if($null-ne$ADDnsStageObject -and $null-ne$ADDnsStageObject.Result){[bool](Get-SafeProperty $ADDnsStageObject.Result 'BroadPrincipalWriteDetected' $false)}else{$false}
$Html = @"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT $Profile Audit</title>
<style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body>
<h1>MSADPT $Profile Audit</h1>
<div class="card"><b>Mode:</b> $(Convert-HtmlText $Mode)<br><b>Profile:</b> $(Convert-HtmlText $Profile)<br><b>Bootstrap DC:</b> $(Convert-HtmlText $BootstrapServer)<br><b>Live modules executed:</b> $LiveModulesExecuted<br><b>Modules reused:</b> $SkippedModules<br><b>Operational module errors:</b> $FatalOrchestrationErrorCount<br><b>Nonfatal collection-method errors:</b> $NonFatalCollectionMethodErrorCount<br><b>Total recorded operational issues:</b> $TotalRecordedOperationalIssueCount<br><b>Remote changes:</b> $(Convert-HtmlText $Plan.RemoteChanges)<br><b>Ticket requests:</b> None</div>
<h2>$Profile Results</h2>
<div class="card"><b>Domain controllers inventoried:</b> $DcCount<br><b>SPN records:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'SpnRecords' 0))<br><b>User-owned SPNs:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'UserSpnRecords' 0))<br><b>Duplicate SPN groups:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'DuplicateSpnGroups' 0))<br><b>AS-REP candidates:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'AsRepCandidates' 0))<br><b>Kerberoast candidates:</b> $(Convert-HtmlText (Get-SafeProperty $KerberosCounts 'KerberoastCandidates' 0))<br><b>Delegation candidates:</b> $(Convert-HtmlText (([int](Get-SafeProperty $KerberosCounts 'UnconstrainedDelegationCandidates' 0))+([int](Get-SafeProperty $KerberosCounts 'ConstrainedDelegationCandidates' 0))+([int](Get-SafeProperty $KerberosCounts 'RbcdCandidates' 0))))</div>
<h2>Coverage</h2><table><tr><th>Attack family</th><th>State</th><th>Limitations</th></tr>$CoverageHtml</table>
<h2>AD-Integrated DNS</h2><div class="card"><b>Disposition:</b> $(Convert-HtmlText $ADDnsReportDisposition)<br><b>Behavioral validation selected:</b> $([bool]$EnableBehavioralValidation)<br><b>Authorization breadth:</b> $(Convert-HtmlText $ADDnsAuthorizationBreadth)<br><b>Broad principal write detected:</b> $ADDnsBroadWrite<br>Successful DNS write capability does not by itself prove relay, credential capture, privilege escalation, or domain compromise.</div><ul><li><a href="../analysis/ADDnsSecurity/ad-dns-security-summary.json">DNS security summary</a></li><li><a href="../evidence/ADDnsSecurity/ad-dns-write-validation.json">Write validation evidence</a></li><li><a href="../evidence/ADDnsSecurity/ad-dns-cleanup-manifest.json">Cleanup verification</a></li><li><a href="../evidence/ADDnsSecurity/ad-dns-effective-write-context.json">Effective authorization context</a></li><li><a href="../evidence/ADDnsSecurity/ad-dns-resolution-validation.json">Authoritative resolution validation</a></li><li><a href="../evidence/ADDnsSecurity/ad-dns-inventory.json">DNS inventory</a></li><li><a href="../analysis/ADDnsSecurity/ad-dns-dangling-reference-candidates.json">Dangling-reference candidates</a></li></ul>
<h2>SMB and File Exposure</h2>$SMBHtml
<h2>Active Directory Certificate Services</h2>$ADCSHtml
<h2>Current AD Vulnerabilities</h2>$PatchHtml
<h2>Operational Errors</h2><table><tr><th>Module</th><th>Stage</th><th>Error</th></tr>$ErrorHtml</table>
<h2>Kerberos Cryptographic Posture</h2><p>Focused review is evidence triage, not vulnerability confirmation. Static capability is kept separate from observed ticket usage.</p><ul><li><a href="../analysis/KerberosEncryptionPrioritization/kerberos-encryption-correlation-summary.json">Correlation summary</a></li><li><a href="../analysis/KerberosEncryptionPrioritization/kerberos-prioritized-account-review.json">Prioritized account review</a></li></ul><h2>Evidence</h2><ul><li><a href="../state/execution-plan.json">Execution plan</a></li><li><a href="../state/coverage-ledger.json">Coverage ledger</a></li><li><a href="../evidence/KerberosSPNBaseline/kerberos-spn-baseline-summary.json">Kerberos summary</a></li><li><a href="../evidence/DomainControllerEnumeration/domain-controller-details.json">Domain-controller inventory</a></li><li><a href="../evidence/SMBFullAssessment/Collector/smb-share-pivot-summary.json">SMB assessment summary</a></li><li><a href="../analysis/ADCSOfflineEvidenceToCandidate/adcs-offline-pipeline-summary.json">AD CS pipeline summary</a></li><li><a href="../analysis/ADCSOfflineEvidenceToCandidate/Correlation/adcs-technique-candidates.json">AD CS candidates</a></li><li><a href="../evidence/DomainControllerPatchState/patch-state-summary.json">Domain-controller patch-state summary</a></li><li><a href="../evidence/DomainControllerPatchState/ad-vulnerability-applicability.json">AD vulnerability applicability</a></li><li><a href="../errors/operational-errors.json">Operational errors</a></li></ul>
<p class="note">Configuration and static candidates are leads. The selected profile does not request passwords or automatically reproduce downstream security impact.</p></body></html>
"@
[IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

$OverallStatus = if ($ErrorRows.Count -eq 0) { 'Passed' } elseif ($LiveModulesExecuted -gt 0 -or $SkippedModules -gt 0) { 'PassedWithErrors' } else { 'Failed' }
Show -State 'REPORT' -Message $ReportPath -Color Cyan
Show -State 'DONE' -Message "Status=$OverallStatus; live=$LiveModulesExecuted; reused=$SkippedModules; operational-errors=$FatalOrchestrationErrorCount; nonfatal-method-errors=$NonFatalCollectionMethodErrorCount." -Color Green

[pscustomobject][ordered]@{
    Status = $OverallStatus
    Mode = $Mode
    Profile = $Profile
    EngagementDirectory = $EngagementDirectory
    BootstrapServer = $BootstrapServer
    RegistryModuleCount = [int]$Registry.ModuleCount
    IntegratedModuleCount = $Integrated.Count
    OptionalIntegratedModuleCount = $IntegratedOptional.Count
    StandaloneModuleCount = $Standalone.Count
    LiveModulesExecuted = $LiveModulesExecuted
    ReusedModuleCount = $SkippedModules
    OperationalErrorCount = $FatalOrchestrationErrorCount
    NonFatalCollectionMethodErrorCount = $NonFatalCollectionMethodErrorCount
    TotalRecordedOperationalIssueCount = $TotalRecordedOperationalIssueCount
    ADDnsIncluded = [bool]$IncludeADDns
    ADDnsBehavioralValidationEnabled = [bool]$EnableBehavioralValidation
    ADDnsExecuted = [bool]$ADDnsExecuted
    ADDnsReused = [bool]$ADDnsReused
    ADCSIncluded = [bool]$IncludeADCS
    ADCSExecuted = [bool]$ADCSExecuted
    ADCSReused = [bool]$ADCSReused
    KerberosCryptographicPostureIncluded = [bool]$IncludeKerberosCrypto
    KdcTelemetryIncluded = [bool]$IncludeKdcTelemetry
    SMBIncluded = [bool]$IncludeSMB
    SMBExecuted = [bool]$SMBExecuted
    SMBReused = [bool]$SMBReused
    PatchStateIncluded = [bool]$IncludePatchState
    PatchStateExecuted = [bool]$PatchExecuted
    PatchStateReused = [bool]$PatchReused
    CoverageLedgerPath = $LedgerPath
    ExecutionPlanPath = $ExecutionPlanPath
    HtmlReportPath = $ReportPath
}