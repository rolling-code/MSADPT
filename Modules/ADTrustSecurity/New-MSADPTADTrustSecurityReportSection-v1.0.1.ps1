<#
.SYNOPSIS
Builds a normalized MSADPT report section from AD Trust Security evidence.

.DESCRIPTION
Reads an existing AD Trust Security collection, distinguishes active trust absence from retained
foreign-principal inventory, preserves remote-validation boundaries, and emits normalized JSON plus
a reusable HTML fragment. No Active Directory, network, Git, or external service is contacted.

.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CollectionDirectory,

    [string]$OutputDirectory,

    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,

    [ValidateSet('Plan','Audit','Analyze','Resume','Standalone')]
    [string]$Mode = 'Analyze',

    [ValidateSet('Quick','Full','Standalone','NotApplicable')]
    [string]$Profile = 'Standalone',

    [switch]$OpenHtml,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.1'

function Write-Status {
    param(
        [ValidateSet('INFO','READ','ANALYZE','PASS','WARN','REPORT')]
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

function Read-JsonArray {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required evidence file not found: $Path"
    }

    $Value = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    foreach ($Item in @($Value)) {
        Write-Output -NoEnumerate $Item
    }
}

function New-Metric {
    param(
        [string]$Id,
        [string]$Label,
        [AllowNull()][object]$Value,
        [ValidateSet('Good','Informational','Attention','Unavailable','NotApplicable')]
        [string]$State,
        [string]$Description
    )

    [pscustomobject][ordered]@{
        id = $Id
        label = $Label
        value = $Value
        state = $State
        description = $Description
    }
}

function New-Finding {
    param(
        [string]$Id,
        [string]$Title,
        [ValidateSet('Confirmed','Likely or probable','Inconclusive','Not detected','Not applicable')]
        [string]$Disposition,
        [string]$Summary,
        [string[]]$Evidence,
        [string[]]$Limitations,
        [string]$Recommendation,
        [ValidateSet('Immediate','High','Normal','Informational','NotApplicable')]
        [string]$Priority
    )

    [pscustomobject][ordered]@{
        id = $Id
        title = $Title
        disposition = $Disposition
        summary = $Summary
        evidence = @($Evidence)
        limitations = @($Limitations)
        recommendation = $Recommendation
        priority = $Priority
    }
}

$StartedUtc = (Get-Date).ToUniversalTime()
$CollectionDirectory = Resolve-FullPath -Path $CollectionDirectory
$RepositoryRoot = Resolve-FullPath -Path $RepositoryRoot

if (-not (Test-Path -LiteralPath $CollectionDirectory -PathType Container)) {
    throw "Collection directory not found: $CollectionDirectory"
}

$RawDirectory = Join-Path $CollectionDirectory 'Raw'
if (-not (Test-Path -LiteralPath $RawDirectory -PathType Container)) {
    throw "Raw evidence directory not found: $RawDirectory"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $CollectionDirectory 'Analysis'
}
$OutputDirectory = Resolve-FullPath -Path $OutputDirectory
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$ReportingModulePath = Join-Path $RepositoryRoot 'Common\MSADPT.Reporting.psm1'
if (-not (Test-Path -LiteralPath $ReportingModulePath -PathType Leaf)) {
    throw "Reporting module not found: $ReportingModulePath"
}
Import-Module $ReportingModulePath -Force -ErrorAction Stop

Write-Status -State INFO -Message "Collection: $CollectionDirectory" -Color Cyan
Write-Status -State INFO -Message 'Network activity: None; directory changes: None.' -Color Green
Write-Status -State READ -Message 'Loading trust APIs, trustedDomain objects, ACLs, SID history, foreign principals, and operational evidence.' -Color Cyan

$ContextPath = Join-Path $RawDirectory 'trust-context.json'
$TrustsPath = Join-Path $RawDirectory 'ad-trusts.json'
$TrustObjectsPath = Join-Path $RawDirectory 'trusted-domain-objects.json'
$TrustAclsPath = Join-Path $RawDirectory 'trusted-domain-acls.json'
$SidHistoryPath = Join-Path $RawDirectory 'sid-history-principals.json'
$ForeignPrincipalsPath = Join-Path $RawDirectory 'foreign-security-principals.json'
$NltestPath = Join-Path $RawDirectory 'nltest-output.json'
$ErrorsPath = Join-Path $RawDirectory 'operational-errors.json'
$PlanPath = Join-Path $RawDirectory 'collection-plan.json'
$ManifestPath = Join-Path $CollectionDirectory 'evidence-manifest.json'

$Context = Get-Content -LiteralPath $ContextPath -Raw -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop
$Trusts = @(Read-JsonArray -Path $TrustsPath)
$TrustObjects = @(Read-JsonArray -Path $TrustObjectsPath)
$TrustAcls = @(Read-JsonArray -Path $TrustAclsPath)
$SidHistoryPrincipals = @(Read-JsonArray -Path $SidHistoryPath)
$ForeignPrincipals = @(Read-JsonArray -Path $ForeignPrincipalsPath)
$NltestOutput = @(Read-JsonArray -Path $NltestPath)
$OperationalErrors = @(Read-JsonArray -Path $ErrorsPath)
$CollectionPlan = @(Read-JsonArray -Path $PlanPath)

$TrustCount = $Trusts.Count
$TrustObjectCount = $TrustObjects.Count
$TrustAclCount = $TrustAcls.Count
$SidHistoryCount = $SidHistoryPrincipals.Count
$ForeignPrincipalCount = $ForeignPrincipals.Count
$NltestCommandCount = $NltestOutput.Count
$OperationalErrorCount = $OperationalErrors.Count
$PlanOperationCount = $CollectionPlan.Count

$Target = [string]$Context.Server
$CollectorVersion = [string]$Context.Version
if ([string]::IsNullOrWhiteSpace($CollectorVersion)) { $CollectorVersion = 'Unknown' }
$RemoteValidationPerformed = if ($null -ne $Context.PSObject.Properties['RemoteTrustValidation']) {
    [bool]$Context.RemoteTrustValidation
}
else {
    $false
}

Write-Status -State READ -Message ("Loaded arrays: Trusts={0}; TrustedDomainObjects={1}; TrustAcls={2}; SidHistory={3}; ForeignPrincipals={4}; Nltest={5}; Errors={6}; PlanOperations={7}." -f $TrustCount,$TrustObjectCount,$TrustAclCount,$SidHistoryCount,$ForeignPrincipalCount,$NltestCommandCount,$OperationalErrorCount,$PlanOperationCount) -Color Gray
Write-Status -State ANALYZE -Message ("Trusts={0}; trustedDomainObjects={1}; foreignPrincipals={2}; remoteValidation={3}." -f $TrustCount,$TrustObjectCount,$ForeignPrincipalCount,$RemoteValidationPerformed) -Color Cyan

$Metrics = @(
    New-Metric -Id 'ad-trusts' -Label 'AD Trusts' -Value $TrustCount -State $(if ($TrustCount -gt 0) { 'Informational' } else { 'Good' }) -Description 'Trust relationships returned by the Active Directory trust API.'
    New-Metric -Id 'trusted-domain-objects' -Label 'trustedDomain Objects' -Value $TrustObjectCount -State $(if ($TrustObjectCount -gt 0) { 'Informational' } else { 'Good' }) -Description 'trustedDomain directory objects returned from the domain naming context.'
    New-Metric -Id 'trust-acls' -Label 'Trust ACL Entries' -Value $TrustAclCount -State $(if ($TrustObjectCount -gt 0) { 'Informational' } else { 'NotApplicable' }) -Description 'Access-control entries collected from trustedDomain objects.'
    New-Metric -Id 'sid-history-principals' -Label 'SID History Principals' -Value $SidHistoryCount -State $(if ($SidHistoryCount -gt 0) { 'Attention' } else { 'Good' }) -Description 'Principals with SID history returned by the collector.'
    New-Metric -Id 'foreign-security-principals' -Label 'Foreign Security Principals' -Value $ForeignPrincipalCount -State $(if ($ForeignPrincipalCount -gt 0) { 'Informational' } else { 'Good' }) -Description 'Foreign Security Principal objects retained in the directory.'
    New-Metric -Id 'remote-validation' -Label 'Remote Trust Validation' -Value $(if ($RemoteValidationPerformed) { 'Performed' } else { 'Not performed' }) -State $(if ($RemoteValidationPerformed) { 'Good' } else { 'Unavailable' }) -Description 'Whether remote trust authentication or partner validation was performed.'
    New-Metric -Id 'operational-errors' -Label 'Operational Errors' -Value $OperationalErrorCount -State $(if ($OperationalErrorCount -gt 0) { 'Attention' } else { 'Good' }) -Description 'Collector operational errors.'
)

$Findings = [Collections.Generic.List[object]]::new()

if ($TrustCount -eq 0 -and $TrustObjectCount -eq 0) {
    $Findings.Add((New-Finding `
        -Id 'active-trusts-not-detected' `
        -Title 'Active trust relationships were not detected' `
        -Disposition 'Not detected' `
        -Summary 'Neither the Active Directory trust API nor trustedDomain object inventory returned a current trust relationship.' `
        -Evidence @(
            "Trust API count: $TrustCount.",
            "trustedDomain object count: $TrustObjectCount.",
            "Operational error count: $OperationalErrorCount."
        ) `
        -Limitations @(
            'Not detected does not prove that every historical, external, or unreachable trust condition is absent.',
            'Remote trust authentication and partner-domain behavior were not tested unless explicitly recorded.'
        ) `
        -Recommendation 'No trust remediation is indicated from this evidence alone. Revalidate only when architecture, migration, or foreign-principal evidence suggests an expected trust.' `
        -Priority 'Informational'))
}
else {
    $Findings.Add((New-Finding `
        -Id 'active-trust-inventory' `
        -Title 'Active trust relationships were collected' `
        -Disposition 'Confirmed' `
        -Summary "$TrustCount trust API records and $TrustObjectCount trustedDomain objects were collected for boundary analysis." `
        -Evidence @("Trust API count: $TrustCount.","trustedDomain object count: $TrustObjectCount.","Trust ACL entry count: $TrustAclCount.") `
        -Limitations @('Trust presence does not by itself establish insecure SID filtering, selective authentication, or delegation.') `
        -Recommendation 'Evaluate direction, type, transitivity, SID filtering, selective authentication, TGT delegation, object ACLs, and business necessity.' `
        -Priority 'Normal'))
}

if ($ForeignPrincipalCount -gt 0) {
    $Findings.Add((New-Finding `
        -Id 'foreign-security-principal-inventory' `
        -Title 'Foreign Security Principal objects remain in the directory' `
        -Disposition 'Confirmed' `
        -Summary "$ForeignPrincipalCount Foreign Security Principal objects were inventoried independently from current trust detection." `
        -Evidence @("Foreign Security Principal count: $ForeignPrincipalCount.","Current trust count: $TrustCount.","trustedDomain object count: $TrustObjectCount.") `
        -Limitations @(
            'Foreign Security Principal presence does not prove a current trust.',
            'An FSP may reflect historical access, migration, external membership, or unresolved directory references.'
        ) `
        -Recommendation 'Correlate foreign principal SIDs with group memberships, ACLs, business ownership, historical migrations, and any expected trust boundary before cleanup.' `
        -Priority 'Informational'))
}
else {
    $Findings.Add((New-Finding `
        -Id 'foreign-security-principals-not-detected' `
        -Title 'Foreign Security Principal objects were not detected' `
        -Disposition 'Not detected' `
        -Summary 'No Foreign Security Principal objects were returned by the collected inventory.' `
        -Evidence @("Foreign Security Principal count: $ForeignPrincipalCount.") `
        -Limitations @('This does not independently prove that no foreign SID is represented in every security descriptor or historical artifact.') `
        -Recommendation 'No FSP-specific follow-up is indicated unless another module identifies unresolved foreign SIDs.' `
        -Priority 'Informational'))
}

if ($SidHistoryCount -gt 0) {
    $Findings.Add((New-Finding `
        -Id 'sid-history-present' `
        -Title 'SID history-bearing principals were detected' `
        -Disposition 'Confirmed' `
        -Summary "$SidHistoryCount principals with SID history were returned and require ownership and migration-context review." `
        -Evidence @("SID history principal count: $SidHistoryCount.") `
        -Limitations @('SID history presence is not automatically malicious or exploitable.') `
        -Recommendation 'Verify migration justification, source SID provenance, current authorization effect, and retirement plan.' `
        -Priority 'Normal'))
}

if (-not $RemoteValidationPerformed) {
    $Findings.Add((New-Finding `
        -Id 'remote-trust-validation-not-performed' `
        -Title 'Remote trust validation was not performed' `
        -Disposition 'Not applicable' `
        -Summary 'The collector performed local read-only trust and directory inventory without authenticating to or testing a partner domain.' `
        -Evidence @("NLTEST command-result count: $NltestCommandCount.",'Remote trust validation flag: false.') `
        -Limitations @('Partner reachability, cross-boundary authentication, and remote policy behavior were not tested.') `
        -Recommendation 'Perform bounded remote validation only when an active trust is detected and a specific security decision requires it.' `
        -Priority 'NotApplicable'))
}

$ExecutionStatus = if ($OperationalErrorCount -gt 0) { 'CompletedWithLimitations' } else { 'Completed' }
$EvidenceComplete = $OperationalErrorCount -eq 0
$Disposition = if ($OperationalErrorCount -gt 0) {
    'Inconclusive'
}
elseif ($TrustCount -eq 0 -and $TrustObjectCount -eq 0) {
    'Not detected'
}
else {
    'Confirmed'
}
$Confidence = if ($OperationalErrorCount -eq 0) { 'High' } else { 'Medium' }

$SummaryText = if ($Disposition -eq 'Inconclusive') {
    'Trust evidence was collected, but operational errors prevent a complete local trust-boundary conclusion.'
}
elseif ($Disposition -eq 'Not detected') {
    'No current trust relationship was detected through the trust API or trustedDomain inventory; retained foreign-principal evidence is reported separately.'
}
else {
    'Current trust relationships were collected and are available for direction, filtering, delegation, ACL, and business-necessity analysis.'
}

$EvidenceFiles = @(
    @{ Label='Trust context'; Path=$ContextPath; MediaType='application/json' },
    @{ Label='AD trusts'; Path=$TrustsPath; MediaType='application/json' },
    @{ Label='trustedDomain objects'; Path=$TrustObjectsPath; MediaType='application/json' },
    @{ Label='trustedDomain ACLs'; Path=$TrustAclsPath; MediaType='application/json' },
    @{ Label='SID history principals'; Path=$SidHistoryPath; MediaType='application/json' },
    @{ Label='Foreign Security Principals'; Path=$ForeignPrincipalsPath; MediaType='application/json' },
    @{ Label='NLTEST output'; Path=$NltestPath; MediaType='application/json' },
    @{ Label='Operational errors'; Path=$ErrorsPath; MediaType='application/json' },
    @{ Label='Collection plan'; Path=$PlanPath; MediaType='application/json' },
    @{ Label='Evidence manifest'; Path=$ManifestPath; MediaType='application/json' }
)

$EvidenceLinks = @(
    foreach ($EvidenceFile in $EvidenceFiles) {
        [pscustomobject][ordered]@{
            label = [string]$EvidenceFile.Label
            relativePath = ([IO.Path]::GetRelativePath($CollectionDirectory, [string]$EvidenceFile.Path) -replace '\\','/')
            mediaType = [string]$EvidenceFile.MediaType
            exists = Test-Path -LiteralPath ([string]$EvidenceFile.Path) -PathType Leaf
        }
    }
)

$Limitations = [Collections.Generic.List[string]]::new()
if (-not $RemoteValidationPerformed) {
    $Limitations.Add('Remote trust authentication and partner-domain behavior were not tested.')
}
if ($ForeignPrincipalCount -gt 0) {
    $Limitations.Add('Foreign Security Principal objects were collected as retained directory inventory and must not be equated with current trusts.')
}
if ($OperationalErrorCount -gt 0) {
    $Limitations.Add('Operational errors were recorded; review structured error evidence before relying on completeness.')
}
$Limitations.Add('Not detected does not mean confirmed absent beyond the successfully queried local interfaces and naming contexts.')

$Recommendations = @(
    'Correlate Foreign Security Principal SIDs with privileged groups, ACLs, unresolved trustee evidence, and known migration history.',
    'Perform remote trust validation only when a current trust is detected and the result will support a specific security decision.',
    'Preserve current-trust evidence separately from historical or retained foreign-principal evidence.'
)

$CompletedUtc = (Get-Date).ToUniversalTime()
$Section = New-MSADPTReportSection `
    -ModuleId 'Collect-MSADPTADTrustSecurity' `
    -ModuleVersion $CollectorVersion `
    -Title 'AD Trust Security' `
    -Category 'Trusts' `
    -ExecutionStatus $ExecutionStatus `
    -Mode $Mode `
    -Profile $Profile `
    -Target $Target `
    -StartedUtc $StartedUtc.ToString('o') `
    -CompletedUtc $CompletedUtc.ToString('o') `
    -DurationSeconds ([math]::Round(($CompletedUtc - $StartedUtc).TotalSeconds, 3)) `
    -ReusedEvidence $true `
    -NetworkExecuted $false `
    -DirectoryChanges 'None' `
    -Disposition $Disposition `
    -Summary $SummaryText `
    -Confidence $Confidence `
    -EvidenceComplete $EvidenceComplete `
    -Metrics $Metrics `
    -Findings @($Findings) `
    -EvidenceLinks $EvidenceLinks `
    -Limitations @($Limitations) `
    -Recommendations $Recommendations

$Validation = Test-MSADPTReportSection -Section $Section -EvidenceRoot $CollectionDirectory
if (-not $Validation.valid) {
    throw "Report-section validation failed: $($Validation.errors -join '; ')"
}

$SectionJsonPath = Join-Path $OutputDirectory 'ad-trust-security-report-section.json'
$SectionHtmlPath = Join-Path $OutputDirectory 'ad-trust-security-report-section.html'
$ValidationPath = Join-Path $OutputDirectory 'ad-trust-security-report-section-validation.json'

ConvertTo-Json -InputObject $Section -Depth 16 |
    Set-Content -LiteralPath $SectionJsonPath -Encoding UTF8
ConvertTo-Json -InputObject $Validation -Depth 8 |
    Set-Content -LiteralPath $ValidationPath -Encoding UTF8
$SectionHtml = ConvertTo-MSADPTReportSectionHtml `
    -Section $Section `
    -EvidenceLinkPrefix '../'
[IO.File]::WriteAllText($SectionHtmlPath, $SectionHtml, (New-Object Text.UTF8Encoding($false)))

foreach ($OutputPath in @($SectionJsonPath,$SectionHtmlPath,$ValidationPath)) {
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "Expected output file was not created: $OutputPath"
    }
    if ((Get-Item -LiteralPath $OutputPath).Length -eq 0) {
        throw "Expected output file is empty: $OutputPath"
    }
}
$null = Get-Content -LiteralPath $SectionJsonPath -Raw | ConvertFrom-Json -ErrorAction Stop
$null = Get-Content -LiteralPath $ValidationPath -Raw | ConvertFrom-Json -ErrorAction Stop

Write-Status -State PASS -Message ("Report section completed: disposition={0}; findings={1}; evidenceComplete={2}." -f $Disposition,$Findings.Count,$EvidenceComplete) -Color Green
Write-Status -State REPORT -Message $SectionHtmlPath -Color Cyan

if ($OpenHtml) {
    Start-Process -FilePath $SectionHtmlPath
}

[pscustomobject][ordered]@{
    Status = 'Completed'
    Version = $Version
    ModuleVersion = $CollectorVersion
    Disposition = $Disposition
    ExecutionStatus = $ExecutionStatus
    TrustCount = $TrustCount
    TrustedDomainObjectCount = $TrustObjectCount
    ForeignSecurityPrincipalCount = $ForeignPrincipalCount
    SidHistoryPrincipalCount = $SidHistoryCount
    FindingCount = $Findings.Count
    MetricCount = $Metrics.Count
    EvidenceLinkCount = $EvidenceLinks.Count
    EvidenceComplete = $EvidenceComplete
    ValidationErrors = $Validation.errorCount
    ValidationWarnings = $Validation.warningCount
    ReportSectionJsonPath = $SectionJsonPath
    ReportSectionHtmlPath = $SectionHtmlPath
    ValidationPath = $ValidationPath
    NetworkActivity = 'None'
    DirectoryChanges = 'None'
}
