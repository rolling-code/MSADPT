<#
.SYNOPSIS
Builds a normalized MSADPT report section from Authentication Policy Security evidence.

.DESCRIPTION
Reads an existing Authentication Policy Security collection, preserves negative results and evidence
limitations, emits normalized report-section JSON, and renders a reusable HTML fragment. No Active
Directory, network, Git, or external service is contacted.

.NOTES
Version: 1.0.4
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
$Version = '1.0.4'

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
Write-Status -State READ -Message 'Loading Authentication Policy, Silo, assignment, Protected Users, and limitation evidence.' -Color Cyan

$PolicyPath = Join-Path $RawDirectory 'authentication-policies.json'
$SiloPath = Join-Path $RawDirectory 'authentication-policy-silos.json'
$SiloMembersPath = Join-Path $RawDirectory 'authentication-policy-silo-members.json'
$AssignedPath = Join-Path $RawDirectory 'assigned-authentication-policy-principals.json'
$ProtectedUsersPath = Join-Path $RawDirectory 'protected-users-membership.json'
$PrincipalsPath = Join-Path $RawDirectory 'policy-relevant-principals.json'
$UnresolvedPath = Join-Path $RawDirectory 'unresolved-policy-references.json'
$ErrorsPath = Join-Path $RawDirectory 'operational-errors.json'
$JsonValidationPath = Join-Path $RawDirectory 'json-validation.json'
$ContextPath = Join-Path $RawDirectory 'authentication-policy-context.json'
$ManifestPath = Join-Path $CollectionDirectory 'evidence-manifest.json'

$Policies = @(Read-JsonArray -Path $PolicyPath)
$Silos = @(Read-JsonArray -Path $SiloPath)
$SiloMembers = @(Read-JsonArray -Path $SiloMembersPath)
$AssignedPrincipals = @(Read-JsonArray -Path $AssignedPath)
$ProtectedUsers = @(Read-JsonArray -Path $ProtectedUsersPath)
$RelevantPrincipals = @(Read-JsonArray -Path $PrincipalsPath)
$UnresolvedReferences = @(Read-JsonArray -Path $UnresolvedPath)
$OperationalErrors = @(Read-JsonArray -Path $ErrorsPath)
$JsonValidationSource = 'CollectorArtifact'
if (Test-Path -LiteralPath $JsonValidationPath -PathType Leaf) {
    $JsonValidation = @(Read-JsonArray -Path $JsonValidationPath)
}
else {
    $JsonValidationSource = 'DirectParse'
    $JsonValidation = @()
    Write-Status -State WARN -Message 'json-validation.json is absent. The adapter validated each required substantive JSON file directly while loading it.' -Color Yellow
}
$Context = Get-Content -LiteralPath $ContextPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

$PolicyCount = $Policies.Count
$SiloCount = $Silos.Count
$EnforcedSiloCount = @($Silos | Where-Object { $_.Enforced }).Count
$SiloMemberCount = $SiloMembers.Count
$AssignedPrincipalCount = $AssignedPrincipals.Count
$ProtectedUsersCount = $ProtectedUsers.Count
$RelevantPrincipalCount = $RelevantPrincipals.Count
$UnresolvedCount = $UnresolvedReferences.Count
$OperationalErrorCount = $OperationalErrors.Count
$JsonValidationFailureCount = @($JsonValidation | Where-Object { -not $_.Valid }).Count

Write-Status -State READ -Message ("Loaded arrays: Policies={0}; Silos={1}; SiloMembers={2}; Assigned={3}; ProtectedUsers={4}; Principals={5}; Unresolved={6}; Errors={7}; JsonValidation={8}; ValidationSource={9}." -f $Policies.Count,$Silos.Count,$SiloMembers.Count,$AssignedPrincipals.Count,$ProtectedUsers.Count,$RelevantPrincipals.Count,$UnresolvedReferences.Count,$OperationalErrors.Count,$JsonValidation.Count,$JsonValidationSource) -Color Gray
$PostureAvailableCount = @(
    $RelevantPrincipals | Where-Object {
        $Property = $_.PSObject.Properties['PostureComplete']
        $null -ne $Property -and [bool]$Property.Value
    }
).Count
$PostureUnavailableCount = $RelevantPrincipalCount - $PostureAvailableCount

$Target = [string]$Context.Server
$CollectorVersion = [string]$Context.Version
if ([string]::IsNullOrWhiteSpace($CollectorVersion)) { $CollectorVersion = 'Unknown' }

Write-Status -State ANALYZE -Message ("Policies={0}; Silos={1}; Assignments={2}; ProtectedUsers={3}; PostureUnavailable={4}." -f $PolicyCount,$SiloCount,$AssignedPrincipalCount,$ProtectedUsersCount,$PostureUnavailableCount) -Color Cyan

$Metrics = @(
    New-Metric -Id 'authentication-policies' -Label 'Authentication Policies' -Value $PolicyCount -State $(if ($PolicyCount -gt 0) { 'Informational' } else { 'NotApplicable' }) -Description 'Authentication Policy objects returned from the configuration partition.'
    New-Metric -Id 'authentication-policy-silos' -Label 'Authentication Policy Silos' -Value $SiloCount -State $(if ($SiloCount -gt 0) { 'Informational' } else { 'NotApplicable' }) -Description 'Authentication Policy Silo objects returned from the configuration partition.'
    New-Metric -Id 'enforced-silos' -Label 'Enforced Silos' -Value $EnforcedSiloCount -State $(if ($SiloCount -eq 0) { 'NotApplicable' } elseif ($EnforcedSiloCount -gt 0) { 'Good' } else { 'Attention' }) -Description 'Silos with enforcement enabled.'
    New-Metric -Id 'assigned-principals' -Label 'Assigned Principals' -Value $AssignedPrincipalCount -State $(if ($AssignedPrincipalCount -gt 0) { 'Informational' } else { 'NotApplicable' }) -Description 'Principals with a direct Authentication Policy or Silo assignment.'
    New-Metric -Id 'protected-users' -Label 'Protected Users Members' -Value $ProtectedUsersCount -State $(if ($ProtectedUsersCount -gt 0) { 'Good' } else { 'Informational' }) -Description 'Recursively resolved Protected Users members.'
    New-Metric -Id 'posture-available' -Label 'Principal Posture Available' -Value $PostureAvailableCount -State $(if ($PostureAvailableCount -eq $RelevantPrincipalCount -and $RelevantPrincipalCount -gt 0) { 'Good' } else { 'Unavailable' }) -Description 'Relevant principals for which extended account posture was available.'
    New-Metric -Id 'posture-unavailable' -Label 'Principal Posture Unavailable' -Value $PostureUnavailableCount -State $(if ($PostureUnavailableCount -gt 0) { 'Unavailable' } else { 'Good' }) -Description 'Relevant principals whose identity was resolved but extended posture attributes were unavailable.'
    New-Metric -Id 'operational-errors' -Label 'Operational Errors' -Value $OperationalErrorCount -State $(if ($OperationalErrorCount -gt 0) { 'Attention' } else { 'Good' }) -Description 'Collector operational errors.'
)

$Findings = [Collections.Generic.List[object]]::new()

if ($PolicyCount -eq 0 -and $SiloCount -eq 0 -and $AssignedPrincipalCount -eq 0) {
    $Findings.Add((New-Finding `
        -Id 'authn-policy-not-detected' `
        -Title 'Authentication Policies and Silos were not detected' `
        -Disposition 'Not detected' `
        -Summary 'No Authentication Policy objects, Authentication Policy Silo objects, or direct policy/silo assignments were returned by the collected interfaces.' `
        -Evidence @(
            "Authentication Policy count: $PolicyCount.",
            "Authentication Policy Silo count: $SiloCount.",
            "Assigned principal count: $AssignedPrincipalCount.",
            "Operational error count: $OperationalErrorCount."
        ) `
        -Limitations @(
            'Absence of Authentication Policies or Silos is not independently a vulnerability.',
            'Other controls may restrict sensitive identities.'
        ) `
        -Recommendation 'Correlate privileged identities, Protected Users membership, delegation posture, and existing tiering controls before recommending policy deployment.' `
        -Priority 'Informational'))
}
else {
    $Findings.Add((New-Finding `
        -Id 'authn-policy-inventory' `
        -Title 'Authentication Policy and Silo configuration was collected' `
        -Disposition 'Confirmed' `
        -Summary 'Authentication Policy or Silo configuration exists and requires assignment and enforcement analysis.' `
        -Evidence @("Policies: $PolicyCount.","Silos: $SiloCount.","Enforced silos: $EnforcedSiloCount.","Assigned principals: $AssignedPrincipalCount.") `
        -Limitations @('Configuration presence alone does not prove effective enforcement for every identity.') `
        -Recommendation 'Review policy expressions, silo enforcement, membership, assignments, and affected identity classes.' `
        -Priority 'Normal'))
}

$Findings.Add((New-Finding `
    -Id 'protected-users-membership' `
    -Title 'Protected Users membership was collected' `
    -Disposition $(if ($ProtectedUsersCount -gt 0) { 'Confirmed' } else { 'Not detected' }) `
    -Summary $(if ($ProtectedUsersCount -gt 0) { "$ProtectedUsersCount Protected Users members were resolved with identity evidence." } else { 'No Protected Users members were returned by the collected interface.' }) `
    -Evidence @("Resolved Protected Users membership count: $ProtectedUsersCount.","Policy-relevant principal count: $RelevantPrincipalCount.") `
    -Limitations @('Protected Users membership is a separate control from Authentication Policy and Silo assignment.','Membership alone does not prove complete privileged-account coverage.') `
    -Recommendation 'Correlate Protected Users membership with effective privileged-group paths and other sensitive-account inventories.' `
    -Priority 'Informational'))

if ($PostureUnavailableCount -gt 0) {
    $Findings.Add((New-Finding `
        -Id 'principal-posture-unavailable' `
        -Title 'Extended principal posture was unavailable' `
        -Disposition 'Inconclusive' `
        -Summary "$PostureUnavailableCount relevant principals were identity-resolved, but extended posture attributes were unavailable to the collection identity through the attempted interfaces." `
        -Evidence @(
            "Relevant principal count: $RelevantPrincipalCount.",
            "Posture-available count: $PostureAvailableCount.",
            "Posture-unavailable count: $PostureUnavailableCount.",
            'Identity and SID evidence remained available.'
        ) `
        -Limitations @(
            'Unavailable attributes must not be interpreted as absent values.',
            'Authentication Policy evidence should be correlated with Kerberos, privileged-group, managed-secret, and Directory Control evidence.'
        ) `
        -Recommendation 'Use existing MSADPT evidence keyed by SID for offline correlation; perform additional live collection only if a specific decision remains blocked.' `
        -Priority 'Informational'))
}

if ($UnresolvedCount -gt 0) {
    $Findings.Add((New-Finding `
        -Id 'unresolved-policy-references' `
        -Title 'Authentication Policy references require resolution' `
        -Disposition 'Inconclusive' `
        -Summary "$UnresolvedCount policy, silo, or membership references were not resolved." `
        -Evidence @("Unresolved reference count: $UnresolvedCount.") `
        -Limitations @('An unresolved reference is not automatically stale or exploitable.') `
        -Recommendation 'Classify each unresolved reference using targeted directory evidence before remediation.' `
        -Priority 'Normal'))
}

$ExecutionStatus = if ($OperationalErrorCount -gt 0) {
    'CompletedWithLimitations'
}
elseif ($PostureUnavailableCount -gt 0 -or $UnresolvedCount -gt 0) {
    'CompletedWithLimitations'
}
else {
    'Completed'
}

$Disposition = if ($OperationalErrorCount -gt 0 -or $PostureUnavailableCount -gt 0 -or $UnresolvedCount -gt 0) {
    'Inconclusive'
}
elseif ($PolicyCount -eq 0 -and $SiloCount -eq 0 -and $AssignedPrincipalCount -eq 0) {
    'Not detected'
}
else {
    'Confirmed'
}

$EvidenceComplete = $OperationalErrorCount -eq 0 -and $UnresolvedCount -eq 0 -and $PostureUnavailableCount -eq 0
$Confidence = if ($OperationalErrorCount -eq 0) { 'High' } else { 'Medium' }
$SummaryText = if ($Disposition -eq 'Inconclusive') {
    'Policy, Silo, assignment, and Protected Users evidence was collected, but one or more account-posture or reference limitations prevent a complete identity-protection conclusion.'
}
elseif ($Disposition -eq 'Not detected') {
    'No Authentication Policies, Silos, or direct assignments were detected; Protected Users evidence remains a separate compensating-control inventory.'
}
else {
    'Authentication Policy and Silo configuration was collected and is available for enforcement and coverage analysis.'
}

$EvidenceFiles = @(
    @{ Label='Authentication Policies'; Path=$PolicyPath; MediaType='application/json' },
    @{ Label='Authentication Policy Silos'; Path=$SiloPath; MediaType='application/json' },
    @{ Label='Assigned principals'; Path=$AssignedPath; MediaType='application/json' },
    @{ Label='Protected Users membership'; Path=$ProtectedUsersPath; MediaType='application/json' },
    @{ Label='Policy-relevant principals'; Path=$PrincipalsPath; MediaType='application/json' },
    @{ Label='Unresolved references'; Path=$UnresolvedPath; MediaType='application/json' },
    @{ Label='Operational errors'; Path=$ErrorsPath; MediaType='application/json' },
    @{ Label='JSON validation'; Path=$JsonValidationPath; MediaType='application/json' },
    @{ Label='Evidence manifest'; Path=$ManifestPath; MediaType='application/json' }
)

$EvidenceLinks = @(
    foreach ($EvidenceFile in $EvidenceFiles) {
        $RelativePath = [IO.Path]::GetRelativePath($CollectionDirectory, [string]$EvidenceFile.Path)
        [pscustomobject][ordered]@{
            label = [string]$EvidenceFile.Label
            relativePath = $RelativePath -replace '\\','/'
            mediaType = [string]$EvidenceFile.MediaType
            exists = Test-Path -LiteralPath ([string]$EvidenceFile.Path) -PathType Leaf
        }
    }
)

$Limitations = [Collections.Generic.List[string]]::new()
if ($JsonValidationSource -eq 'DirectParse') {
    $Limitations.Add('The auxiliary json-validation.json collector artifact was absent. Required substantive JSON evidence was parsed directly by the report adapter; no synthetic evidence file was created.')
}
if ($PostureUnavailableCount -gt 0) {
    $Limitations.Add('Extended posture attributes were unavailable for some or all identity-resolved relevant principals. Unavailable does not mean absent.')
}
if ($UnresolvedCount -gt 0) {
    $Limitations.Add('One or more policy, silo, or membership references were unresolved and require bounded classification.')
}
if ($OperationalErrorCount -gt 0) {
    $Limitations.Add('Operational errors were recorded; review the structured error evidence before relying on completeness.')
}
$Limitations.Add('Absence of Authentication Policies or Silos is not independently a vulnerability.')
$Limitations.Add('Protected Users membership and Authentication Policy assignment are different controls.')

$Recommendations = @(
    'Correlate relevant identities by SID with privileged-group membership, Kerberos posture, managed-secret exposure, and Directory Control evidence.',
    'Prioritize new live collection only when a specific posture decision remains blocked after offline correlation.',
    'Do not recommend Authentication Policy deployment solely because no policies or silos were detected.'
)

$CompletedUtc = (Get-Date).ToUniversalTime()
$Section = New-MSADPTReportSection `
    -ModuleId 'Collect-MSADPTAuthenticationPolicySecurity' `
    -ModuleVersion $CollectorVersion `
    -Title 'Authentication Policies and Protected Users' `
    -Category 'Identity.AuthenticationPolicy' `
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

$SectionJsonPath = Join-Path $OutputDirectory 'authentication-policy-report-section.json'
$SectionHtmlPath = Join-Path $OutputDirectory 'authentication-policy-report-section.html'
$ValidationPath = Join-Path $OutputDirectory 'authentication-policy-report-section-validation.json'

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
