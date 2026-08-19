<#
.SYNOPSIS
Ranks the unified MSADPT ADCS candidate inventory across ESC1, ESC2, ESC4, and ESC15.
.DESCRIPTION
Consumes the validated unified 516-route candidate inventory and offline identity-context evidence.
It produces separate evidence-completeness and validation-priority scores, technique-aware reasons,
and a deduplicated next-LAN evidence plan. Scores are workflow triage values, not severity,
vulnerability, or exploitability declarations.

This script performs no AD, CA, LDAP, DNS, TCP, SMB, Kerberos, certificate, authentication,
credential or hash replay, Ollama target interaction, registry, or ledger operation.
.NOTES
Version: 0.3.0
Execution class: offline_analysis
Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$UnifiedCandidateInventoryPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$IdentityContextPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [Parameter()][string]$ConsoleModulePath,
    [Parameter()][ValidateRange(1,1000)][int]$TopCandidateCount = 25,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PlannerVersion = '0.3.0'
$AllowedTechniques = @('ESC1','ESC2','ESC4','ESC15')
$AllowedDispositions = @('Prerequisites satisfied','Incomplete evidence','Blocked','Not applicable')

foreach ($RequiredPath in @($UnifiedCandidateInventoryPath,$IdentityContextPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "RequiredEvidenceMissing: $RequiredPath"
    }
}
if (-not [string]::IsNullOrWhiteSpace($ConsoleModulePath)) {
    if (-not (Test-Path -LiteralPath $ConsoleModulePath -PathType Leaf)) {
        throw "ConsoleModuleMissing: $ConsoleModulePath"
    }
    Import-Module $ConsoleModulePath -Force -ErrorAction Stop
}

function Write-PlannerEvent {
    param(
        [ValidateSet('Info','Action','Success','Warning','Error')][string]$Kind,
        [string]$Message,
        [string]$Target
    )
    if (Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue) {
        return Write-MSADPTConsoleEvent -Kind $Kind -Message $Message -Target $Target -Code 'UnifiedCandidatePlanner'
    }
    if (-not $Quiet) {
        $Color = switch ($Kind) {
            'Success' { 'Green' }
            'Warning' { 'DarkYellow' }
            'Error' { 'Red' }
            'Info' { 'Cyan' }
            default { 'Yellow' }
        }
        Write-Host ('[{0}] {1}: {2}' -f $Kind,$Target,$Message) -ForegroundColor $Color
    }
}

function Read-JsonArray {
    param([string]$Path,[string]$Label)
    try {
        $Rows = @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "${Label}JsonParseFailure: $($_.Exception.Message)"
    }
    if ($Rows.Count -eq 0) {
        throw "${Label}Empty: $Path"
    }
    return $Rows
}

function Get-IdentityContext {
    param([string]$Principal,$IdentityContexts)
    return ($IdentityContexts |
        Where-Object { [string]$_.identityReference -eq $Principal } |
        Select-Object -First 1)
}

function Get-FactState {
    param($Candidate,[string]$FactId)
    $Fact = @($Candidate.facts |
        Where-Object { [string]$_.id -eq $FactId } |
        Select-Object -First 1)
    if ($Fact.Count -eq 0) { return 'Missing' }
    return [string]$Fact[0].state
}

function Get-ActionDefinition {
    param($Candidate,[string]$FactId)
    $Technique = [string]$Candidate.technique
    $Template = [string]$Candidate.template
    $Principal = [string]$Candidate.principal
    $Ca = [string]$Candidate.certificationAuthority

    switch ($FactId) {
        'effectiveLowPrivilegeEnrollment' {
            return [pscustomobject]@{
                key = "Enrollment|$Template|$Principal"
                action = "Resolve direct and recursive membership for '$Principal'; evaluate applicable deny ACEs and effective enrollment on template '$Template'."
                scope = 'Template and principal'
            }
        }
        'effectiveNonPrivilegedTemplateControl' {
            return [pscustomobject]@{
                key = "TemplateControl|$Template|$Principal"
                action = "Evaluate effective GenericAll, GenericWrite, WriteDacl, WriteOwner, deny, inheritance, ownership, and nested control for '$Principal' on '$Template'."
                scope = 'Template and principal'
            }
        }
        'applicationPolicyRequestHandling' {
            return [pscustomobject]@{
                key = "Esc15ApplicationPolicy|$Ca"
                action = "Collect deterministic Application Policy request-handling behavior for certification authority '$Ca'."
                scope = 'Certification authority'
            }
        }
        'relevantPatchState' {
            return [pscustomobject]@{
                key = "Esc15PatchState|$Ca"
                action = "Collect relevant patch and enforcement state for certification authority '$Ca' and applicable domain controllers."
                scope = 'CA host and domain controllers'
            }
        }
        'policyModuleRestriction' {
            return [pscustomobject]@{
                key = "Esc15PolicyModule|$Ca"
                action = "Collect active policy-module restrictions for certification authority '$Ca'."
                scope = 'Certification authority'
            }
        }
        default {
            return [pscustomobject]@{
                key = "Fact|$Technique|$FactId|$Template|$Principal"
                action = "Collect deterministic evidence for '$FactId' on route '$Technique | $Ca | $Template | $Principal'."
                scope = 'Exact candidate route'
            }
        }
    }
}

$Candidates = @(Read-JsonArray -Path $UnifiedCandidateInventoryPath -Label 'UnifiedCandidateInventory')
$IdentityContexts = @(Read-JsonArray -Path $IdentityContextPath -Label 'IdentityContext')
$UnexpectedTechniques = @($Candidates |
    Where-Object { [string]$_.technique -notin $AllowedTechniques })
if ($UnexpectedTechniques.Count -gt 0) {
    throw "UnexpectedTechniques: $(@($UnexpectedTechniques.technique | Sort-Object -Unique) -join ', ')"
}
$DuplicateIds = @($Candidates | Group-Object candidateId | Where-Object { $_.Count -gt 1 })
if ($DuplicateIds.Count -gt 0) {
    throw "DuplicateCandidateIds: $($DuplicateIds.Count) duplicate group(s)."
}

$null = Write-PlannerEvent -Kind Info -Message "Loaded $($Candidates.Count) unified candidate routes and $($IdentityContexts.Count) identity contexts." -Target 'Planner v0.3.0'
$Plan = @()
$Index = 0
foreach ($Candidate in $Candidates) {
    $Index++
    $Technique = [string]$Candidate.technique
    $Disposition = [string]$Candidate.disposition
    if ($Disposition -notin $AllowedDispositions) {
        throw "UnsupportedDisposition [$($Candidate.candidateId)]: $Disposition"
    }

    $ContextArray = @(Get-IdentityContext -Principal ([string]$Candidate.principal) -IdentityContexts $IdentityContexts)
    $Context = if ($ContextArray.Count -gt 0) { $ContextArray[0] } else { $null }
    $IdentityCategory = if ($null -ne $Context) { [string]$Context.category } elseif ($null -ne $Candidate.PSObject.Properties['identityCategory'] -and -not [string]::IsNullOrWhiteSpace([string]$Candidate.identityCategory)) { [string]$Candidate.identityCategory } else { 'UnknownPrivilegeContext' }
    $IdentityModifier = if ($null -ne $Context -and $null -ne $Context.PSObject.Properties['validationPriorityModifier']) { [int]$Context.validationPriorityModifier } else { 0 }
    $IsPrivileged = if ($null -ne $Context -and $null -ne $Context.PSObject.Properties['isPrivilegedContext']) { [bool]$Context.isPrivilegedContext } else { $IdentityCategory -in @('PrivilegedAdministrative','TierZeroIndicator') }
    $IsBroad = if ($null -ne $Context -and $null -ne $Context.PSObject.Properties['isBroadIdentity']) { [bool]$Context.isBroadIdentity } else { $IdentityCategory -in @('BroadLowPrivilege','BroadComputerIdentity') }

    $RequiredCount = [int]$Candidate.requiredCount
    $SatisfiedCount = [int]$Candidate.satisfiedRequiredCount
    $CompletenessScore = if ($RequiredCount -gt 0) { [int][math]::Round(($SatisfiedCount / $RequiredCount) * 100,0) } else { 0 }
    $MissingFacts = @($Candidate.missingOrInconclusive)
    $NotObservedFacts = @($Candidate.notObserved)
    $MissingIds = @($MissingFacts | ForEach-Object { [string]$_.id } | Sort-Object -Unique)
    $NotObservedIds = @($NotObservedFacts | ForEach-Object { [string]$_.id } | Sort-Object -Unique)

    $Esc2Capability = $Technique -eq 'ESC2' -and (Get-FactState -Candidate $Candidate -FactId 'anyPurposeOrNoEkuRestriction') -eq 'Confirmed'
    $Esc15VersionOne = $Technique -eq 'ESC15' -and (Get-FactState -Candidate $Candidate -FactId 'affectedVersionOneTemplate') -eq 'Confirmed'
    $Esc15RequesterControl = $Technique -eq 'ESC15' -and (Get-FactState -Candidate $Candidate -FactId 'requesterControlsCertificateIdentity') -eq 'Confirmed'
    $Esc15RuntimeGapCount = if ($Technique -eq 'ESC15') {
        @('applicationPolicyRequestHandling','relevantPatchState','policyModuleRestriction' |
            Where-Object { (Get-FactState -Candidate $Candidate -FactId $_) -eq 'Inconclusive' }).Count
    }
    else { 0 }

    $Priority = [int][math]::Round($CompletenessScore * 0.45,0)
    $Priority += $IdentityModifier
    if ($Disposition -eq 'Incomplete evidence') { $Priority += 15 }
    elseif ($Disposition -eq 'Prerequisites satisfied') { $Priority += 20 }
    elseif ($Disposition -eq 'Blocked') { $Priority -= 30 }
    else { $Priority -= 50 }
    if ($MissingIds.Count -eq 1) { $Priority += 15 }
    elseif ($MissingIds.Count -gt 3) { $Priority -= 10 }
    if ($NotObservedIds.Count -gt 0) { $Priority -= [math]::Min(20,$NotObservedIds.Count * 5) }
    if ($IsPrivileged) { $Priority -= 20 }
    if ($IsBroad -and $Disposition -ne 'Blocked') { $Priority += 5 }
    if ($Technique -eq 'ESC1') { $Priority += 10 }
    elseif ($Technique -eq 'ESC4') { $Priority += 5 }
    elseif ($Technique -eq 'ESC2' -and $Esc2Capability) { $Priority += 20 }
    elseif ($Technique -eq 'ESC2') { $Priority -= 15 }
    elseif ($Technique -eq 'ESC15' -and $Esc15VersionOne -and $Esc15RequesterControl) { $Priority += 15 }
    elseif ($Technique -eq 'ESC15') { $Priority -= 20 }
    if ($Technique -eq 'ESC15' -and $Esc15RuntimeGapCount -eq 3) { $Priority += 5 }
    $Priority = [int][math]::Max(0,[math]::Min(100,$Priority))
    $PriorityBand = if ($Priority -ge 80) { 'P1' } elseif ($Priority -ge 60) { 'P2' } elseif ($Priority -ge 35) { 'P3' } else { 'P4' }

    $Reasons = @()
    if ($Esc2Capability) { $Reasons += 'Exact template has Any Purpose or no EKU restriction.' }
    if ($Esc15VersionOne) { $Reasons += 'Exact template is schema version 1.' }
    if ($Esc15RequesterControl) { $Reasons += 'Requester-controlled certificate identity prerequisite is confirmed.' }
    if ($Esc15RuntimeGapCount -eq 3) { $Reasons += 'Three shared ESC15 runtime and patch facts remain inconclusive.' }
    if ($IsPrivileged) { $Reasons += 'Already-privileged identity context reduces validation priority.' }
    if ($Reasons.Count -eq 0) { $Reasons += 'Priority is based on completeness, disposition, identity context, and remaining evidence effort.' }

    $Actions = @()
    foreach ($FactId in $MissingIds) {
        $Actions += ,(Get-ActionDefinition -Candidate $Candidate -FactId $FactId)
    }
    if ($Actions.Count -eq 0 -and $Disposition -eq 'Blocked') {
        $Actions += ,[pscustomobject]@{
            key = "PreserveBlock|$($Candidate.candidateId)"
            action = 'Preserve blocking evidence and revalidate only if the source configuration changes or becomes stale.'
            scope = 'Exact candidate route'
        }
    }

    if (-not $Quiet -and ($Index -le $TopCandidateCount -or $Index % 50 -eq 0 -or $Index -eq $Candidates.Count)) {
        $Percent = [math]::Round(($Index / $Candidates.Count) * 100,0)
        $null = Write-PlannerEvent -Kind Action -Message "[$Index/$($Candidates.Count) $Percent%] Evaluating unified route." -Target "$Technique | $($Candidate.template) | $($Candidate.principal)"
    }

    $Plan += ,[pscustomobject][ordered]@{
        rank = $null
        priorityBand = $PriorityBand
        validationPriorityScore = $Priority
        evidenceCompletenessScore = $CompletenessScore
        candidateId = [string]$Candidate.candidateId
        technique = $Technique
        certificationAuthority = [string]$Candidate.certificationAuthority
        template = [string]$Candidate.template
        principal = [string]$Candidate.principal
        identityCategory = $IdentityCategory
        identityPriorityModifier = $IdentityModifier
        isPrivilegedContext = $IsPrivileged
        isBroadIdentity = $IsBroad
        disposition = $Disposition
        requiredCount = $RequiredCount
        satisfiedRequiredCount = $SatisfiedCount
        missingFactIds = @($MissingIds)
        notObservedFactIds = @($NotObservedIds)
        esc2Capability = $Esc2Capability
        esc15VersionOne = $Esc15VersionOne
        esc15RequesterControlsIdentity = $Esc15RequesterControl
        esc15RuntimeGapCount = $Esc15RuntimeGapCount
        priorityReasons = @($Reasons)
        validationActionKeys = @($Actions.key)
        validationActions = @($Actions.action)
        safeFollowUp = [string]$Candidate.safeFollowUp
        limitations = @('Evidence completeness is not severity.','Validation priority is not exploitability.','No active certificate or authentication testing is authorized by this plan.')
    }
}

$Sorted = @($Plan | Sort-Object @{Expression='validationPriorityScore';Descending=$true},@{Expression='evidenceCompletenessScore';Descending=$true},technique,template,principal)
for ($RankIndex = 0; $RankIndex -lt $Sorted.Count; $RankIndex++) { $Sorted[$RankIndex].rank = $RankIndex + 1 }
$Top = @($Sorted | Select-Object -First $TopCandidateCount)

$ActionRows = @()
foreach ($Candidate in $Top) {
    for ($ActionIndex = 0; $ActionIndex -lt @($Candidate.validationActions).Count; $ActionIndex++) {
        $ActionRows += ,[pscustomobject]@{
            key = [string]$Candidate.validationActionKeys[$ActionIndex]
            action = [string]$Candidate.validationActions[$ActionIndex]
            candidateId = [string]$Candidate.candidateId
            score = [int]$Candidate.validationPriorityScore
        }
    }
}
$ConsolidatedActions = @()
foreach ($Group in @($ActionRows | Group-Object key)) {
    $Rows = @($Group.Group)
    $ConsolidatedActions += ,[pscustomobject][ordered]@{
        actionKey = [string]$Group.Name
        action = [string]$Rows[0].action
        supportingCandidateCount = $Rows.Count
        highestValidationPriorityScore = [int](($Rows | Measure-Object score -Maximum).Maximum)
        supportingCandidateIds = @($Rows | Select-Object -ExpandProperty candidateId -Unique)
    }
}
$ConsolidatedActions = @($ConsolidatedActions | Sort-Object @{Expression='highestValidationPriorityScore';Descending=$true},actionKey)

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$PlanJsonPath = Join-Path $OutputDirectory 'adcs-unified-validation-plan.json'
$PlanCsvPath = Join-Path $OutputDirectory 'adcs-unified-validation-plan.csv'
$TopPath = Join-Path $OutputDirectory 'adcs-unified-top-candidates.json'
$OfficePlanPath = Join-Path $OutputDirectory 'adcs-unified-next-lan-plan.json'
$SummaryPath = Join-Path $OutputDirectory 'adcs-unified-planner-summary.json'

$Sorted | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $PlanJsonPath -Encoding UTF8
$Sorted | Select-Object rank,priorityBand,validationPriorityScore,evidenceCompletenessScore,technique,certificationAuthority,template,principal,identityCategory,identityPriorityModifier,isPrivilegedContext,disposition,requiredCount,satisfiedRequiredCount,esc2Capability,esc15VersionOne,esc15RequesterControlsIdentity,esc15RuntimeGapCount,@{Name='MissingFactIds';Expression={@($_.missingFactIds) -join ';'}},@{Name='NotObservedFactIds';Expression={@($_.notObservedFactIds) -join ';'}},@{Name='PriorityReasons';Expression={@($_.priorityReasons) -join ' | '}},@{Name='ValidationActions';Expression={@($_.validationActions) -join ' | '}} | Export-Csv -LiteralPath $PlanCsvPath -NoTypeInformation -Encoding UTF8
$Top | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $TopPath -Encoding UTF8

$OfficePlan = [pscustomobject][ordered]@{
    schemaVersion = '1.0'
    plannerVersion = $PlannerVersion
    sourceScope = 'preserved_real_evidence'
    candidateCount = $Sorted.Count
    topCandidateCount = $Top.Count
    consolidatedEvidenceActions = @($ConsolidatedActions)
    sharedEsc15EvidenceGaps = @('applicationPolicyRequestHandling','relevantPatchState','policyModuleRestriction')
    prohibitedAutomaticActions = @('Certificate request','Certificate authentication','Template modification','Group modification','CA setting change','Credential or hash replay')
    topCandidates = @($Top)
}
$OfficePlan | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $OfficePlanPath -Encoding UTF8

$Summary = [pscustomobject][ordered]@{
    schemaVersion = '1.0'
    planner = 'ADCSUnifiedCandidateValidationPlan'
    plannerVersion = $PlannerVersion
    status = 'Completed'
    executionClass = 'offline_analysis'
    sourceScope = 'preserved_real_evidence'
    candidateCount = $Sorted.Count
    p1Count = @($Sorted | Where-Object { [string]$_.priorityBand -eq 'P1' }).Count
    p2Count = @($Sorted | Where-Object { [string]$_.priorityBand -eq 'P2' }).Count
    p3Count = @($Sorted | Where-Object { [string]$_.priorityBand -eq 'P3' }).Count
    p4Count = @($Sorted | Where-Object { [string]$_.priorityBand -eq 'P4' }).Count
    privilegedTopCandidateCount = @($Top | Where-Object { [bool]$_.isPrivilegedContext }).Count
    esc2CapabilityCandidateCount = @($Sorted | Where-Object { [bool]$_.esc2Capability }).Count
    esc15VersionOneCandidateCount = @($Sorted | Where-Object { [bool]$_.esc15VersionOne }).Count
    esc15FocusedCandidateCount = @($Sorted | Where-Object { [bool]$_.esc15VersionOne -and [bool]$_.esc15RequesterControlsIdentity }).Count
    consolidatedActionCount = $ConsolidatedActions.Count
    evidence = @($PlanJsonPath,$PlanCsvPath,$TopPath,$OfficePlanPath)
}
$Summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$null = Write-PlannerEvent -Kind Success -Message "Ranked $($Sorted.Count) unified candidates and consolidated $($ConsolidatedActions.Count) top-route evidence actions." -Target 'Planner v0.3.0'
Write-Output $Summary
