<#
.SYNOPSIS
Ranks candidate-specific ADCS routes using separate completeness and validation-priority scores.
.DESCRIPTION
Consumes candidate-specific ADCS facts plus offline identity-context classifications. Evidence completeness
measures how much of a route is known. Validation priority measures the value and efficiency of collecting
missing evidence next. Neither score represents severity, vulnerability, or exploitability.

No Active Directory, LDAP, CA, DNS, TCP, SMB, Kerberos, authentication, certificate, registry, or ledger
operation is performed.
.NOTES
Version: 0.2.0
Execution class: offline_analysis
Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CandidateFactsPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$IdentityContextPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [Parameter()][string]$ConsoleModulePath,
    [Parameter()][ValidateRange(1,1000)][int]$TopCandidateCount = 25,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PlannerVersion = '0.2.0'
$AllowedDispositions = @('Prerequisites satisfied','Incomplete evidence','Blocked','Not applicable')

foreach ($Path in @($CandidateFactsPath,$IdentityContextPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required evidence not found: $Path"
    }
}
if (-not [string]::IsNullOrWhiteSpace($ConsoleModulePath)) {
    if (-not (Test-Path -LiteralPath $ConsoleModulePath -PathType Leaf)) {
        throw "Console module not found: $ConsoleModulePath"
    }
    Import-Module $ConsoleModulePath -Force -ErrorAction Stop
}

function Write-MSADPTPlannerEvent {
    param(
        [ValidateSet('Info','Action','Success','Warning','Error','Muted')][string]$Kind,
        [string]$Message,
        [string]$Target,
        [string]$Code,
        [hashtable]$Data
    )
    if (Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue) {
        return Write-MSADPTConsoleEvent -Kind $Kind -Message $Message -Target $Target -Code $Code -Data $Data
    }
    $Event = [pscustomobject][ordered]@{
        TimestampUtc=(Get-Date).ToUniversalTime().ToString('o');Kind=$Kind;Code=$Code
        Message=$Message;Target=$Target;Data=if($null-ne$Data){[pscustomobject]$Data}else{$null}
    }
    if (-not $Quiet) {
        $Color = switch($Kind){'Info'{'Cyan'}'Action'{'Yellow'}'Success'{'Green'}'Warning'{'DarkYellow'}'Error'{'Red'}default{'DarkGray'}}
        Write-Host ('[{0}] {1}: {2}' -f $Kind.ToUpperInvariant(),$Target,$Message) -ForegroundColor $Color
    }
    Write-Output $Event
}

function Get-MSADPTIdentityContextRecord {
    param([string]$IdentityReference,$ContextRecords)
    return @(
        $ContextRecords |
            Where-Object { [string]$_.identityReference -eq $IdentityReference } |
            Select-Object -First 1
    )
}

function Get-MSADPTValidationAction {
    param([string]$Technique,[string]$FactId,[string]$Template,[string]$Principal,[string]$Ca)
    switch ($FactId) {
        'effectiveLowPrivilegeEnrollment' {
            return "Resolve direct and recursive membership for '$Principal'; evaluate applicable deny ACEs and effective enrollment on template '$Template'."
        }
        'effectiveNonPrivilegedTemplateControl' {
            return "Resolve '$Principal'; evaluate GenericAll, GenericWrite, WriteDacl, WriteOwner, deny ACEs, inheritance, ownership, and nested control for template '$Template'."
        }
        'principalResolved' {
            return "Resolve '$Principal' to SID, object class, enabled state, distinguished name, and current membership evidence."
        }
        default {
            return "Collect deterministic evidence for prerequisite '$FactId' on $Technique route '$Ca | $Template | $Principal'."
        }
    }
}

function Get-MSADPTConsolidationKey {
    param([string]$FactId,[string]$Template,[string]$Principal)
    switch ($FactId) {
        'effectiveLowPrivilegeEnrollment' { return "Enrollment|$Template|$Principal" }
        'effectiveNonPrivilegedTemplateControl' { return "TemplateControl|$Template|$Principal" }
        'principalResolved' { return "Identity|$Principal" }
        default { return "Fact|$FactId|$Template|$Principal" }
    }
}

try {
    $Candidates = @(Get-Content -LiteralPath $CandidateFactsPath -Raw | ConvertFrom-Json -ErrorAction Stop)
}
catch { throw "CandidateFactsJsonParseFailure: $($_.Exception.Message)" }
try {
    $IdentityContexts = @(Get-Content -LiteralPath $IdentityContextPath -Raw | ConvertFrom-Json -ErrorAction Stop)
}
catch { throw "IdentityContextJsonParseFailure: $($_.Exception.Message)" }
if ($Candidates.Count -eq 0) { throw 'CandidateFactsEmpty: No candidate records were supplied.' }
if ($IdentityContexts.Count -eq 0) { throw 'IdentityContextEmpty: No identity-context records were supplied.' }

$Events = New-Object 'System.Collections.Generic.List[object]'
$Events.Add((Write-MSADPTPlannerEvent -Kind Info -Code 'PlannerStarted' -Message ("Loaded {0} candidate route(s) and {1} identity context(s)." -f $Candidates.Count,$IdentityContexts.Count) -Target 'ADCS validation planner' -Data @{PlannerVersion=$PlannerVersion}))
$Plan = New-Object 'System.Collections.Generic.List[object]'
$Current = 0

foreach ($Candidate in $Candidates) {
    $Current++
    $Technique = [string]$Candidate.technique
    $Ca = [string]$Candidate.certificationAuthority
    $Template = [string]$Candidate.template
    $Principal = [string]$Candidate.principal
    $Disposition = [string]$Candidate.disposition
    if ($Disposition -notin $AllowedDispositions) {
        throw "Unsupported candidate disposition for $($Candidate.candidateId): $Disposition"
    }

    $ContextArray = @(Get-MSADPTIdentityContextRecord -IdentityReference $Principal -ContextRecords $IdentityContexts)
    $Context = if ($ContextArray.Count -gt 0) { $ContextArray[0] } else { $null }
    $IdentityCategory = if ($null -ne $Context) { [string]$Context.category } else { 'UnknownPrivilegeContext' }
    $IdentityConfidence = if ($null -ne $Context) { [string]$Context.confidence } else { 'Low' }
    $IdentityModifier = if ($null -ne $Context) { [int]$Context.validationPriorityModifier } else { 0 }
    $IsPrivilegedContext = if ($null -ne $Context) { [bool]$Context.isPrivilegedContext } else { $false }
    $IsBroadIdentity = if ($null -ne $Context) { [bool]$Context.isBroadIdentity } else { $false }

    if (-not $Quiet -and $Current -le $TopCandidateCount) {
        $Percent = [math]::Round(($Current / $Candidates.Count) * 100,0)
        $Events.Add((Write-MSADPTPlannerEvent -Kind Action -Code 'EvaluateCandidate' -Message ("[{0}/{1} {2}%] Calculating completeness and validation priority." -f $Current,$Candidates.Count,$Percent) -Target ("{0} | {1} | {2}" -f $Technique,$Template,$Principal) -Data @{IdentityCategory=$IdentityCategory}))
    }

    $RequiredCount = [int]$Candidate.requiredCount
    $SatisfiedCount = [int]$Candidate.satisfiedRequiredCount
    $CompletenessScore = if ($RequiredCount -gt 0) {
        [int][math]::Round(($SatisfiedCount / $RequiredCount) * 100,0)
    } else { 0 }

    $Missing = @($Candidate.missingOrInconclusive)
    $NotObserved = @($Candidate.notObserved)
    $MissingIds = @($Missing | ForEach-Object { [string]$_.id } | Sort-Object -Unique)
    $NotObservedIds = @($NotObserved | ForEach-Object { [string]$_.id } | Sort-Object -Unique)
    $DuplicateFactIds = @($Candidate.facts | Group-Object id | Where-Object Count -gt 1 | Select-Object -ExpandProperty Name)

    $ValidationPriorityScore = 0
    $ValidationPriorityScore += [int][math]::Round($CompletenessScore * 0.55,0)
    $ValidationPriorityScore += $IdentityModifier
    if ($Disposition -eq 'Prerequisites satisfied') { $ValidationPriorityScore += 20 }
    if ($Disposition -eq 'Incomplete evidence') { $ValidationPriorityScore += 15 }
    if ($Disposition -eq 'Blocked') { $ValidationPriorityScore -= 30 }
    if ($Disposition -eq 'Not applicable') { $ValidationPriorityScore -= 50 }
    if ($MissingIds.Count -eq 1) { $ValidationPriorityScore += 15 }
    if ($MissingIds.Count -gt 3) { $ValidationPriorityScore -= 10 }
    if ($NotObservedIds.Count -gt 0) { $ValidationPriorityScore -= [math]::Min(20,($NotObservedIds.Count * 5)) }
    if ($DuplicateFactIds.Count -gt 0) { $ValidationPriorityScore -= 30 }
    if ($Technique -eq 'ESC1') { $ValidationPriorityScore += 10 }
    if ($Technique -eq 'ESC4') { $ValidationPriorityScore += 5 }
    if ($IsPrivilegedContext) { $ValidationPriorityScore -= 15 }
    if ($IsBroadIdentity -and $Disposition -ne 'Blocked') { $ValidationPriorityScore += 5 }
    $ValidationPriorityScore = [int][math]::Max(0,[math]::Min(100,$ValidationPriorityScore))

    $PriorityBand = if($ValidationPriorityScore -ge 80){'P1'}elseif($ValidationPriorityScore -ge 60){'P2'}elseif($ValidationPriorityScore -ge 35){'P3'}else{'P4'}
    $ValidationActions = New-Object 'System.Collections.Generic.List[string]'
    $ActionKeys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($FactId in $MissingIds) {
        $ValidationActions.Add((Get-MSADPTValidationAction -Technique $Technique -FactId $FactId -Template $Template -Principal $Principal -Ca $Ca))
        $ActionKeys.Add((Get-MSADPTConsolidationKey -FactId $FactId -Template $Template -Principal $Principal))
    }
    if ($ValidationActions.Count -eq 0 -and $Disposition -eq 'Prerequisites satisfied') {
        $ValidationActions.Add('Perform human evidence review; confirm all facts belong to this exact route. Do not perform enrollment or modification testing automatically.')
        $ActionKeys.Add("HumanReview|$Technique|$Template|$Principal")
    }
    if ($ValidationActions.Count -eq 0 -and $Disposition -eq 'Blocked') {
        $ValidationActions.Add('Preserve the blocking evidence and revalidate only if its source changes or becomes stale.')
        $ActionKeys.Add("PreserveBlock|$Technique|$Template|$Principal")
    }

    $Plan.Add([pscustomobject][ordered]@{
        rank=$null;priorityBand=$PriorityBand;validationPriorityScore=$ValidationPriorityScore
        evidenceCompletenessScore=$CompletenessScore;candidateId=[string]$Candidate.candidateId
        technique=$Technique;certificationAuthority=$Ca;template=$Template;principal=$Principal
        identityCategory=$IdentityCategory;identityConfidence=$IdentityConfidence
        identityPriorityModifier=$IdentityModifier;isPrivilegedContext=$IsPrivilegedContext;isBroadIdentity=$IsBroadIdentity
        accessRowCount=[int]$Candidate.accessRowCount;disposition=$Disposition
        requiredCount=$RequiredCount;satisfiedRequiredCount=$SatisfiedCount
        missingFactIds=@($MissingIds);notObservedFactIds=@($NotObservedIds);duplicateFactIds=@($DuplicateFactIds)
        validationActionKeys=@($ActionKeys.ToArray());validationActions=@($ValidationActions.ToArray())
        safeFollowUp=[string]$Candidate.safeFollowUp;sourceCandidateFacts=$CandidateFactsPath;sourceIdentityContext=$IdentityContextPath
        limitations=@('Evidence completeness is not severity.','Validation priority is not severity or exploitability.','A high-priority route is efficient or valuable to validate next.','No certificate request, template modification, authentication, or credential replay is authorized by this plan.')
    })
}

$SortedPlan = @($Plan.ToArray() | Sort-Object @{Expression='validationPriorityScore';Descending=$true},@{Expression='evidenceCompletenessScore';Descending=$true},technique,template,principal)
for ($Index=0;$Index -lt $SortedPlan.Count;$Index++) { $SortedPlan[$Index].rank=$Index+1 }
$Top = @($SortedPlan | Select-Object -First $TopCandidateCount)

$ActionGroups = @(
    $Top |
        ForEach-Object {
            $Candidate = $_
            for ($ActionIndex=0;$ActionIndex -lt @($Candidate.validationActions).Count;$ActionIndex++) {
                [pscustomobject]@{
                    key=[string]$Candidate.validationActionKeys[$ActionIndex]
                    action=[string]$Candidate.validationActions[$ActionIndex]
                    candidateId=[string]$Candidate.candidateId
                    validationPriorityScore=[int]$Candidate.validationPriorityScore
                }
            }
        } |
        Group-Object key
)
$ConsolidatedActions = New-Object 'System.Collections.Generic.List[object]'
foreach ($ActionGroup in $ActionGroups) {
    $Rows=@($ActionGroup.Group)
    $ConsolidatedActions.Add([pscustomobject][ordered]@{
        actionKey=[string]$ActionGroup.Name;action=[string]$Rows[0].action
        supportingCandidateCount=$Rows.Count;highestValidationPriorityScore=[int](($Rows|Measure-Object validationPriorityScore -Maximum).Maximum)
        supportingCandidateIds=@($Rows|Select-Object -ExpandProperty candidateId -Unique)
    })
}
$SortedActions=@($ConsolidatedActions.ToArray()|Sort-Object @{Expression='highestValidationPriorityScore';Descending=$true},actionKey)

New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$PlanJsonPath=Join-Path $OutputDirectory 'adcs-candidate-validation-plan.json'
$PlanCsvPath=Join-Path $OutputDirectory 'adcs-candidate-validation-plan.csv'
$TopJsonPath=Join-Path $OutputDirectory 'adcs-top-candidates.json'
$OfficePlanPath=Join-Path $OutputDirectory 'adcs-next-lan-validation-plan.json'
$EventPath=Join-Path $OutputDirectory 'adcs-validation-planner-events.json'

$SortedPlan|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $PlanJsonPath -Encoding UTF8
$SortedPlan|Select-Object rank,priorityBand,validationPriorityScore,evidenceCompletenessScore,technique,certificationAuthority,template,principal,identityCategory,identityConfidence,identityPriorityModifier,isPrivilegedContext,isBroadIdentity,accessRowCount,disposition,requiredCount,satisfiedRequiredCount,
    @{Name='MissingFactIds';Expression={@($_.missingFactIds)-join ';'}},
    @{Name='NotObservedFactIds';Expression={@($_.notObservedFactIds)-join ';'}},
    @{Name='ValidationActions';Expression={@($_.validationActions)-join ' | '}},safeFollowUp|
    Export-Csv -LiteralPath $PlanCsvPath -NoTypeInformation -Encoding UTF8
$Top|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $TopJsonPath -Encoding UTF8

$OfficePlan=[pscustomobject][ordered]@{
    schemaVersion='1.0';planner='ADCSCandidateValidationPlan';plannerVersion=$PlannerVersion
    generatedUtc=(Get-Date).ToUniversalTime().ToString('o');candidateCount=$SortedPlan.Count;topCandidateCount=$Top.Count
    p1Count=@($SortedPlan|Where-Object priorityBand -eq 'P1').Count;p2Count=@($SortedPlan|Where-Object priorityBand -eq 'P2').Count
    scoreDefinitions=[pscustomobject]@{
        evidenceCompletenessScore='Percentage of required facts confirmed for the exact candidate route.'
        validationPriorityScore='Workflow priority derived from completeness, identity context, disposition, and evidence effort. Not severity.'
    }
    nextLanSequence=@(
        'Explicitly confirm Mario is on the ExampleOrg LAN.',
        'Archive current ADCSAttackPathPrerequisiteValidation v0.1.3 evidence.',
        'Revalidate v0.1.4 collector, manifest, and offline tests.',
        'Run one deterministic dry run and confirm only v0.1.4 is eligible.',
        'Execute exactly one v0.1.4 refresh.',
        'Confirm no JSON depth warning and run Test-MSADPTEvidenceSerialization.ps1.',
        'Validate ledger supersession and evidence counts.',
        'Rebuild aggregate facts, candidate-specific facts, and identity context.',
        'Rerun planner v0.2.0 and compare route and priority changes.'
    )
    consolidatedEvidenceActions=@($SortedActions)
    prohibitedAutomaticActions=@('Certificate enrollment','Certificate authentication','Template modification','Group modification','Credential or hash replay','CA setting change')
    topCandidates=@($Top)
}
$OfficePlan|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $OfficePlanPath -Encoding UTF8
$Events.Add((Write-MSADPTPlannerEvent -Kind Success -Code 'PlannerCompleted' -Message ("Ranked {0} candidate(s) and consolidated {1} top-candidate action(s)." -f $SortedPlan.Count,$SortedActions.Count) -Target 'ADCS validation planner' -Data @{PlanPath=$PlanJsonPath;OfficePlanPath=$OfficePlanPath}))
$Events.ToArray()|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $EventPath -Encoding UTF8

[pscustomobject][ordered]@{
    schemaVersion='1.0';planner='ADCSCandidateValidationPlan';plannerVersion=$PlannerVersion;status='Completed';executionClass='offline_analysis'
    candidateCount=$SortedPlan.Count;topCandidateCount=$Top.Count;p1Count=@($SortedPlan|Where-Object priorityBand -eq 'P1').Count
    p2Count=@($SortedPlan|Where-Object priorityBand -eq 'P2').Count;privilegedTopCandidateCount=@($Top|Where-Object isPrivilegedContext -eq $true).Count
    consolidatedActionCount=$SortedActions.Count;prerequisitesSatisfiedCount=@($SortedPlan|Where-Object disposition -eq 'Prerequisites satisfied').Count
    incompleteEvidenceCount=@($SortedPlan|Where-Object disposition -eq 'Incomplete evidence').Count;blockedCount=@($SortedPlan|Where-Object disposition -eq 'Blocked').Count
    evidence=@($PlanJsonPath,$PlanCsvPath,$TopJsonPath,$OfficePlanPath,$EventPath)
}
