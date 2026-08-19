<#
.SYNOPSIS
Creates an environment-agnostic validation plan for normalized MSADPT ADCS candidate inventories.
.DESCRIPTION
Ranks arbitrary normalized ADCS candidate inventories using deterministic evidence completeness,
identity context, technique capability, validation effort, and reusable evidence actions. Supports
ESC1, ESC2, ESC3, ESC4, ESC13, and ESC15 without assuming a domain, forest, CA, template count,
route count, or organization-specific identity.

This tool performs offline analysis only. It does not contact AD, LDAP, DNS, TCP, SMB, Kerberos,
a certification authority, certificate services, Ollama, or the MSADPT evidence ledger.
.NOTES
Version: 0.4.1
Execution class: offline_analysis
PowerShell: Windows PowerShell 5.1 and PowerShell 7
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CandidateInventoryPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$IdentityContextPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [ValidateRange(1,1000)][int]$TopCandidateCount=25,
    [string]$ConsoleModulePath,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$PlannerVersion='0.4.1'
$SupportedTechniques=@('ESC1','ESC2','ESC3','ESC4','ESC13','ESC15')

function Write-PlanEvent {
    param([string]$Kind,[string]$Message,[string]$Target)
    if(Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue){
        return Write-MSADPTConsoleEvent -Kind $Kind -Message $Message -Target $Target -Code 'ADCSValidationPlanner'
    }
    if(-not $Quiet){
        $Color=if($Kind -eq 'Success'){'Green'}elseif($Kind -eq 'Warning'){'DarkYellow'}elseif($Kind -eq 'Error'){'Red'}else{'Yellow'}
        Write-Host ('[{0}] {1}: {2}' -f $Kind,$Target,$Message) -ForegroundColor $Color
    }
}
function Read-JsonArray {
    param([string]$Path,[string]$Label)
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "${Label}Missing: $Path"}
    try{$Rows=@(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)}catch{throw "${Label}JsonParseFailure: $($_.Exception.Message)"}
    if($Rows.Count -eq 0){throw "${Label}Empty: $Path"}
    return $Rows
}
function Get-FactState {
    param($Candidate,[string]$Id)
    $Fact=@($Candidate.facts|Where-Object{[string]$_.id -eq $Id}|Select-Object -First 1)
    if($Fact.Count -eq 0){return 'Missing'}
    return [string]$Fact[0].state
}
function Get-Identity {
    param($Rows,[string]$Principal)
    return ($Rows|Where-Object{[string]$_.identityReference -eq $Principal}|Select-Object -First 1)
}
function Get-EvidenceAction {
    param($Candidate,[string]$FactId)
    $Technique=[string]$Candidate.technique;$Ca=[string]$Candidate.certificationAuthority;$Template=[string]$Candidate.template;$Principal=[string]$Candidate.principal
    switch($FactId){
        'enrollmentAgentRestrictionsPermitRoute' {[pscustomobject]@{key="ESC3-AgentRestrictions|$Ca";action="Collect enrollment-agent restrictions for CA '$Ca' and determine whether the exact agent route is permitted.";scope='Certification authority'}}
        'targetTemplateChainResolved' {[pscustomobject]@{key="ESC3-TargetChain|$Ca|$Template|$Principal";action="Resolve the exact enrollment-agent target-template chain for '$Principal' through '$Template' on '$Ca'.";scope='Exact ESC3 route'}}
        'issuancePolicyOidPresent' {[pscustomobject]@{key='ESC13-TemplateIssuancePolicyCollection';action='Extend deterministic template collection to include issuance-policy OIDs. Missing schema properties must remain inconclusive.';scope='Template collection schema'}}
        'issuancePolicyOidObjectResolved' {[pscustomobject]@{key='ESC13-OidObjectInventory';action='Collect and resolve issuance-policy OID objects from the configuration partition.';scope='Forest OID objects'}}
        'oidToGroupLinkPresent' {[pscustomobject]@{key='ESC13-OidGroupLinks';action='Collect msDS-OIDToGroupLink values for resolved issuance-policy OID objects.';scope='Forest OID objects'}}
        'linkedGroupResolved' {[pscustomobject]@{key='ESC13-LinkedGroupResolution';action='Resolve linked-group distinguished names and stable identifiers.';scope='Linked groups'}}
        'linkedGroupPrivilegeContext' {[pscustomobject]@{key='ESC13-LinkedGroupPrivilege';action='Classify linked-group privilege and business context without inferring privilege from naming alone.';scope='Linked groups'}}
        'effectiveLinkedGroupEnrollmentRoute' {[pscustomobject]@{key="ESC13-EffectiveRoute|$Template|$Principal";action="Evaluate effective enrollment and linked-group route for '$Principal' through template '$Template'.";scope='Exact ESC13 route'}}
        'applicationPolicyRequestHandling' {[pscustomobject]@{key="ESC15-ApplicationPolicy|$Ca";action="Collect deterministic Application Policy request-handling behavior for CA '$Ca'.";scope='Certification authority'}}
        'relevantPatchState' {[pscustomobject]@{key="ESC15-PatchState|$Ca";action="Collect relevant CA-host and domain-controller patch and enforcement state for '$Ca'.";scope='CA host and domain controllers'}}
        'policyModuleRestriction' {[pscustomobject]@{key="ESC15-PolicyModule|$Ca";action="Collect active policy-module restrictions for CA '$Ca'.";scope='Certification authority'}}
        'effectiveLowPrivilegeEnrollment' {[pscustomobject]@{key="Enrollment|$Template|$Principal";action="Resolve nested membership, deny ACEs, and effective enrollment for '$Principal' on '$Template'.";scope='Template and principal'}}
        'effectiveNonPrivilegedTemplateControl' {[pscustomobject]@{key="TemplateControl|$Template|$Principal";action="Evaluate effective template control for '$Principal' on '$Template', including deny, inheritance, and ownership.";scope='Template and principal'}}
        default {[pscustomobject]@{key="Fact|$Technique|$FactId|$Ca|$Template|$Principal";action="Collect deterministic evidence for '$FactId' on route '$Technique | $Ca | $Template | $Principal'.";scope='Exact candidate route'}}
    }
}

if(-not[string]::IsNullOrWhiteSpace($ConsoleModulePath)){
    if(-not(Test-Path -LiteralPath $ConsoleModulePath -PathType Leaf)){throw "ConsoleModuleMissing: $ConsoleModulePath"}
    Import-Module $ConsoleModulePath -Force -ErrorAction Stop
}
$Candidates=@(Read-JsonArray $CandidateInventoryPath 'CandidateInventory')
$Contexts=@(Read-JsonArray $IdentityContextPath 'IdentityContext')
$Duplicates=@($Candidates|Group-Object candidateId|Where-Object{$_.Count -gt 1})
if($Duplicates.Count -gt 0){throw "DuplicateCandidateIds: $($Duplicates.Count)"}
$Unexpected=@($Candidates|Where-Object{[string]$_.technique -notin $SupportedTechniques})
if($Unexpected.Count -gt 0){throw "UnsupportedTechniques: $(@($Unexpected.technique|Sort-Object -Unique)-join', ')"}
$null=Write-PlanEvent 'Info' "Loaded $($Candidates.Count) candidates across $(@($Candidates.technique|Sort-Object -Unique).Count) techniques." 'Planner v0.4.0'

$Plan=@();$Index=0
foreach($Candidate in $Candidates){
    $Index++
    $Technique=[string]$Candidate.technique;$Disposition=[string]$Candidate.disposition
    $Context=Get-Identity $Contexts ([string]$Candidate.principal)
    $Category=if($null-ne$Context){[string]$Context.category}elseif($null-ne$Candidate.PSObject.Properties['identityCategory']){[string]$Candidate.identityCategory}else{'UnknownPrivilegeContext'}
    $Modifier=if($null-ne$Context -and $null-ne$Context.PSObject.Properties['validationPriorityModifier']){[int]$Context.validationPriorityModifier}else{0}
    $Privileged=if($null-ne$Context -and $null-ne$Context.PSObject.Properties['isPrivilegedContext']){[bool]$Context.isPrivilegedContext}else{$Category -in @('PrivilegedAdministrative','TierZeroIndicator')}
    $Required=[int]$Candidate.requiredCount;$Satisfied=[int]$Candidate.satisfiedRequiredCount
    $Completeness=if($Required -gt 0){[int][math]::Round(($Satisfied/$Required)*100,0)}else{0}
    $Missing=@($Candidate.missingOrInconclusive|ForEach-Object{[string]$_.id}|Sort-Object -Unique)
    $NotObserved=@($Candidate.notObserved|ForEach-Object{[string]$_.id}|Sort-Object -Unique)
    $Esc2Capability=(Get-FactState $Candidate 'anyPurposeOrNoEkuRestriction') -eq 'Confirmed'
    $Esc3Capability=(Get-FactState $Candidate 'certificateRequestAgentEku') -eq 'Confirmed'
    $Esc13PolicyState=Get-FactState $Candidate 'issuancePolicyOidPresent'
    $Esc15VersionOne=(Get-FactState $Candidate 'affectedVersionOneTemplate') -eq 'Confirmed'
    $Esc15Requester=(Get-FactState $Candidate 'requesterControlsCertificateIdentity') -eq 'Confirmed'

    $Score=[int][math]::Round($Completeness*0.45,0)+$Modifier
    if($Disposition -eq 'Incomplete evidence'){$Score+=15}elseif($Disposition -eq 'Prerequisites satisfied'){$Score+=20}elseif($Disposition -eq 'Blocked'){$Score-=30}else{$Score-=45}
    if($Missing.Count -eq 1){$Score+=15}elseif($Missing.Count -gt 4){$Score-=10}
    if($NotObserved.Count -gt 0){$Score-=[math]::Min(20,$NotObserved.Count*5)}
    if($Privileged){$Score-=20}
    switch($Technique){
        'ESC1' {$Score+=10}
        'ESC2' {if($Esc2Capability){$Score+=20}else{$Score-=15}}
        'ESC3' {if($Esc3Capability){$Score+=20}else{$Score-=20}}
        'ESC4' {$Score+=5}
        'ESC13' {if($Esc13PolicyState -eq 'Confirmed'){$Score+=20}elseif($Esc13PolicyState -eq 'Inconclusive'){$Score+=5}else{$Score-=20}}
        'ESC15' {if($Esc15VersionOne -and $Esc15Requester){$Score+=15}else{$Score-=20}}
    }
    $Score=[int][math]::Max(0,[math]::Min(100,$Score))
    $Band=if($Score -ge 80){'P1'}elseif($Score -ge 60){'P2'}elseif($Score -ge 35){'P3'}else{'P4'}
    $Actions=@()
    foreach($FactId in $Missing){
        $ActionDefinition=Get-EvidenceAction $Candidate $FactId
        if($null -ne $ActionDefinition){$Actions+=,$ActionDefinition}
    }
    $ActionKeys=@()
    $ActionTexts=@()
    foreach($ActionDefinition in $Actions){
        if($null -eq $ActionDefinition.PSObject.Properties['key'] -or $null -eq $ActionDefinition.PSObject.Properties['action']){
            throw "InvalidEvidenceAction [$($Candidate.candidateId)]: action object is missing key or action."
        }
        $ActionKeys+=[string]$ActionDefinition.key
        $ActionTexts+=[string]$ActionDefinition.action
    }
    if(-not$Quiet -and ($Index%50 -eq 0 -or $Index -eq $Candidates.Count)){$Percent=[math]::Round(($Index/$Candidates.Count)*100,0);$null=Write-PlanEvent 'Action' "[$Index/$($Candidates.Count) $Percent%] Ranking candidate." "$Technique | $($Candidate.template) | $($Candidate.principal)"}
    $Plan+=,[pscustomobject][ordered]@{
        rank=$null;priorityBand=$Band;validationPriorityScore=$Score;evidenceCompletenessScore=$Completeness
        candidateId=[string]$Candidate.candidateId;technique=$Technique;certificationAuthority=[string]$Candidate.certificationAuthority
        template=[string]$Candidate.template;principal=[string]$Candidate.principal;identityCategory=$Category
        identityPriorityModifier=$Modifier;isPrivilegedContext=$Privileged;disposition=$Disposition
        missingFactIds=@($Missing);notObservedFactIds=@($NotObserved)
        esc2Capability=$Esc2Capability;esc3AgentEkuCapability=$Esc3Capability;esc13IssuancePolicyState=$Esc13PolicyState
        esc15VersionOne=$Esc15VersionOne;esc15RequesterControlsIdentity=$Esc15Requester
        validationActionKeys=@($ActionKeys);validationActions=@($ActionTexts)
        limitations=@('Priority is workflow triage, not severity.','Candidate state is not an exploitability declaration.')
    }
}
$Sorted=@($Plan|Sort-Object @{Expression='validationPriorityScore';Descending=$true},@{Expression='evidenceCompletenessScore';Descending=$true},technique,template,principal)
for($i=0;$i-lt$Sorted.Count;$i++){$Sorted[$i].rank=$i+1}
$Top=@($Sorted|Select-Object -First $TopCandidateCount)
$ActionRows=@();foreach($Candidate in $Top){for($i=0;$i-lt@($Candidate.validationActions).Count;$i++){$ActionRows+=,[pscustomobject]@{key=[string]$Candidate.validationActionKeys[$i];action=[string]$Candidate.validationActions[$i];candidateId=[string]$Candidate.candidateId;score=[int]$Candidate.validationPriorityScore}}}
$Consolidated=@();foreach($Group in @($ActionRows|Group-Object key)){$Rows=@($Group.Group);$Consolidated+=,[pscustomobject][ordered]@{actionKey=[string]$Group.Name;action=[string]$Rows[0].action;supportingCandidateCount=$Rows.Count;highestValidationPriorityScore=[int](($Rows|Measure-Object score -Maximum).Maximum);supportingCandidateIds=@($Rows.candidateId|Sort-Object -Unique)}}
$Consolidated=@($Consolidated|Sort-Object @{Expression='supportingCandidateCount';Descending=$true},@{Expression='highestValidationPriorityScore';Descending=$true},actionKey)

New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$PlanPath=Join-Path $OutputDirectory 'adcs-validation-plan.json';$CsvPath=Join-Path $OutputDirectory 'adcs-validation-plan.csv';$TopPath=Join-Path $OutputDirectory 'adcs-top-candidates.json';$LanPath=Join-Path $OutputDirectory 'adcs-next-lan-plan.json';$SummaryPath=Join-Path $OutputDirectory 'adcs-planner-summary.json'
$Sorted|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $PlanPath -Encoding UTF8
$Sorted|Select-Object rank,priorityBand,validationPriorityScore,evidenceCompletenessScore,technique,certificationAuthority,template,principal,identityCategory,isPrivilegedContext,disposition,esc2Capability,esc3AgentEkuCapability,esc13IssuancePolicyState,esc15VersionOne,esc15RequesterControlsIdentity,@{N='MissingFactIds';E={@($_.missingFactIds)-join';'}},@{N='ValidationActions';E={@($_.validationActions)-join' | '}}|Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
$Top|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $TopPath -Encoding UTF8
$Lan=[pscustomobject][ordered]@{schemaVersion='1.0';plannerVersion=$PlannerVersion;sourceScope='preserved_real_evidence';candidateCount=$Sorted.Count;topCandidateCount=$Top.Count;consolidatedEvidenceActions=@($Consolidated);prohibitedAutomaticActions=@('Certificate request','Certificate authentication','Template modification','Group modification','CA setting change','Credential or hash replay');topCandidates=@($Top)}
$Lan|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $LanPath -Encoding UTF8
$TechniqueCounts=[ordered]@{};foreach($Technique in @($Sorted.technique|Sort-Object -Unique)){$TechniqueCounts[$Technique]=@($Sorted|Where-Object{[string]$_.technique -eq $Technique}).Count}
$Summary=[pscustomobject][ordered]@{schemaVersion='1.0';planner='ADCSValidationPlan';plannerVersion=$PlannerVersion;status='Completed';executionClass='offline_analysis';candidateCount=$Sorted.Count;techniqueCounts=[pscustomobject]$TechniqueCounts;p1Count=@($Sorted|Where-Object{$_.priorityBand -eq 'P1'}).Count;p2Count=@($Sorted|Where-Object{$_.priorityBand -eq 'P2'}).Count;p3Count=@($Sorted|Where-Object{$_.priorityBand -eq 'P3'}).Count;p4Count=@($Sorted|Where-Object{$_.priorityBand -eq 'P4'}).Count;privilegedTopCandidateCount=@($Top|Where-Object{[bool]$_.isPrivilegedContext}).Count;esc2CapabilityCandidateCount=@($Sorted|Where-Object{[bool]$_.esc2Capability}).Count;esc3AgentEkuCandidateCount=@($Sorted|Where-Object{[bool]$_.esc3AgentEkuCapability}).Count;esc13ConfirmedPolicyCandidateCount=@($Sorted|Where-Object{$_.esc13IssuancePolicyState -eq 'Confirmed'}).Count;esc13InconclusivePolicyCandidateCount=@($Sorted|Where-Object{$_.technique -eq 'ESC13' -and $_.esc13IssuancePolicyState -eq 'Inconclusive'}).Count;esc15FocusedCandidateCount=@($Sorted|Where-Object{[bool]$_.esc15VersionOne -and [bool]$_.esc15RequesterControlsIdentity}).Count;consolidatedActionCount=$Consolidated.Count;evidence=@($PlanPath,$CsvPath,$TopPath,$LanPath)}
$Summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$null=Write-PlanEvent 'Success' "Ranked $($Sorted.Count) candidates and consolidated $($Consolidated.Count) evidence actions." 'Planner v0.4.0'
Write-Output $Summary
