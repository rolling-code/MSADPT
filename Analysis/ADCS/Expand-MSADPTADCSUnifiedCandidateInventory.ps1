<#
.SYNOPSIS
Expands the validated ADCS unified candidate inventory from four to six techniques.
.DESCRIPTION
Combines the validated 516-route ESC1/ESC2/ESC4/ESC15 inventory with the validated 258-route
ESC3/ESC13 inventory. It normalizes missing and not-observed facts, validates exact technique counts,
rejects duplicate candidate IDs, and exports a planner-ready 774-route inventory.

No AD, CA, LDAP, DNS, TCP, SMB, Kerberos, certificate, authentication, credential or hash replay,
Ollama target interaction, registry, or ledger operation is performed.
.NOTES
Version: 0.2.0
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExistingUnifiedInventoryPath,
    [Parameter(Mandatory=$true)][string]$Esc3Esc13CandidatePath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateRange(1,100000)][int]$ExpectedRoutesPerTechnique=129,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ExpanderVersion='0.2.0'
$AllowedTechniques=@('ESC1','ESC2','ESC3','ESC4','ESC13','ESC15')

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    if(-not $Quiet){Write-Host ('[{0,-5}] {1}' -f $Status,$Message) -ForegroundColor $Color}
}
function Read-JsonArray {
    param([string]$Path,[string]$Label)
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "${Label}Missing: $Path"}
    try{$Rows=@(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)}catch{throw "${Label}JsonParseFailure: $($_.Exception.Message)"}
    if($Rows.Count -eq 0){throw "${Label}Empty: $Path"}
    return $Rows
}
function Normalize-Candidate {
    param($Candidate,[string]$SourceInventory)
    $Facts=@($Candidate.facts)
    $Missing=@($Facts|Where-Object{[string]$_.state -in @('Inconclusive','Not applicable')}|Select-Object id,state,rationale)
    $NotObserved=@($Facts|Where-Object{[string]$_.state -eq 'Not observed'}|Select-Object id,state,rationale)
    [pscustomobject][ordered]@{
        candidateId=[string]$Candidate.candidateId
        technique=[string]$Candidate.technique
        certificationAuthority=[string]$Candidate.certificationAuthority
        template=[string]$Candidate.template
        principal=[string]$Candidate.principal
        identityCategory=if ($null -ne $Candidate.PSObject.Properties['identityCategory']){[string]$Candidate.identityCategory}else{$null}
        accessRowCount=if ($null -ne $Candidate.PSObject.Properties['accessRowCount']){[int]$Candidate.accessRowCount}else{0}
        disposition=[string]$Candidate.disposition
        requiredCount=[int]$Candidate.requiredCount
        satisfiedRequiredCount=[int]$Candidate.satisfiedRequiredCount
        missingOrInconclusive=@($Missing)
        notObserved=@($NotObserved)
        facts=@($Facts)
        safeFollowUp=[string]$Candidate.safeFollowUp
        sourceInventory=$SourceInventory
        limitations=@('Normalized prerequisite route; not a severity, vulnerability, or exploitability declaration.')
    }
}

Write-Step 'START' 'Expanding unified ADCS inventory to six techniques.' Cyan
$Existing=@(Read-JsonArray $ExistingUnifiedInventoryPath 'ExistingUnifiedInventory')
$New=@(Read-JsonArray $Esc3Esc13CandidatePath 'Esc3Esc13Inventory')
$ExpectedExisting=$ExpectedRoutesPerTechnique*4
$ExpectedNew=$ExpectedRoutesPerTechnique*2
$ExpectedTotal=$ExpectedRoutesPerTechnique*6
if($Existing.Count -ne $ExpectedExisting){throw "ExistingInventoryCountMismatch: expected $ExpectedExisting, found $($Existing.Count)."}
if($New.Count -ne $ExpectedNew){throw "Esc3Esc13InventoryCountMismatch: expected $ExpectedNew, found $($New.Count)."}

$Expanded=@()
foreach($Candidate in $Existing){$Expanded+=,(Normalize-Candidate $Candidate $ExistingUnifiedInventoryPath)}
foreach($Candidate in $New){$Expanded+=,(Normalize-Candidate $Candidate $Esc3Esc13CandidatePath)}
if($Expanded.Count -ne $ExpectedTotal){throw "ExpandedInventoryCountMismatch: expected $ExpectedTotal, found $($Expanded.Count)."}
$Duplicates=@($Expanded|Group-Object candidateId|Where-Object{$_.Count -gt 1})
if($Duplicates.Count -gt 0){throw "DuplicateCandidateIds: $($Duplicates.Count) duplicate group(s)."}
$Unexpected=@($Expanded|Where-Object{[string]$_.technique -notin $AllowedTechniques})
if($Unexpected.Count -gt 0){throw "UnexpectedTechniques: $(@($Unexpected.technique|Sort-Object -Unique)-join', ')"}
$TechniqueCounts=[ordered]@{}
foreach($Technique in $AllowedTechniques){
    $Count=@($Expanded|Where-Object{[string]$_.technique -eq $Technique}).Count
    if($Count -ne $ExpectedRoutesPerTechnique){throw "TechniqueCountMismatch [$Technique]: expected $ExpectedRoutesPerTechnique, found $Count."}
    $TechniqueCounts[$Technique]=$Count
}

New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$JsonPath=Join-Path $OutputDirectory 'adcs-unified-candidate-inventory-v020.json'
$CsvPath=Join-Path $OutputDirectory 'adcs-unified-candidate-summary-v020.csv'
$SummaryPath=Join-Path $OutputDirectory 'adcs-unified-candidate-inventory-v020-summary.json'
$Sorted=@($Expanded|Sort-Object technique,template,principal)
$Sorted|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $JsonPath -Encoding UTF8
$Sorted|Select-Object candidateId,technique,certificationAuthority,template,principal,identityCategory,accessRowCount,disposition,requiredCount,satisfiedRequiredCount,@{Name='MissingFactIds';Expression={@($_.missingOrInconclusive|ForEach-Object id)-join';'}},@{Name='NotObservedFactIds';Expression={@($_.notObserved|ForEach-Object id)-join';'}},safeFollowUp,sourceInventory|Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
$Summary=[pscustomobject][ordered]@{
    schemaVersion='1.0';expander='ADCSUnifiedCandidateInventory';expanderVersion=$ExpanderVersion
    status='Completed';executionClass='offline_analysis';sourceScope='preserved_real_evidence'
    candidateCount=$Sorted.Count;expectedRoutesPerTechnique=$ExpectedRoutesPerTechnique
    techniqueCounts=[pscustomobject]$TechniqueCounts
    uniquePrincipalCount=@($Sorted.principal|Sort-Object -Unique).Count
    uniqueTemplateCount=@($Sorted.template|Sort-Object -Unique).Count
    prerequisitesSatisfiedCount=@($Sorted|Where-Object{[string]$_.disposition -eq 'Prerequisites satisfied'}).Count
    blockedCount=@($Sorted|Where-Object{[string]$_.disposition -eq 'Blocked'}).Count
    incompleteEvidenceCount=@($Sorted|Where-Object{[string]$_.disposition -eq 'Incomplete evidence'}).Count
    outputPath=$JsonPath;summaryCsvPath=$CsvPath
    nextAction='Use this 774-route inventory as the input to the next unified planner update.'
}
$Summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
Write-Step 'OK' "Validated $($Sorted.Count) unique routes across six techniques." Green
Write-Step 'DONE' 'Expanded unified inventory is planner-ready.' Green
Write-Output $Summary
