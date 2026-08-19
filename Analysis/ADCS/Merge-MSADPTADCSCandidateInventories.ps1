<#
.SYNOPSIS
Normalizes and merges candidate-specific ADCS inventories for identity-aware planning.
.DESCRIPTION
Combines validated ESC1/ESC4 and ESC2/ESC15 candidate JSON files into one planner-compatible inventory.
Missing and not-observed fact collections are derived from each candidate facts array. Existing route
fields are preserved. The merger performs no network, AD, CA, LDAP, SMB, Kerberos, certificate,
authentication, Ollama, or ledger operation.
.NOTES
Version: 0.1.0
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Esc1Esc4CandidatePath,
    [Parameter(Mandatory=$true)][string]$Esc2Esc15CandidatePath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$MergerVersion='0.1.0'
function Write-Step([string]$Status,[string]$Message,[ConsoleColor]$Color){if(-not$Quiet){Write-Host ('[{0,-5}] {1}'-f$Status,$Message)-ForegroundColor $Color}}
function Read-JsonArray([string]$Path,[string]$Label){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "${Label}Missing: $Path"}
    try{$Rows=@(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)}catch{throw "${Label}JsonParseFailure: $($_.Exception.Message)"}
    if ($Rows.Count -eq 0){throw "${Label}Empty: $Path"};return $Rows
}
function Normalize-Candidate($Candidate,[string]$SourceInventory){
    $Facts=@($Candidate.facts)
    $Missing=@($Facts|Where-Object{[string]$_.state -in @('Inconclusive','Not applicable')}|Select-Object id,state,rationale)
    $NotObserved=@($Facts|Where-Object{[string]$_.state -eq 'Not observed'}|Select-Object id,state,rationale)
    $AccessRowCount=if ($null -ne $Candidate.PSObject.Properties['accessRowCount']){[int]$Candidate.accessRowCount}else{0}
    [pscustomobject][ordered]@{
        candidateId=[string]$Candidate.candidateId;technique=[string]$Candidate.technique
        certificationAuthority=[string]$Candidate.certificationAuthority;template=[string]$Candidate.template
        principal=[string]$Candidate.principal;identityCategory=if ($null -ne $Candidate.PSObject.Properties['identityCategory']){[string]$Candidate.identityCategory}else{$null}
        accessRowCount=$AccessRowCount;disposition=[string]$Candidate.disposition
        requiredCount=[int]$Candidate.requiredCount;satisfiedRequiredCount=[int]$Candidate.satisfiedRequiredCount
        missingOrInconclusive=@($Missing);notObserved=@($NotObserved);facts=@($Facts)
        safeFollowUp=[string]$Candidate.safeFollowUp;sourceInventory=$SourceInventory
        limitations=@('Normalized candidate route; disposition remains prerequisite-based and is not severity or exploitability.')
    }
}
Write-Step 'START' 'Merging ADCS candidate inventories.' Cyan
$First=@(Read-JsonArray $Esc1Esc4CandidatePath 'Esc1Esc4Candidates')
$Second=@(Read-JsonArray $Esc2Esc15CandidatePath 'Esc2Esc15Candidates')
$Merged=@()
foreach($Candidate in $First){$Merged+=,(Normalize-Candidate $Candidate $Esc1Esc4CandidatePath)}
foreach($Candidate in $Second){$Merged+=,(Normalize-Candidate $Candidate $Esc2Esc15CandidatePath)}
$Duplicates=@($Merged|Group-Object candidateId|Where-Object{$_.Count-gt1})
if ($Duplicates.Count -gt 0){throw "DuplicateCandidateIds: $($Duplicates.Count) duplicate group(s)."}
$Allowed=@('ESC1','ESC2','ESC4','ESC15')
$Unexpected=@($Merged|Where-Object{[string]$_.technique -notin $Allowed})
if ($Unexpected.Count -gt 0){throw "UnexpectedTechniques: $(@($Unexpected.technique|Sort-Object -Unique)-join', ')"}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$JsonPath=Join-Path $OutputDirectory 'adcs-unified-candidate-inventory.json'
$CsvPath=Join-Path $OutputDirectory 'adcs-unified-candidate-summary.csv'
$Merged|Sort-Object technique,template,principal|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $JsonPath -Encoding UTF8
$Merged|Sort-Object technique,template,principal|Select-Object candidateId,technique,certificationAuthority,template,principal,identityCategory,accessRowCount,disposition,requiredCount,satisfiedRequiredCount,@{N='MissingFactIds';E={@($_.missingOrInconclusive|ForEach-Object id)-join';'}},@{N='NotObservedFactIds';E={@($_.notObserved|ForEach-Object id)-join';'}},safeFollowUp|Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
$Counts=@{};foreach($Technique in $Allowed){$Counts[$Technique]=@($Merged|Where-Object{[string]$_.technique -eq $Technique}).Count}
Write-Step 'OK' "Unified inventory created: $($Merged.Count) unique routes." Green
[pscustomobject][ordered]@{status='Completed';mergerVersion=$MergerVersion;candidateCount=$Merged.Count;esc1Count=$Counts.ESC1;esc2Count=$Counts.ESC2;esc4Count=$Counts.ESC4;esc15Count=$Counts.ESC15;outputPath=$JsonPath;summaryPath=$CsvPath}
