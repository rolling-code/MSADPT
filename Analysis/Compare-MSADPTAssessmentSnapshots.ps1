<#
.SYNOPSIS
Compares two MSADPT assessment snapshots and exports deterministic deltas.
.DESCRIPTION
Environment-agnostic offline comparison engine. Compares file manifests, normalized candidate
inventories, and planner outputs. Reports added, removed, and changed files; added and removed
candidates; changed fact states; changed dispositions; priority-band and score changes; and
unexpected record-count shrinkage.

No network, AD, LDAP, SMB, Kerberos, certificate, authentication, Ollama, or ledger action occurs.
.NOTES
Version: 0.1.0
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BaselineManifestPath,
    [Parameter(Mandatory=$true)][string]$CurrentManifestPath,
    [string]$BaselineCandidatePath,
    [string]$CurrentCandidatePath,
    [string]$BaselinePlanPath,
    [string]$CurrentPlanPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$FailOnUnexpectedShrinkage,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ComparatorVersion='0.1.0'
function Write-Step([string]$Status,[string]$Message,[ConsoleColor]$Color){if(-not $Quiet){Write-Host ('[{0,-5}] {1}' -f $Status,$Message) -ForegroundColor $Color}}
function Read-Json([string]$Path,[string]$Label){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "${Label}Missing: $Path"};try{return Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop}catch{throw "${Label}ParseFailure: $($_.Exception.Message)"}}
function Read-JsonArray([string]$Path,[string]$Label){return @(Read-Json $Path $Label)}
function Get-PropertyValue($Object,[string]$Name){if($null -eq $Object){return $null};$Property=$Object.PSObject.Properties[$Name];if($null -eq $Property){return $null};return $Property.Value}
function Get-ManifestFiles($Manifest){$Files=Get-PropertyValue $Manifest 'baselineFiles';if($null -eq $Files){$Files=Get-PropertyValue $Manifest 'files'};return @($Files)}
function Get-ManifestFileKey($File){foreach($Name in @('relativePath','baselinePath','path','sourcePath','name')){$Value=Get-PropertyValue $File $Name;if(-not[string]::IsNullOrWhiteSpace([string]$Value)){return [string]$Value}};return $null}
function Get-FactMap($Candidate){$Map=@{};foreach($Fact in @($Candidate.facts)){$Id=[string](Get-PropertyValue $Fact 'id');if(-not[string]::IsNullOrWhiteSpace($Id)){$Map[$Id]=[string](Get-PropertyValue $Fact 'state')}};return $Map}
Write-Step 'START' 'Comparing MSADPT snapshots.' Cyan
$BaselineManifest=Read-Json $BaselineManifestPath 'BaselineManifest';$CurrentManifest=Read-Json $CurrentManifestPath 'CurrentManifest'
$BaselineFiles=@(Get-ManifestFiles $BaselineManifest);$CurrentFiles=@(Get-ManifestFiles $CurrentManifest)
$BaselineFileMap=@{};foreach($File in $BaselineFiles){$Key=Get-ManifestFileKey $File;if(-not[string]::IsNullOrWhiteSpace($Key)){$BaselineFileMap[$Key]=$File}}
$CurrentFileMap=@{};foreach($File in $CurrentFiles){$Key=Get-ManifestFileKey $File;if(-not[string]::IsNullOrWhiteSpace($Key)){$CurrentFileMap[$Key]=$File}}
$FileDelta=@();$AllFileKeys=@($BaselineFileMap.Keys+$CurrentFileMap.Keys|Sort-Object -Unique)
foreach($Key in $AllFileKeys){$Before=if($BaselineFileMap.ContainsKey($Key)){$BaselineFileMap[$Key]}else{$null};$After=if($CurrentFileMap.ContainsKey($Key)){$CurrentFileMap[$Key]}else{$null};$BeforeHash=[string](Get-PropertyValue $Before 'sha256');$AfterHash=[string](Get-PropertyValue $After 'sha256');$BeforeSize=Get-PropertyValue $Before 'size';$AfterSize=Get-PropertyValue $After 'size';$Change=if($null-eq$Before){'Added'}elseif($null-eq$After){'Removed'}elseif($BeforeHash-ne$AfterHash -or [string]$BeforeSize-ne[string]$AfterSize){'Changed'}else{'Unchanged'};$FileDelta+=,[pscustomobject]@{key=$Key;change=$Change;baselineSha256=$BeforeHash;currentSha256=$AfterHash;baselineSize=$BeforeSize;currentSize=$AfterSize}}
$CandidateDelta=@();$FactDelta=@();$DispositionDelta=@();$BaselineCandidates=@();$CurrentCandidates=@()
if(-not[string]::IsNullOrWhiteSpace($BaselineCandidatePath) -and -not[string]::IsNullOrWhiteSpace($CurrentCandidatePath)){
 $BaselineCandidates=@(Read-JsonArray $BaselineCandidatePath 'BaselineCandidates');$CurrentCandidates=@(Read-JsonArray $CurrentCandidatePath 'CurrentCandidates')
 $B=@{};foreach($Row in $BaselineCandidates){$B[[string]$Row.candidateId]=$Row};$C=@{};foreach($Row in $CurrentCandidates){$C[[string]$Row.candidateId]=$Row}
 foreach($Id in @($B.Keys+$C.Keys|Sort-Object -Unique)){$Before=if($B.ContainsKey($Id)){$B[$Id]}else{$null};$After=if($C.ContainsKey($Id)){$C[$Id]}else{$null};$Change=if($null-eq$Before){'Added'}elseif($null-eq$After){'Removed'}else{'Present'};if($Change-ne'Present'){$CandidateDelta+=,[pscustomobject]@{candidateId=$Id;change=$Change;technique=if($null-ne$After){$After.technique}else{$Before.technique};template=if($null-ne$After){$After.template}else{$Before.template};principal=if($null-ne$After){$After.principal}else{$Before.principal}}};if($null-ne$Before -and $null-ne$After){$BD=[string](Get-PropertyValue $Before 'disposition');$AD=[string](Get-PropertyValue $After 'disposition');if($BD-ne$AD){$DispositionDelta+=,[pscustomobject]@{candidateId=$Id;baselineDisposition=$BD;currentDisposition=$AD}};$BF=Get-FactMap $Before;$AF=Get-FactMap $After;foreach($FactId in @($BF.Keys+$AF.Keys|Sort-Object -Unique)){$BS=if($BF.ContainsKey($FactId)){$BF[$FactId]}else{'Missing'};$AS=if($AF.ContainsKey($FactId)){$AF[$FactId]}else{'Missing'};if($BS-ne$AS){$FactDelta+=,[pscustomobject]@{candidateId=$Id;factId=$FactId;baselineState=$BS;currentState=$AS}}}}}
}
$PriorityDelta=@();$BaselinePlan=@();$CurrentPlan=@()
if(-not[string]::IsNullOrWhiteSpace($BaselinePlanPath) -and -not[string]::IsNullOrWhiteSpace($CurrentPlanPath)){
 $BaselinePlan=@(Read-JsonArray $BaselinePlanPath 'BaselinePlan');$CurrentPlan=@(Read-JsonArray $CurrentPlanPath 'CurrentPlan');$B=@{};foreach($Row in $BaselinePlan){$B[[string]$Row.candidateId]=$Row};$C=@{};foreach($Row in $CurrentPlan){$C[[string]$Row.candidateId]=$Row};foreach($Id in @($B.Keys+$C.Keys|Sort-Object -Unique)){if($B.ContainsKey($Id)-and$C.ContainsKey($Id)){$Before=$B[$Id];$After=$C[$Id];$BB=[string](Get-PropertyValue $Before 'priorityBand');$AB=[string](Get-PropertyValue $After 'priorityBand');$BS=Get-PropertyValue $Before 'validationPriorityScore';$AS=Get-PropertyValue $After 'validationPriorityScore';$BR=Get-PropertyValue $Before 'rank';$AR=Get-PropertyValue $After 'rank';if($BB-ne$AB -or [string]$BS-ne[string]$AS -or [string]$BR-ne[string]$AR){$PriorityDelta+=,[pscustomobject]@{candidateId=$Id;baselineBand=$BB;currentBand=$AB;baselineScore=$BS;currentScore=$AS;baselineRank=$BR;currentRank=$AR}}}}
}
$Shrinkage=@();if($CurrentFiles.Count-lt$BaselineFiles.Count){$Shrinkage+=,"Manifest file count decreased from $($BaselineFiles.Count) to $($CurrentFiles.Count)."};if($CurrentCandidates.Count-lt$BaselineCandidates.Count){$Shrinkage+=,"Candidate count decreased from $($BaselineCandidates.Count) to $($CurrentCandidates.Count)."};if($CurrentPlan.Count-lt$BaselinePlan.Count){$Shrinkage+=,"Planner row count decreased from $($BaselinePlan.Count) to $($CurrentPlan.Count)."}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$FilePath=Join-Path $OutputDirectory 'file-integrity-delta.csv';$CandidatePath=Join-Path $OutputDirectory 'candidate-delta.json';$FactPath=Join-Path $OutputDirectory 'changed-facts.json';$DispositionPath=Join-Path $OutputDirectory 'disposition-changes.csv';$PriorityPath=Join-Path $OutputDirectory 'priority-changes.csv';$SummaryPath=Join-Path $OutputDirectory 'comparison-summary.json'
$FileDelta|Export-Csv -LiteralPath $FilePath -NoTypeInformation -Encoding UTF8;$CandidateDelta|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $CandidatePath -Encoding UTF8;$FactDelta|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $FactPath -Encoding UTF8;$DispositionDelta|Export-Csv -LiteralPath $DispositionPath -NoTypeInformation -Encoding UTF8;$PriorityDelta|Export-Csv -LiteralPath $PriorityPath -NoTypeInformation -Encoding UTF8
$Summary=[pscustomobject][ordered]@{schemaVersion='1.0';comparatorVersion=$ComparatorVersion;status=if($Shrinkage.Count-eq0){'Completed'}else{'CompletedWithWarnings'};fileAddedCount=@($FileDelta|Where-Object{$_.change-eq'Added'}).Count;fileRemovedCount=@($FileDelta|Where-Object{$_.change-eq'Removed'}).Count;fileChangedCount=@($FileDelta|Where-Object{$_.change-eq'Changed'}).Count;candidateAddedCount=@($CandidateDelta|Where-Object{$_.change-eq'Added'}).Count;candidateRemovedCount=@($CandidateDelta|Where-Object{$_.change-eq'Removed'}).Count;factChangeCount=$FactDelta.Count;dispositionChangeCount=$DispositionDelta.Count;priorityChangeCount=$PriorityDelta.Count;shrinkageWarnings=@($Shrinkage);outputs=@($FilePath,$CandidatePath,$FactPath,$DispositionPath,$PriorityPath)}
$Summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
if($FailOnUnexpectedShrinkage -and $Shrinkage.Count-gt0){throw "UnexpectedShrinkage: $($Shrinkage -join ' ')"}
Write-Step 'DONE' "Comparison completed: facts=$($FactDelta.Count), dispositions=$($DispositionDelta.Count), priorities=$($PriorityDelta.Count), shrinkageWarnings=$($Shrinkage.Count)." Green
Write-Output $Summary
