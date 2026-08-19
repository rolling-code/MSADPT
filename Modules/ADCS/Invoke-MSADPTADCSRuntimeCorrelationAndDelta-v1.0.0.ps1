<#
.SYNOPSIS
Rebuilds aggregate ADCS correlation with CA-runtime evidence and compares it with the no-runtime baseline.
.DESCRIPTION
Consumes the authoritative CA-runtime evidence collected by ADCSCARuntimeConfigurationCollection v0.1.1,
runs the canonical ADCS end-to-end offline pipeline in a new isolated directory, validates all generated
outputs, and produces deterministic fact and technique-disposition deltas against the previously validated
no-runtime aggregate rebuild.

No network, AD, CA, certificate, authentication, registry, service, ledger, or Ollama operation occurs.
.NOTES
Version: 1.0.0
Package identity: MSADPT-ADCS-RUNTIME-CORRELATION-AND-DELTA
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$EngagementPath = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example',
    [string]$NoRuntimeBaselineRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example\analysis\ADCS\EndToEnd-v014-20260817-084053',
    [string]$OutputRoot,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$PackageIdentity='MSADPT-ADCS-RUNTIME-CORRELATION-AND-DELTA'
$PackageVersion='1.0.0'
$ExpectedRunnerHash='9D8B23208F1BC3AFDB5CFEB92477647B02507722F484A37EBB19F2C4353350DD'
$ExpectedFactBuilderHash='80DB4BBCF80287FB4F68C6B93D80B7FFECBAE52D02B354B4B331FDFA0373A41C'
$ExpectedCorrelationHash='93D0899D06342F5EF9D2D3818540DD392E3BC6935FEED4282AC104D55E4521CC'

function Write-Step { param([string]$Status,[string]$Message,[ConsoleColor]$Color) if(-not$Quiet){Write-Host ('[{0,-7}] {1}' -f $Status,$Message) -ForegroundColor $Color} }
function Require-File { param([string]$Path,[string]$Label) if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "RequiredFileMissing [$Label]: $Path"} }
function Validate-Script { param([string]$Path,[string]$Label,[string]$ExpectedHash)
    Require-File $Path $Label;$Tokens=$null;$Errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$Errors)
    if($Errors.Count-gt0){throw "ScriptParseFailure [$Label]: $($Errors.Message -join '; ')"}
    $Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant();if($Hash-ne$ExpectedHash){throw "ScriptHashMismatch [$Label]: expected $ExpectedHash, found $Hash"}
    [pscustomobject]@{label=$Label;path=$Path;sha256=$Hash}
}
function Read-JsonDocument { param([string]$Path,[string]$Label) Require-File $Path $Label;try{Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop}catch{throw "JsonParseFailure [$Label]: $($_.Exception.Message)"} }
function Get-Collection { param([object]$Document,[string[]]$Names,[string]$Label)
    if($Document-is[array]){return @($Document)}
    foreach($Name in $Names){$P=$Document.PSObject.Properties[$Name];if($null-ne$P){return @($P.Value)}}
    throw "CollectionPropertyNotFound [$Label]: $($Names -join ', ')"
}
function Get-Key { param([object]$Object,[string[]]$Names)
    foreach($Name in $Names){$P=$Object.PSObject.Properties[$Name];if($null-ne$P -and -not[string]::IsNullOrWhiteSpace([string]$P.Value)){return [string]$P.Value}}
    return $null
}
function Get-Value { param([object]$Object,[string[]]$Names)
    foreach($Name in $Names){$P=$Object.PSObject.Properties[$Name];if($null-ne$P){return $P.Value}}
    return $null
}

Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
Write-Step 'INFO' 'Offline correlation only; authoritative CA-runtime evidence will be consumed.' DarkGray
foreach($Dir in @($MSADPTRoot,$EngagementPath,$NoRuntimeBaselineRoot)){if(-not(Test-Path -LiteralPath $Dir -PathType Container)){throw "RequiredDirectoryMissing: $Dir"}}

$Runner=Join-Path $MSADPTRoot 'Analysis\ADCS\Invoke-MSADPTADCSEndToEndOfflineAnalysis.ps1'
$FactBuilder=Join-Path $MSADPTRoot 'Analysis\ADCS\Convert-MSADPTADCSEvidenceToFacts.ps1'
$Correlation=Join-Path $MSADPTRoot 'Analysis\ADCS\Invoke-MSADPTADCSPrerequisiteCorrelation.ps1'
$Catalog=Join-Path $MSADPTRoot 'Config\ADCS\adcs-technique-prerequisites-v1.0.0.json'
if(-not(Test-Path -LiteralPath $Catalog -PathType Leaf)){$Catalog=(Get-ChildItem -LiteralPath $MSADPTRoot -Filter 'adcs-technique-prerequisites-v1.0.0.json' -File -Recurse|Where-Object{$_.FullName-notmatch'\.backup-' -and $_.FullName-notmatch'\\Tests\\'}|Select-Object -First 1).FullName}
$Console=Join-Path $MSADPTRoot 'Common\MSADPT.Console.psm1'
$TemplateConfiguration=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-configuration.json'
$TemplateAccess=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-access.csv'
$IdentityPrerequisite=Join-Path $EngagementPath 'evidence\ADCSAttackPathPrerequisiteValidation\resolved-identity-prerequisites.json'
$RuntimeEvidence=Join-Path $EngagementPath 'evidence\ADCSCARuntimeConfigurationCollection\ca-runtime-evidence.json'
$BaselineFacts=Join-Path $NoRuntimeBaselineRoot 'Facts\adcs-facts.json'
$BaselineCandidates=Join-Path $NoRuntimeBaselineRoot 'Correlation\adcs-technique-candidates.json'
foreach($File in @($Catalog,$TemplateConfiguration,$TemplateAccess,$IdentityPrerequisite,$RuntimeEvidence,$BaselineFacts,$BaselineCandidates)){Require-File $File $File}

$RunnerInfo=Validate-Script $Runner 'End-to-end runner' $ExpectedRunnerHash
$FactBuilderInfo=Validate-Script $FactBuilder 'Fact builder' $ExpectedFactBuilderHash
$CorrelationInfo=Validate-Script $Correlation 'Correlation engine' $ExpectedCorrelationHash
if(Test-Path -LiteralPath $Console -PathType Leaf){$Tokens=$null;$Errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($Console,[ref]$Tokens,[ref]$Errors);if($Errors.Count-gt0){throw'ConsoleModuleParseFailure'}}else{$Console=$null}
Write-Step 'OK' 'Canonical runner, fact builder, and correlation engine validated.' Green

$RuntimeRows=@(Read-JsonDocument $RuntimeEvidence 'CA-runtime evidence')
if($RuntimeRows.Count-ne1){throw "RuntimeCARowCountMismatch: expected 1, found $($RuntimeRows.Count)"}
$Queries=@($RuntimeRows[0].CertutilQueries);if($Queries.Count-ne7){throw "RuntimeQueryCountMismatch: expected 7, found $($Queries.Count)"}
$CompletedQueries=@($Queries|Where-Object{[string]$_.Result.Status-eq'Completed'}).Count
$NonCompletedQueries=$Queries.Count-$CompletedQueries
Write-Step 'OK' "Validated authoritative runtime evidence: CAs=1, queries=7, completed=$CompletedQueries, non-completed=$NonCompletedQueries." Green

if([string]::IsNullOrWhiteSpace($OutputRoot)){$OutputRoot=Join-Path $EngagementPath ('analysis\ADCS\EndToEnd-Runtime-v011-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
if(Test-Path -LiteralPath $OutputRoot){if(@(Get-ChildItem -LiteralPath $OutputRoot -Force -ErrorAction SilentlyContinue).Count-gt0){throw "OutputRootNotEmpty: $OutputRoot"}}
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null

$Parameters=@{TemplateConfigurationPath=$TemplateConfiguration;TemplateAccessPath=$TemplateAccess;IdentityPrerequisitePath=$IdentityPrerequisite;CaRuntimeObservationPath=$RuntimeEvidence;FactBuilderPath=$FactBuilder;CatalogPath=$Catalog;CorrelationEnginePath=$Correlation;OutputRoot=$OutputRoot;Quiet=$Quiet;WarningVariable='PipelineWarnings'}
if($null-ne$Console){$Parameters.ConsoleModulePath=$Console}
$PipelineWarnings=@()
Write-Step 'ACTION' 'Running aggregate ADCS fact and correlation pipeline with CA-runtime evidence.' Yellow
$PipelineOutput=@(& $Runner @Parameters)
if($PipelineWarnings.Count-gt0){throw "PipelineWarningsDetected: $($PipelineWarnings -join '; ')"}

$CurrentFacts=Join-Path $OutputRoot 'Facts\adcs-facts.json'
$CurrentCandidates=Join-Path $OutputRoot 'Correlation\adcs-technique-candidates.json'
$CurrentSummary=Join-Path $OutputRoot 'adcs-offline-pipeline-summary.json'
foreach($File in @($CurrentFacts,$CurrentCandidates,$CurrentSummary)){Require-File $File $File}

$BaselineFactDoc=Read-JsonDocument $BaselineFacts 'Baseline facts'
$CurrentFactDoc=Read-JsonDocument $CurrentFacts 'Current facts'
$BaselineFactRows=@(Get-Collection $BaselineFactDoc @('facts','Facts','items','Items','records','Records') 'Baseline facts')
$CurrentFactRows=@(Get-Collection $CurrentFactDoc @('facts','Facts','items','Items','records','Records') 'Current facts')
if($BaselineFactRows.Count-ne20 -or $CurrentFactRows.Count-ne20){throw "FactCountMismatch: baseline=$($BaselineFactRows.Count), current=$($CurrentFactRows.Count)"}

$FactKeyNames=@('factId','FactId','factKey','FactKey','name','Name','prerequisiteId','PrerequisiteId','prerequisite','Prerequisite')
$StateNames=@('state','State','status','Status','value','Value','result','Result')
$BMap=@{};foreach($Fact in $BaselineFactRows){$Key=Get-Key $Fact $FactKeyNames;if($null-eq$Key){$Key=($Fact|ConvertTo-Json -Compress -Depth 10)};$BMap[$Key]=$Fact}
$CMap=@{};foreach($Fact in $CurrentFactRows){$Key=Get-Key $Fact $FactKeyNames;if($null-eq$Key){$Key=($Fact|ConvertTo-Json -Compress -Depth 10)};$CMap[$Key]=$Fact}
$FactDelta=@()
foreach($Key in @($BMap.Keys+$CMap.Keys|Sort-Object -Unique)){
    $Before=if($BMap.ContainsKey($Key)){$BMap[$Key]}else{$null};$After=if($CMap.ContainsKey($Key)){$CMap[$Key]}else{$null}
    $BeforeJson=if($null-ne$Before){$Before|ConvertTo-Json -Compress -Depth 15}else{$null};$AfterJson=if($null-ne$After){$After|ConvertTo-Json -Compress -Depth 15}else{$null}
    if($BeforeJson-ne$AfterJson){$FactDelta+=,[pscustomobject]@{factKey=$Key;baselineState=if($null-ne$Before){Get-Value $Before $StateNames}else{$null};currentState=if($null-ne$After){Get-Value $After $StateNames}else{$null};baseline=$Before;current=$After}}
}

$BaselineTechniqueRows=@(Read-JsonDocument $BaselineCandidates 'Baseline technique candidates')
$CurrentTechniqueRows=@(Read-JsonDocument $CurrentCandidates 'Current technique candidates')
if($BaselineTechniqueRows.Count-ne16 -or $CurrentTechniqueRows.Count-ne16){throw "TechniqueCountMismatch: baseline=$($BaselineTechniqueRows.Count), current=$($CurrentTechniqueRows.Count)"}
$TechniqueDelta=@()
foreach($Technique in @('ESC1','ESC2','ESC3','ESC4','ESC5','ESC6','ESC7','ESC8','ESC9','ESC10','ESC11','ESC12','ESC13','ESC14','ESC15','ESC16')){
    $Before=@($BaselineTechniqueRows|Where-Object{[string](Get-Value $_ @('technique','Technique','id','Id'))-eq$Technique})|Select-Object -First 1
    $After=@($CurrentTechniqueRows|Where-Object{[string](Get-Value $_ @('technique','Technique','id','Id'))-eq$Technique})|Select-Object -First 1
    if($null-eq$Before -or $null-eq$After){throw "TechniqueRecordMissing: $Technique"}
    $BeforeJson=$Before|ConvertTo-Json -Compress -Depth 15;$AfterJson=$After|ConvertTo-Json -Compress -Depth 15
    if($BeforeJson-ne$AfterJson){$TechniqueDelta+=,[pscustomobject]@{technique=$Technique;baselineDisposition=Get-Value $Before @('disposition','Disposition','status','Status');currentDisposition=Get-Value $After @('disposition','Disposition','status','Status');baselineSatisfied=Get-Value $Before @('satisfiedPrerequisiteCount','SatisfiedPrerequisiteCount','satisfiedCount');currentSatisfied=Get-Value $After @('satisfiedPrerequisiteCount','SatisfiedPrerequisiteCount','satisfiedCount');baseline=$Before;current=$After}}
}

$FactDeltaPath=Join-Path $OutputRoot 'runtime-fact-delta.json'
$TechniqueDeltaPath=Join-Path $OutputRoot 'runtime-technique-delta.json'
$SummaryPath=Join-Path $OutputRoot 'runtime-correlation-delta-summary.json'
$FactDelta|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $FactDeltaPath -Encoding UTF8
$TechniqueDelta|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $TechniqueDeltaPath -Encoding UTF8
$Summary=[pscustomobject][ordered]@{schemaVersion='1.0';packageIdentity=$PackageIdentity;packageVersion=$PackageVersion;status='Completed';generatedUtc=([DateTime](Get-Date)).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture);runtimeEvidence=[pscustomobject]@{path=$RuntimeEvidence;caCount=$RuntimeRows.Count;queryCount=$Queries.Count;completedQueryCount=$CompletedQueries;nonCompletedQueryCount=$NonCompletedQueries};baseline=[pscustomobject]@{root=$NoRuntimeBaselineRoot;factCount=$BaselineFactRows.Count;techniqueCount=$BaselineTechniqueRows.Count};current=[pscustomobject]@{root=$OutputRoot;factCount=$CurrentFactRows.Count;techniqueCount=$CurrentTechniqueRows.Count};delta=[pscustomobject]@{factChangeCount=$FactDelta.Count;techniqueChangeCount=$TechniqueDelta.Count;changedTechniques=@($TechniqueDelta.technique)};outputs=[pscustomobject]@{factDeltaPath=$FactDeltaPath;techniqueDeltaPath=$TechniqueDeltaPath;pipelineSummaryPath=$CurrentSummary};tools=[pscustomobject]@{runner=$RunnerInfo;factBuilder=$FactBuilderInfo;correlation=$CorrelationInfo};safety=[pscustomobject]@{networkActivity='None';collectorActivity='None';ledgerChanges='None';certificateActivity='None';authenticationActivity='None';ollamaActivity='None'}}
$Summary|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$Check=Get-Content -LiteralPath $SummaryPath -Raw|ConvertFrom-Json -ErrorAction Stop;if([string]$Check.status-ne'Completed'){throw'SummaryRoundTripFailure'}
Write-Step 'DONE' "Runtime correlation complete: facts changed=$($FactDelta.Count), techniques changed=$($TechniqueDelta.Count): $(@($TechniqueDelta.technique)-join', ')." Green
[pscustomobject][ordered]@{Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;RuntimeCACount=$RuntimeRows.Count;RuntimeQueryCount=$Queries.Count;CompletedRuntimeQueryCount=$CompletedQueries;NonCompletedRuntimeQueryCount=$NonCompletedQueries;FactCount=$CurrentFactRows.Count;TechniqueCount=$CurrentTechniqueRows.Count;FactChangeCount=$FactDelta.Count;TechniqueChangeCount=$TechniqueDelta.Count;ChangedTechniques=@($TechniqueDelta.technique);OutputRoot=$OutputRoot;SummaryPath=$SummaryPath;FactDeltaPath=$FactDeltaPath;TechniqueDeltaPath=$TechniqueDeltaPath;NetworkActivity='None';LedgerChanges='None';CertificateActivity='None';AuthenticationActivity='None';OllamaActivity='None'}
