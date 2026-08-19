<#
.SYNOPSIS
Tests the MSADPT post-collection processor using deterministic offline tools and fixtures.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$ProcessorPath,[Parameter(Mandatory=$true)][string]$OutputRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Tokens=$null;$Errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($ProcessorPath,[ref]$Tokens,[ref]$Errors)
if($Errors.Count -gt 0){throw "Processor parse failed: $($Errors.Message -join '; ')"}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
$ToolRoot=Join-Path $OutputRoot 'repo';$AnalysisRoot=Join-Path $ToolRoot 'Analysis';$ToolsRoot=Join-Path $ToolRoot 'Tools';$DataRoot=Join-Path $OutputRoot 'data';New-Item -ItemType Directory -Path $AnalysisRoot,$ToolsRoot,$DataRoot -Force|Out-Null
$BuilderPath=Join-Path $AnalysisRoot 'New-MSADPTAssessmentSnapshotManifest.ps1';$ComparatorPath=Join-Path $AnalysisRoot 'Compare-MSADPTAssessmentSnapshots.ps1'
@'
<# Version: 0.1.1 #>
param([string[]]$InputPath,[string]$SnapshotRoot,[string]$OutputManifestPath,[string]$SnapshotLabel,[string]$SourceScope,[switch]$FailOnJsonParseError,[switch]$Quiet)
$Files=@(Get-ChildItem -LiteralPath $InputPath[0] -File);$Rows=@($Files|ForEach-Object{[pscustomobject]@{relativePath=$_.Name;sha256=(Get-FileHash $_.FullName).Hash;size=$_.Length}});[pscustomobject]@{files=$Rows}|ConvertTo-Json -Depth 5|Set-Content $OutputManifestPath;[pscustomobject]@{BuilderVersion='0.1.1';FileCount=$Rows.Count;TotalBytes=0;JsonFileCount=1;JsonParseFailureCount=0;ManifestPath=$OutputManifestPath;ManifestSha256=(Get-FileHash $OutputManifestPath).Hash}
'@|Set-Content -LiteralPath $BuilderPath -Encoding UTF8
@'
<# Version: 0.1.0 #>
param([string]$BaselineManifestPath,[string]$CurrentManifestPath,[string]$BaselineCandidatePath,[string]$CurrentCandidatePath,[string]$BaselinePlanPath,[string]$CurrentPlanPath,[string]$OutputDirectory,[switch]$FailOnUnexpectedShrinkage,[switch]$Quiet)
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null;@{}|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'comparison-summary.json');[pscustomobject]@{comparatorVersion='0.1.0';status='Completed';fileAddedCount=0;fileRemovedCount=0;fileChangedCount=1;candidateAddedCount=0;candidateRemovedCount=0;factChangeCount=1;dispositionChangeCount=1;priorityChangeCount=1;shrinkageWarnings=@()}
'@|Set-Content -LiteralPath $ComparatorPath -Encoding UTF8
function Fact($id,$state){[pscustomobject]@{id=$id;state=$state}}
$Candidates=@([pscustomobject]@{candidateId='ESC1|CA|T|P';technique='ESC1';disposition='Incomplete evidence';facts=@((Fact 'x' 'Inconclusive'))})
$Plan=@([pscustomobject]@{candidateId='ESC1|CA|T|P';priorityBand='P3';validationPriorityScore=40;rank=1})
$BaselineManifest=[pscustomobject]@{files=@([pscustomobject]@{relativePath='current.json';sha256='A';size=1})}
$CurrentFile=Join-Path $DataRoot 'current.json';$Candidates|ConvertTo-Json -Depth 6|Set-Content $CurrentFile
$Paths=@{bm=Join-Path $DataRoot 'baseline-manifest.json';bc=Join-Path $DataRoot 'baseline-candidates.json';bp=Join-Path $DataRoot 'baseline-plan.json';cc=Join-Path $DataRoot 'current-candidates.json';cp=Join-Path $DataRoot 'current-plan.json'}
$BaselineManifest|ConvertTo-Json -Depth 5|Set-Content $Paths.bm;$Candidates|ConvertTo-Json -Depth 6|Set-Content $Paths.bc;$Candidates|ConvertTo-Json -Depth 6|Set-Content $Paths.cc;$Plan|ConvertTo-Json -Depth 5|Set-Content $Paths.bp;$Plan|ConvertTo-Json -Depth 5|Set-Content $Paths.cp
$OutDir=Join-Path $OutputRoot 'out';$Checkpoint=Join-Path $OutputRoot 'checkpoint.json'
$Output=@(& $ProcessorPath -BaselineManifestPath $Paths.bm -BaselineCandidatePath $Paths.bc -BaselinePlanPath $Paths.bp -CurrentInputPath $DataRoot -CurrentSnapshotRoot $DataRoot -CurrentCandidatePath $Paths.cc -CurrentPlanPath $Paths.cp -OutputDirectory $OutDir -SnapshotBuilderPath $BuilderPath -ComparatorPath $ComparatorPath -SessionStatePath $Checkpoint -Quiet)
$Terminal=@($Output|Where-Object{$null -ne $_ -and $null -ne $_.PSObject.Properties['processorVersion']})|Select-Object -Last 1
$Checks=@(
 [pscustomobject]@{Test='TerminalResult';Passed=$null -ne $Terminal}
 [pscustomobject]@{Test='ManifestCreated';Passed=Test-Path (Join-Path $OutDir 'post-collection-manifest.json')}
 [pscustomobject]@{Test='ComparisonSummary';Passed=Test-Path (Join-Path $OutDir 'comparison\comparison-summary.json')}
 [pscustomobject]@{Test='ProcessingSummary';Passed=Test-Path (Join-Path $OutDir 'post-collection-processing-summary.json')}
 [pscustomobject]@{Test='CheckpointCreated';Passed=Test-Path $Checkpoint}
 [pscustomobject]@{Test='FactDeltaPreserved';Passed=[int]$Terminal.delta.factChangeCount -eq 1}
 [pscustomobject]@{Test='NoNetworkActivity';Passed=[string]$Terminal.safety.networkActivity -eq 'None'}
)
$Failed=@($Checks|Where-Object{-not $_.Passed});if($Failed.Count -gt 0){$Failed|Format-List;throw "$($Failed.Count) processor test(s) failed"}
[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;ProcessorVersion='0.1.0';TestVersion='1.0.0'}
