<#
.SYNOPSIS
Builds and compares a post-collection MSADPT snapshot in one offline operation.
.DESCRIPTION
Validates the baseline and current inputs, builds the current snapshot manifest, requires valid JSON,
compares current outputs to the preserved baseline, fails on unexpected record shrinkage when requested,
and exports a compact processing summary. It invokes only the installed offline snapshot builder and
comparison engine.

No collector, AD, CA, LDAP, DNS, TCP, SMB, Kerberos, certificate, authentication, credential/hash replay,
Ollama, registry, or ledger operation is performed.
.NOTES
Version: 0.1.0
Package identity: MSADPT-POST-COLLECTION-PROCESSOR
Execution class: offline_post_collection_analysis
PowerShell: Windows PowerShell 5.1 and PowerShell 7
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BaselineManifestPath,
    [Parameter(Mandatory=$true)][string]$BaselineCandidatePath,
    [Parameter(Mandatory=$true)][string]$BaselinePlanPath,
    [Parameter(Mandatory=$true)][string[]]$CurrentInputPath,
    [Parameter(Mandatory=$true)][string]$CurrentSnapshotRoot,
    [Parameter(Mandatory=$true)][string]$CurrentCandidatePath,
    [Parameter(Mandatory=$true)][string]$CurrentPlanPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$SnapshotBuilderPath,
    [string]$ComparatorPath,
    [string]$SessionStatePath,
    [string]$SnapshotLabel='Post-collection validated snapshot',
    [string]$SourceScope='refreshed_real_evidence',
    [switch]$AllowShrinkage,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ProcessorVersion='0.1.0'
$PackageIdentity='MSADPT-POST-COLLECTION-PROCESSOR'

function Write-ProcessorEvent {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    if(-not $Quiet){Write-Host ('[{0,-7}] {1}' -f $Status,$Message) -ForegroundColor $Color}
}

function Test-RequiredFile {
    param([string]$Path,[string]$Label)
    if([string]::IsNullOrWhiteSpace($Path) -or -not(Test-Path -LiteralPath $Path -PathType Leaf)){
        throw "RequiredFileMissing [$Label]: $Path"
    }
}

function Test-RequiredDirectory {
    param([string]$Path,[string]$Label)
    if([string]::IsNullOrWhiteSpace($Path) -or -not(Test-Path -LiteralPath $Path -PathType Container)){
        throw "RequiredDirectoryMissing [$Label]: $Path"
    }
}

function Read-JsonArray {
    param([string]$Path,[string]$Label)
    Test-RequiredFile $Path $Label
    try{return @(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)}
    catch{throw "JsonParseFailure [$Label]: $($_.Exception.Message)"}
}

function Get-ScriptValidation {
    param([string]$Path,[string]$Label,[string]$ExpectedVersion)
    Test-RequiredFile $Path $Label
    $Tokens=$null
    $ParseErrors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$ParseErrors)
    if($ParseErrors.Count -gt 0){throw "ScriptParseFailure [$Label]: $($ParseErrors.Message -join '; ')"}
    $Text=[IO.File]::ReadAllText($Path)
    if(-not[string]::IsNullOrWhiteSpace($ExpectedVersion) -and $Text -notmatch [regex]::Escape($ExpectedVersion)){
        throw "ScriptVersionMismatch [$Label]: expected marker '$ExpectedVersion'."
    }
    [pscustomobject]@{path=$Path;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant();versionMarker=$ExpectedVersion}
}

Write-ProcessorEvent 'START' "$PackageIdentity v$ProcessorVersion" Cyan
Write-ProcessorEvent 'INFO' 'Safety mode: offline manifest, validation, and comparison only.' DarkGray

Test-RequiredFile $BaselineManifestPath 'Baseline manifest'
Test-RequiredFile $BaselineCandidatePath 'Baseline candidate inventory'
Test-RequiredFile $BaselinePlanPath 'Baseline planner output'
Test-RequiredDirectory $CurrentSnapshotRoot 'Current snapshot root'
Test-RequiredFile $CurrentCandidatePath 'Current candidate inventory'
Test-RequiredFile $CurrentPlanPath 'Current planner output'
foreach($Path in $CurrentInputPath){
    if(-not(Test-Path -LiteralPath $Path)){throw "CurrentInputPathMissing: $Path"}
}

if([string]::IsNullOrWhiteSpace($SnapshotBuilderPath)){
    $SnapshotBuilderPath=Join-Path (Split-Path $PSScriptRoot -Parent) 'Analysis\New-MSADPTAssessmentSnapshotManifest.ps1'
}
if([string]::IsNullOrWhiteSpace($ComparatorPath)){
    $ComparatorPath=Join-Path (Split-Path $PSScriptRoot -Parent) 'Analysis\Compare-MSADPTAssessmentSnapshots.ps1'
}

$BuilderValidation=Get-ScriptValidation $SnapshotBuilderPath 'Snapshot builder' 'Version: 0.1.1'
$ComparatorValidation=Get-ScriptValidation $ComparatorPath 'Snapshot comparator' 'Version: 0.1.0'
Write-ProcessorEvent 'OK' 'Offline builder and comparator parsed and version markers validated.' Green

$BaselineCandidates=@(Read-JsonArray $BaselineCandidatePath 'Baseline candidate inventory')
$CurrentCandidates=@(Read-JsonArray $CurrentCandidatePath 'Current candidate inventory')
$BaselinePlan=@(Read-JsonArray $BaselinePlanPath 'Baseline planner output')
$CurrentPlan=@(Read-JsonArray $CurrentPlanPath 'Current planner output')

$BaselineDuplicateCount=@($BaselineCandidates|Group-Object candidateId|Where-Object{$_.Count -gt 1}).Count
$CurrentDuplicateCount=@($CurrentCandidates|Group-Object candidateId|Where-Object{$_.Count -gt 1}).Count
if($BaselineDuplicateCount -gt 0){throw "BaselineDuplicateCandidateIds: $BaselineDuplicateCount group(s)."}
if($CurrentDuplicateCount -gt 0){throw "CurrentDuplicateCandidateIds: $CurrentDuplicateCount group(s)."}

$PreflightShrinkage=@()
if($CurrentCandidates.Count -lt $BaselineCandidates.Count){$PreflightShrinkage+=,"Candidate count decreased from $($BaselineCandidates.Count) to $($CurrentCandidates.Count)."}
if($CurrentPlan.Count -lt $BaselinePlan.Count){$PreflightShrinkage+=,"Planner row count decreased from $($BaselinePlan.Count) to $($CurrentPlan.Count)."}
if(-not $AllowShrinkage -and $PreflightShrinkage.Count -gt 0){throw "PreflightUnexpectedShrinkage: $($PreflightShrinkage -join ' ')"}
Write-ProcessorEvent 'OK' "Input validation passed: baseline candidates=$($BaselineCandidates.Count), current candidates=$($CurrentCandidates.Count)." Green

New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$ManifestPath=Join-Path $OutputDirectory 'post-collection-manifest.json'
$ComparisonRoot=Join-Path $OutputDirectory 'comparison'
$SummaryPath=Join-Path $OutputDirectory 'post-collection-processing-summary.json'

Write-ProcessorEvent 'STEP' 'Building current snapshot manifest with strict JSON validation.' Yellow
$BuilderOutput=@(
    & $SnapshotBuilderPath `
        -InputPath $CurrentInputPath `
        -SnapshotRoot $CurrentSnapshotRoot `
        -OutputManifestPath $ManifestPath `
        -SnapshotLabel $SnapshotLabel `
        -SourceScope $SourceScope `
        -FailOnJsonParseError `
        -Quiet
)
$BuilderResult=@(
    $BuilderOutput|Where-Object{
        $null -ne $_ -and
        $null -ne $_.PSObject.Properties['BuilderVersion'] -and
        $null -ne $_.PSObject.Properties['ManifestPath']
    }
)|Select-Object -Last 1
if($null -eq $BuilderResult){throw 'SnapshotBuilderTerminalResultMissing'}
if([int]$BuilderResult.JsonParseFailureCount -ne 0){throw "SnapshotJsonParseFailures: $($BuilderResult.JsonParseFailureCount)"}
Write-ProcessorEvent 'OK' "Current manifest created: files=$($BuilderResult.FileCount), JSON failures=0." Green

Write-ProcessorEvent 'STEP' 'Comparing current snapshot against preserved baseline.' Yellow
$ComparatorParameters=@{
    BaselineManifestPath=$BaselineManifestPath
    CurrentManifestPath=$ManifestPath
    BaselineCandidatePath=$BaselineCandidatePath
    CurrentCandidatePath=$CurrentCandidatePath
    BaselinePlanPath=$BaselinePlanPath
    CurrentPlanPath=$CurrentPlanPath
    OutputDirectory=$ComparisonRoot
    Quiet=$true
}
if(-not $AllowShrinkage){$ComparatorParameters['FailOnUnexpectedShrinkage']=$true}
$ComparatorOutput=@(& $ComparatorPath @ComparatorParameters)
$ComparisonResult=@(
    $ComparatorOutput|Where-Object{
        $null -ne $_ -and
        $null -ne $_.PSObject.Properties['comparatorVersion'] -and
        $null -ne $_.PSObject.Properties['status']
    }
)|Select-Object -Last 1
if($null -eq $ComparisonResult){throw 'ComparatorTerminalResultMissing'}

$Summary=[pscustomobject][ordered]@{
    schemaVersion='1.0'
    packageIdentity=$PackageIdentity
    processorVersion=$ProcessorVersion
    status='Completed'
    generatedUtc=([DateTime](Get-Date)).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    safety=[pscustomobject]@{networkActivity='None';collectorActivity='None';ledgerChanges='None';ollamaActivity='None'}
    tools=[pscustomobject]@{snapshotBuilder=$BuilderValidation;snapshotComparator=$ComparatorValidation}
    baseline=[pscustomobject]@{manifestPath=$BaselineManifestPath;candidateCount=$BaselineCandidates.Count;planRowCount=$BaselinePlan.Count}
    current=[pscustomobject]@{manifestPath=$ManifestPath;manifestSha256=$BuilderResult.ManifestSha256;fileCount=$BuilderResult.FileCount;candidateCount=$CurrentCandidates.Count;planRowCount=$CurrentPlan.Count}
    delta=[pscustomobject]@{
        fileAddedCount=[int]$ComparisonResult.fileAddedCount
        fileRemovedCount=[int]$ComparisonResult.fileRemovedCount
        fileChangedCount=[int]$ComparisonResult.fileChangedCount
        candidateAddedCount=[int]$ComparisonResult.candidateAddedCount
        candidateRemovedCount=[int]$ComparisonResult.candidateRemovedCount
        factChangeCount=[int]$ComparisonResult.factChangeCount
        dispositionChangeCount=[int]$ComparisonResult.dispositionChangeCount
        priorityChangeCount=[int]$ComparisonResult.priorityChangeCount
        shrinkageWarnings=@($ComparisonResult.shrinkageWarnings)
    }
    outputs=[pscustomobject]@{comparisonRoot=$ComparisonRoot;comparisonSummary=(Join-Path $ComparisonRoot 'comparison-summary.json');processingSummary=$SummaryPath}
}
$Summary|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$RoundTrip=Get-Content -LiteralPath $SummaryPath -Raw|ConvertFrom-Json -ErrorAction Stop
if([string]$RoundTrip.status -ne 'Completed'){throw 'ProcessingSummaryRoundTripFailure'}

if(-not[string]::IsNullOrWhiteSpace($SessionStatePath)){
    $SessionStateParent=Split-Path $SessionStatePath -Parent
    if(-not[string]::IsNullOrWhiteSpace($SessionStateParent)){New-Item -ItemType Directory -Path $SessionStateParent -Force|Out-Null}
    $Checkpoint=[pscustomobject][ordered]@{
        schemaVersion='1.0';checkpoint='PostCollectionProcessing';status='Passed'
        updatedUtc=$Summary.generatedUtc;processorVersion=$ProcessorVersion
        outputDirectory=$OutputDirectory;summaryPath=$SummaryPath
        candidateCount=$CurrentCandidates.Count;factChangeCount=$Summary.delta.factChangeCount
        dispositionChangeCount=$Summary.delta.dispositionChangeCount;priorityChangeCount=$Summary.delta.priorityChangeCount
    }
    $Checkpoint|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $SessionStatePath -Encoding UTF8
    Write-ProcessorEvent 'OK' "Post-collection checkpoint written: $SessionStatePath" Green
}

Write-ProcessorEvent 'DONE' "Post-collection processing complete: facts=$($Summary.delta.factChangeCount), dispositions=$($Summary.delta.dispositionChangeCount), priorities=$($Summary.delta.priorityChangeCount)." Green
Write-Output $Summary
