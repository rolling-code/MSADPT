<#
.SYNOPSIS
Builds and validates the unified real-evidence ADCS candidate inventory.
.DESCRIPTION
Discovers the standard preserved ESC1/ESC4 and ESC2/ESC15 inventories, invokes the validated merger,
requires exact route and technique counts, validates uniqueness and source scope, and exports a concise
inventory summary. No AD, CA, LDAP, DNS, TCP, SMB, Kerberos, certificate, authentication, Ollama, or
ledger operation is performed.
.NOTES
Version: 1.0.0
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot='C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [ValidateRange(1,100000)][int]$ExpectedSourceRoutes=129,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$RunnerVersion='1.0.0'
function Write-Step([string]$Status,[string]$Message,[ConsoleColor]$Color){if(-not $Quiet){Write-Host ('[{0,-5}] {1}' -f $Status,$Message) -ForegroundColor $Color}}
function Read-JsonArray([string]$Path,[string]$Label){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "${Label}Missing: $Path"}
    try{$Rows=@(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)}catch{throw "${Label}JsonParseFailure: $($_.Exception.Message)"}
    if($Rows.Count -eq 0){throw "${Label}Empty: $Path"};return $Rows
}
try{
    Write-Step 'START' 'Building unified real-evidence ADCS candidate inventory.' Cyan
    if(-not(Test-Path -LiteralPath $MSADPTRoot -PathType Container)){throw "MSADPTRootNotFound: $MSADPTRoot"}
    $MergerPath=Join-Path $MSADPTRoot 'Analysis\ADCS\Merge-MSADPTADCSCandidateInventories.ps1'
    $Esc1Esc4Path=Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSCandidateSpecificFacts\adcs-candidate-specific-facts.json'
    $Esc2Esc15Path=Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSCandidateESC2ESC15-RealEvidence\adcs-esc2-esc15-candidates.json'
    $OutputRoot=Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSUnifiedCandidateInventory'
    foreach($Input in @(
        [pscustomobject]@{Label='Validated merger';Path=$MergerPath},
        [pscustomobject]@{Label='ESC1/ESC4 inventory';Path=$Esc1Esc4Path},
        [pscustomobject]@{Label='ESC2/ESC15 inventory';Path=$Esc2Esc15Path}
    )){
        Write-Step 'CHECK' "$($Input.Label): $($Input.Path)" Yellow
        if(-not(Test-Path -LiteralPath $Input.Path -PathType Leaf)){throw "RequiredInputMissing [$($Input.Label)]: $($Input.Path)"}
        Write-Step 'OK' "$($Input.Label) found" Green
    }
    $First=@(Read-JsonArray $Esc1Esc4Path 'Esc1Esc4Inventory')
    $Second=@(Read-JsonArray $Esc2Esc15Path 'Esc2Esc15Inventory')
    $ExpectedFirst=$ExpectedSourceRoutes*2;$ExpectedSecond=$ExpectedSourceRoutes*2;$ExpectedTotal=$ExpectedSourceRoutes*4
    if($First.Count -ne $ExpectedFirst){throw "Esc1Esc4CountMismatch: expected $ExpectedFirst, found $($First.Count)."}
    if($Second.Count -ne $ExpectedSecond){throw "Esc2Esc15CountMismatch: expected $ExpectedSecond, found $($Second.Count)."}
    Write-Step 'OK' "Input counts validated: first=$($First.Count), second=$($Second.Count)" Green
    Write-Step 'STEP' 'Invoking validated candidate inventory merger v0.1.0.' Yellow
    $MergerOutput=@(& $MergerPath -Esc1Esc4CandidatePath $Esc1Esc4Path -Esc2Esc15CandidatePath $Esc2Esc15Path -OutputDirectory $OutputRoot)
    $Terminal=@($MergerOutput|Where-Object{
        $null -ne $_ -and
        $null -ne $_.PSObject.Properties['mergerVersion'] -and
        $null -ne $_.PSObject.Properties['status'] -and
        [string]$_.mergerVersion -eq '0.1.0' -and
        [string]$_.status -eq 'Completed'
    })|Select-Object -Last 1
    if($null -eq $Terminal){throw 'MergerTerminalResultMissing: Expected v0.1.0 Completed result.'}
    $Unified=@(Read-JsonArray $Terminal.outputPath 'UnifiedInventory')
    if($Unified.Count -ne $ExpectedTotal){throw "UnifiedCountMismatch: expected $ExpectedTotal, found $($Unified.Count)."}
    $Duplicates=@($Unified|Group-Object candidateId|Where-Object{$_.Count -gt 1})
    if($Duplicates.Count -gt 0){throw "DuplicateCandidateIds: $($Duplicates.Count) duplicate group(s)."}
    $ExpectedByTechnique=@{ESC1=$ExpectedSourceRoutes;ESC2=$ExpectedSourceRoutes;ESC4=$ExpectedSourceRoutes;ESC15=$ExpectedSourceRoutes}
    foreach($Technique in $ExpectedByTechnique.Keys){
        $Count=@($Unified|Where-Object{[string]$_.technique -eq $Technique}).Count
        if($Count -ne $ExpectedByTechnique[$Technique]){throw "TechniqueCountMismatch [$Technique]: expected $($ExpectedByTechnique[$Technique]), found $Count."}
    }
    $SummaryPath=Join-Path $OutputRoot 'adcs-unified-candidate-inventory-summary.json'
    $Summary=[pscustomobject][ordered]@{
        schemaVersion='1.0';runner='ADCSUnifiedCandidateInventory';runnerVersion=$RunnerVersion
        status='Completed';executionClass='offline_analysis';sourceScope='preserved_real_evidence'
        sourceRouteCount=$ExpectedSourceRoutes;candidateCount=$Unified.Count
        esc1Count=[int]$Terminal.esc1Count;esc2Count=[int]$Terminal.esc2Count
        esc4Count=[int]$Terminal.esc4Count;esc15Count=[int]$Terminal.esc15Count
        prerequisitesSatisfiedCount=@($Unified|Where-Object{[string]$_.disposition -eq 'Prerequisites satisfied'}).Count
        blockedCount=@($Unified|Where-Object{[string]$_.disposition -eq 'Blocked'}).Count
        incompleteEvidenceCount=@($Unified|Where-Object{[string]$_.disposition -eq 'Incomplete evidence'}).Count
        uniquePrincipalCount=@($Unified.principal|Sort-Object -Unique).Count
        uniqueTemplateCount=@($Unified.template|Sort-Object -Unique).Count
        unifiedInventoryPath=[string]$Terminal.outputPath;unifiedSummaryCsvPath=[string]$Terminal.summaryPath
        nextAction='Use this unified 516-route inventory as planner v0.3.0 input.'
        limitations=@('Unified candidates remain prerequisite records, not vulnerability or exploitability declarations.','ESC15 runtime, patch, and policy-module gaps remain inconclusive while offline.')
    }
    $Summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
    Write-Step 'OK' "Validated $($Unified.Count) unique routes: ESC1=$($Terminal.esc1Count), ESC2=$($Terminal.esc2Count), ESC4=$($Terminal.esc4Count), ESC15=$($Terminal.esc15Count)" Green
    Write-Step 'DONE' 'Unified real-evidence candidate inventory is ready for planner v0.3.0.' Green
    Write-Output $Summary
}catch{Write-Step 'FAIL' $_.Exception.Message Red;throw}
