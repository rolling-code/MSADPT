<#
.SYNOPSIS
Tests the MSADPT snapshot comparison engine with deterministic fixtures.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ComparatorPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Tokens = $null
$ParseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile(
    $ComparatorPath,
    [ref]$Tokens,
    [ref]$ParseErrors
)
if ($ParseErrors.Count -gt 0) {
    throw "Comparator parse failed: $($ParseErrors.Message -join '; ')"
}

if (Test-Path -LiteralPath $OutputRoot) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

function New-SyntheticFact {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [Parameter(Mandatory=$true)][string]$State
    )
    [pscustomobject][ordered]@{
        id = $Id
        state = $State
    }
}

$BaselineManifest = [pscustomobject]@{
    files = @(
        [pscustomobject]@{relativePath='a.json';sha256='A';size=10}
    )
}
$CurrentManifest = [pscustomobject]@{
    files = @(
        [pscustomobject]@{relativePath='a.json';sha256='B';size=11}
        [pscustomobject]@{relativePath='b.json';sha256='C';size=2}
    )
}

$BaselineCandidates = @(
    [pscustomobject]@{
        candidateId='ESC1|CA|T|P';technique='ESC1';template='T';principal='P'
        disposition='Incomplete evidence'
        facts=@((New-SyntheticFact -Id 'x' -State 'Inconclusive'))
    }
    [pscustomobject]@{
        candidateId='ESC2|CA|T|P';technique='ESC2';template='T';principal='P'
        disposition='Blocked'
        facts=@((New-SyntheticFact -Id 'y' -State 'Not observed'))
    }
)
$CurrentCandidates = @(
    [pscustomobject]@{
        candidateId='ESC1|CA|T|P';technique='ESC1';template='T';principal='P'
        disposition='Prerequisites satisfied'
        facts=@((New-SyntheticFact -Id 'x' -State 'Confirmed'))
    }
    [pscustomobject]@{
        candidateId='ESC3|CA|T|P';technique='ESC3';template='T';principal='P'
        disposition='Incomplete evidence'
        facts=@((New-SyntheticFact -Id 'z' -State 'Inconclusive'))
    }
)
$BaselinePlan = @(
    [pscustomobject]@{candidateId='ESC1|CA|T|P';priorityBand='P3';validationPriorityScore=40;rank=2}
)
$CurrentPlan = @(
    [pscustomobject]@{candidateId='ESC1|CA|T|P';priorityBand='P1';validationPriorityScore=90;rank=1}
)

$Paths = @{}
foreach ($Name in @('baselineManifest','currentManifest','baselineCandidates','currentCandidates','baselinePlan','currentPlan')) {
    $Paths[$Name] = Join-Path $OutputRoot "$Name.json"
}
$BaselineManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Paths.baselineManifest -Encoding UTF8
$CurrentManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Paths.currentManifest -Encoding UTF8
$BaselineCandidates | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Paths.baselineCandidates -Encoding UTF8
$CurrentCandidates | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Paths.currentCandidates -Encoding UTF8
$BaselinePlan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Paths.baselinePlan -Encoding UTF8
$CurrentPlan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Paths.currentPlan -Encoding UTF8

$ComparisonRoot = Join-Path $OutputRoot 'comparison'
$Output = @(
    & $ComparatorPath `
        -BaselineManifestPath $Paths.baselineManifest `
        -CurrentManifestPath $Paths.currentManifest `
        -BaselineCandidatePath $Paths.baselineCandidates `
        -CurrentCandidatePath $Paths.currentCandidates `
        -BaselinePlanPath $Paths.baselinePlan `
        -CurrentPlanPath $Paths.currentPlan `
        -OutputDirectory $ComparisonRoot `
        -Quiet
)
$Terminal = @(
    $Output | Where-Object {
        $null -ne $_ -and
        $null -ne $_.PSObject.Properties['comparatorVersion'] -and
        $null -ne $_.PSObject.Properties['status']
    }
) | Select-Object -Last 1
if ($null -eq $Terminal) {
    throw 'Comparator terminal result missing.'
}

$Checks = @(
    [pscustomobject]@{Test='FileChanged';Passed=([int]$Terminal.fileChangedCount -eq 1)}
    [pscustomobject]@{Test='FileAdded';Passed=([int]$Terminal.fileAddedCount -eq 1)}
    [pscustomobject]@{Test='CandidateAdded';Passed=([int]$Terminal.candidateAddedCount -eq 1)}
    [pscustomobject]@{Test='CandidateRemoved';Passed=([int]$Terminal.candidateRemovedCount -eq 1)}
    [pscustomobject]@{Test='FactChanged';Passed=([int]$Terminal.factChangeCount -eq 1)}
    [pscustomobject]@{Test='DispositionChanged';Passed=([int]$Terminal.dispositionChangeCount -eq 1)}
    [pscustomobject]@{Test='PriorityChanged';Passed=([int]$Terminal.priorityChangeCount -eq 1)}
    [pscustomobject]@{Test='OutputsCreated';Passed=(@($Terminal.outputs | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -eq 5)}
)
$Checks | Format-Table -AutoSize
$Failed = @($Checks | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) {
    $Failed | Format-List Test,Passed
    throw "$($Failed.Count) comparison test(s) failed."
}

[pscustomobject][ordered]@{
    Status='Passed'
    TestCount=$Checks.Count
    ComparatorVersion='0.1.0'
    TestVersion='1.0.1'
}
