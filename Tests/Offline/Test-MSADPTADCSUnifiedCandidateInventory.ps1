<#
.SYNOPSIS
Tests the unified real-evidence inventory runner with a synthetic MSADPT tree.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunnerPath,
    [Parameter(Mandatory=$true)][string]$MergerSourcePath,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Tokens = $null
$ParseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile(
    $RunnerPath,
    [ref]$Tokens,
    [ref]$ParseErrors
)
if ($ParseErrors.Count -gt 0) {
    throw "Runner parse failed: $($ParseErrors.Message -join '; ')"
}

if (Test-Path -LiteralPath $OutputRoot) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}

$Root = Join-Path $OutputRoot 'MSADPT'
$AnalysisRoot = Join-Path $Root 'Analysis\ADCS'
$GeneratedRoot = Join-Path $Root 'Tests\Offline\Generated'
$Esc1Esc4Root = Join-Path $GeneratedRoot 'ADCSCandidateSpecificFacts'
$Esc2Esc15Root = Join-Path $GeneratedRoot 'ADCSCandidateESC2ESC15-RealEvidence'

New-Item -ItemType Directory -Path @(
    $AnalysisRoot,
    $Esc1Esc4Root,
    $Esc2Esc15Root
) -Force | Out-Null

Copy-Item `
    -LiteralPath $MergerSourcePath `
    -Destination (Join-Path $AnalysisRoot 'Merge-MSADPTADCSCandidateInventories.ps1') `
    -Force

function New-SyntheticCandidate {
    param([Parameter(Mandatory=$true)][string]$Technique)

    [pscustomobject][ordered]@{
        candidateId = "$Technique|CA|T|P"
        technique = $Technique
        certificationAuthority = 'CA'
        template = 'T'
        principal = 'P'
        disposition = 'Incomplete evidence'
        requiredCount = 1
        satisfiedRequiredCount = 0
        facts = @(
            [pscustomobject]@{
                id = 'x'
                state = 'Inconclusive'
                rationale = 'synthetic'
            }
        )
        safeFollowUp = 'synthetic'
    }
}

$Esc1Esc4Candidates = @(
    (New-SyntheticCandidate -Technique 'ESC1')
    (New-SyntheticCandidate -Technique 'ESC4')
)
$Esc2Esc15Candidates = @(
    (New-SyntheticCandidate -Technique 'ESC2')
    (New-SyntheticCandidate -Technique 'ESC15')
)

$Esc1Esc4Candidates |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $Esc1Esc4Root 'adcs-candidate-specific-facts.json') -Encoding UTF8

$Esc2Esc15Candidates |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $Esc2Esc15Root 'adcs-esc2-esc15-candidates.json') -Encoding UTF8

$Output = @(
    & $RunnerPath `
        -MSADPTRoot $Root `
        -ExpectedSourceRoutes 1 `
        -Quiet
)

$Terminal = @(
    $Output | Where-Object {
        $null -ne $_ -and
        $null -ne $_.PSObject.Properties['runnerVersion'] -and
        $null -ne $_.PSObject.Properties['status'] -and
        [string]$_.runnerVersion -eq '1.0.0' -and
        [string]$_.status -eq 'Completed'
    }
) | Select-Object -Last 1

if ($null -eq $Terminal) {
    throw 'Unified runner terminal result missing.'
}

$Checks = @(
    [pscustomobject]@{
        Test = 'FourRoutes'
        Passed = ([int]$Terminal.candidateCount -eq 4)
    }
    [pscustomobject]@{
        Test = 'TechniqueCounts'
        Passed = (
            [int]$Terminal.esc1Count -eq 1 -and
            [int]$Terminal.esc2Count -eq 1 -and
            [int]$Terminal.esc4Count -eq 1 -and
            [int]$Terminal.esc15Count -eq 1
        )
    }
    [pscustomobject]@{
        Test = 'PreservedScope'
        Passed = ([string]$Terminal.sourceScope -eq 'preserved_real_evidence')
    }
    [pscustomobject]@{
        Test = 'UniquePrincipal'
        Passed = ([int]$Terminal.uniquePrincipalCount -eq 1)
    }
    [pscustomobject]@{
        Test = 'UnifiedFileCreated'
        Passed = (Test-Path -LiteralPath $Terminal.unifiedInventoryPath -PathType Leaf)
    }
)

$Checks | Format-Table -AutoSize
$Failed = @($Checks | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) {
    $Failed | Format-List Test,Passed
    throw "$($Failed.Count) unified runner test(s) failed."
}

[pscustomobject][ordered]@{
    Status = 'Passed'
    TestCount = $Checks.Count
    RunnerVersion = '1.0.0'
    TestVersion = '1.0.1'
}
