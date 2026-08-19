<#
.SYNOPSIS
Runs the complete positive and negative ADCS CA-runtime offline test suite.
.NOTES
Version: 1.0.2
No network, Active Directory, certification authority, TCP, certutil, registry,
controller, or engagement-ledger operation is performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PositiveSuitePath,
    [Parameter(Mandatory = $true)][string]$NegativeSuitePath,
    [Parameter(Mandatory = $true)][string]$PositiveFixtureGeneratorPath,
    [Parameter(Mandatory = $true)][string]$NegativeFixtureGeneratorPath,
    [Parameter(Mandatory = $true)][string]$EvidenceValidatorPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

foreach ($Path in @(
    $PositiveSuitePath,
    $NegativeSuitePath,
    $PositiveFixtureGeneratorPath,
    $NegativeFixtureGeneratorPath,
    $EvidenceValidatorPath
)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required script not found: $Path"
    }
}

$PositiveOutput = Join-Path $OutputRoot 'Positive'
$NegativeOutput = Join-Path $OutputRoot 'Negative'

# Nested suite scripts intentionally emit diagnostic tables before their final result.
# Capture all pipeline output, preserve it for the caller, and select the structured
# terminal result by its required properties rather than assuming a single object.
$PositiveOutputObjects = @(
    & $PositiveSuitePath `
        -FixtureGeneratorPath $PositiveFixtureGeneratorPath `
        -EvidenceValidatorPath $EvidenceValidatorPath `
        -OutputDirectory $PositiveOutput
)

$PositiveResult = @(
    $PositiveOutputObjects |
        Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['Status'] -and
            $null -ne $_.PSObject.Properties['ScenarioCount'] -and
            [string]$_.Status -eq 'Passed'
        }
) | Select-Object -Last 1

if ($null -eq $PositiveResult) {
    throw 'PositiveSuiteTerminalResultMissing: The positive suite did not return a Passed terminal result.'
}

$PositiveOutputObjects | ForEach-Object { Write-Output $_ }

$ValidFixtureRoot = Join-Path $PositiveOutput 'SuccessSingleCa'

$NegativeOutputObjects = @(
    & $NegativeSuitePath `
        -NegativeFixtureGeneratorPath $NegativeFixtureGeneratorPath `
        -EvidenceValidatorPath $EvidenceValidatorPath `
        -ValidFixtureRoot $ValidFixtureRoot `
        -OutputDirectory $NegativeOutput
)

$NegativeResult = @(
    $NegativeOutputObjects |
        Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['Status'] -and
            $null -ne $_.PSObject.Properties['ScenarioCount'] -and
            $null -ne $_.PSObject.Properties['RejectedCount'] -and
            $null -ne $_.PSObject.Properties['ExpectedIssueMatchCount'] -and
            [string]$_.Status -eq 'Passed'
        }
) | Select-Object -Last 1

if ($null -eq $NegativeResult) {
    throw 'NegativeSuiteTerminalResultMissing: The negative suite did not return a Passed terminal result.'
}

$NegativeOutputObjects | ForEach-Object { Write-Output $_ }

$Passed = (
    [string]$PositiveResult.Status -eq 'Passed' -and
    [string]$NegativeResult.Status -eq 'Passed' -and
    [int]$NegativeResult.RejectedCount -eq [int]$NegativeResult.ScenarioCount -and
    [int]$NegativeResult.ExpectedIssueMatchCount -eq [int]$NegativeResult.ScenarioCount
)

if (-not $Passed) {
    throw 'CompleteSuiteValidationFailed: The complete ADCS CA-runtime offline suite did not satisfy every positive and negative gate.'
}

[pscustomobject][ordered]@{
    Status = 'Passed'
    SuiteVersion = '1.0.2'
    PositiveScenarioCount = [int]$PositiveResult.ScenarioCount
    NegativeScenarioCount = [int]$NegativeResult.ScenarioCount
    RejectedNegativeScenarioCount = [int]$NegativeResult.RejectedCount
    ExpectedIssueMatchCount = [int]$NegativeResult.ExpectedIssueMatchCount
    OutputRoot = $OutputRoot
}
