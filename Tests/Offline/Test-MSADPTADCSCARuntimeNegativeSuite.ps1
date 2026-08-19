<#
.SYNOPSIS
Verifies that every malformed ADCS CA-runtime fixture is rejected for the expected reason.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$NegativeFixtureGeneratorPath,
    [Parameter(Mandatory=$true)][string]$EvidenceValidatorPath,
    [Parameter(Mandatory=$true)][string]$ValidFixtureRoot,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

foreach ($Path in @($NegativeFixtureGeneratorPath, $EvidenceValidatorPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required script not found: $Path"
    }
}

$Generation = & $NegativeFixtureGeneratorPath -ValidFixtureRoot $ValidFixtureRoot -OutputDirectory $OutputDirectory
$Index = @(Get-Content -LiteralPath $Generation.IndexPath -Raw | ConvertFrom-Json)

$Results = foreach ($Scenario in $Index) {
    $Rejected = $false
    $ExpectedIssueObserved = $false
    $ErrorText = $null

    try {
        [void](& $EvidenceValidatorPath -EvidencePath $Scenario.EvidencePath -SummaryCsvPath $Scenario.SummaryPath -ServiceConnectionPointPath $Scenario.ServiceConnectionPointPath)
    }
    catch {
        $Rejected = $true
        $ErrorText = $_.Exception.Message
        $ExpectedIssueObserved = $ErrorText -match [regex]::Escape([string]$Scenario.ExpectedIssue)
    }

    [pscustomobject]@{
        Scenario = [string]$Scenario.Scenario
        Expected = 'Rejected'
        Actual = if ($Rejected) { 'Rejected' } else { 'Accepted' }
        Rejected = $Rejected
        ExpectedIssue = [string]$Scenario.ExpectedIssue
        ExpectedIssueObserved = $ExpectedIssueObserved
        Passed = ($Rejected -and $ExpectedIssueObserved)
        Error = $ErrorText
    }
}

$Results | Format-Table Scenario, Expected, Actual, Rejected, ExpectedIssueObserved, Passed, ExpectedIssue -AutoSize

$Failed = @($Results | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) {
    $Failed | Format-List Scenario, ExpectedIssue, Error
    throw "$($Failed.Count) malformed CA-runtime fixture(s) did not fail for the expected reason."
}

[pscustomobject]@{
    Status = 'Passed'
    SuiteVersion = '1.0.1'
    ScenarioCount = $Results.Count
    RejectedCount = @($Results | Where-Object Rejected).Count
    ExpectedIssueMatchCount = @($Results | Where-Object ExpectedIssueObserved).Count
    OutputDirectory = $OutputDirectory
}
