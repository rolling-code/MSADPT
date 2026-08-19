<#
.SYNOPSIS
Runs the real offline identity-context classification and ADCS candidate planner v0.2.0 in one step.
.DESCRIPTION
Discovers the standard MSADPT files, validates prerequisites, generates the real identity-context output
when needed, runs planner v0.2.0 against the candidate-specific facts, and prints the terminal result.
No AD, LDAP, CA, DNS, TCP, SMB, Kerberos, certificate, authentication, or ledger operation is performed.
.NOTES
Version: 1.0.0
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [ValidateRange(1,1000)][int]$TopCandidateCount = 25,
    [switch]$RebuildIdentityContext
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    Write-Host ('[{0,-5}] {1}' -f $Status,$Message) -ForegroundColor $Color
}

try {
    Write-Step 'START' 'Starting one-step offline ADCS candidate planning.' Cyan
    Write-Step 'INFO' "MSADPT root: $MSADPTRoot" DarkGray

    if (-not (Test-Path -LiteralPath $MSADPTRoot -PathType Container)) {
        throw "MSADPTRootNotFound: $MSADPTRoot"
    }

    $ClassifierPath = Join-Path $MSADPTRoot 'Analysis\Identity\Get-MSADPTADIdentityContext.ps1'
    $PlannerPath = Join-Path $MSADPTRoot 'Analysis\ADCS\Get-MSADPTADCSCandidateValidationPlan.ps1'
    $ConsoleModulePath = Join-Path $MSADPTRoot 'Common\MSADPT.Console.psm1'
    $OfflineGeneratedRoot = Join-Path $MSADPTRoot 'Tests\Offline\Generated'
    $CandidateFactsPath = Join-Path $OfflineGeneratedRoot 'ADCSCandidateSpecificFacts\adcs-candidate-specific-facts.json'
    $IdentityContextOutputRoot = Join-Path $OfflineGeneratedRoot 'ADIdentityContext'
    $IdentityContextPath = Join-Path $IdentityContextOutputRoot 'ad-identity-context.json'
    $PlannerOutputRoot = Join-Path $OfflineGeneratedRoot 'ADCSCandidateValidationPlan-v020'

    foreach ($RequiredPath in @($ClassifierPath,$PlannerPath,$ConsoleModulePath,$CandidateFactsPath)) {
        Write-Step 'CHECK' "Verifying required file: $RequiredPath" Yellow
        if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
            throw "RequiredFileMissing: $RequiredPath"
        }
        Write-Step 'OK' "Found: $RequiredPath" Green
    }

    Write-Step 'STEP' 'Locating the newest preserved resolved-identity-prerequisites.json evidence.' Yellow
    $IdentityEvidence = @(
        Get-ChildItem -LiteralPath (Join-Path $MSADPTRoot 'Engagements') -Filter 'resolved-identity-prerequisites.json' -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending
    ) | Select-Object -First 1
    if ($null -eq $IdentityEvidence) {
        throw 'IdentityEvidenceMissing: No resolved-identity-prerequisites.json was found under the MSADPT Engagements folder.'
    }
    $IdentityPrerequisitePath = $IdentityEvidence.FullName
    Write-Step 'OK' "Using identity evidence: $IdentityPrerequisitePath" Green

    if ($RebuildIdentityContext -or -not (Test-Path -LiteralPath $IdentityContextPath -PathType Leaf)) {
        Write-Step 'STEP' 'Generating real offline identity-context classifications.' Yellow
        $ClassifierOutput = @(
            & $ClassifierPath `
                -CandidateFactsPath $CandidateFactsPath `
                -IdentityPrerequisitePath $IdentityPrerequisitePath `
                -OutputDirectory $IdentityContextOutputRoot `
                -ConsoleModulePath $ConsoleModulePath
        )
        $ClassifierResult = @(
            $ClassifierOutput |
                Where-Object {
                    $null -ne $_.PSObject.Properties['classifierVersion'] -and
                    [string]$_.status -eq 'Completed'
                }
        ) | Select-Object -Last 1
        if ($null -eq $ClassifierResult) {
            throw 'IdentityClassifierTerminalResultMissing: The classifier did not return Completed.'
        }
        Write-Step 'OK' "Identity context completed: $($ClassifierResult.uniqueIdentityCount) unique identities." Green
    }
    else {
        Write-Step 'OK' "Using existing identity-context file: $IdentityContextPath" Green
    }

    Write-Step 'CHECK' 'Validating generated identity-context JSON.' Yellow
    $IdentityContextRows = @(Get-Content -LiteralPath $IdentityContextPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($IdentityContextRows.Count -eq 0) {
        throw 'IdentityContextEmpty: The generated identity-context file contains no records.'
    }
    Write-Step 'OK' "Identity-context records loaded: $($IdentityContextRows.Count)" Green

    Write-Step 'STEP' 'Running identity-aware ADCS candidate planner v0.2.0 against preserved real evidence.' Yellow
    $PlannerOutput = @(
        & $PlannerPath `
            -CandidateFactsPath $CandidateFactsPath `
            -IdentityContextPath $IdentityContextPath `
            -OutputDirectory $PlannerOutputRoot `
            -ConsoleModulePath $ConsoleModulePath `
            -TopCandidateCount $TopCandidateCount
    )
    $PlannerResult = @(
        $PlannerOutput |
            Where-Object {
                $null -ne $_.PSObject.Properties['plannerVersion'] -and
                [string]$_.status -eq 'Completed' -and
                [string]$_.plannerVersion -eq '0.2.0'
            }
    ) | Select-Object -Last 1
    if ($null -eq $PlannerResult) {
        throw 'PlannerTerminalResultMissing: Planner v0.2.0 did not return Completed.'
    }

    $PlanCsvPath = Join-Path $PlannerOutputRoot 'adcs-candidate-validation-plan.csv'
    $OfficePlanPath = Join-Path $PlannerOutputRoot 'adcs-next-lan-validation-plan.json'
    foreach ($OutputPath in @($PlanCsvPath,$OfficePlanPath)) {
        if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
            throw "ExpectedOutputMissing: $OutputPath"
        }
    }

    Write-Step 'DONE' 'Real offline identity-aware candidate planning completed successfully.' Green
    [pscustomobject][ordered]@{
        Status = 'Completed'
        RunnerVersion = '1.0.0'
        ClassifierVersion = '0.1.0'
        PlannerVersion = '0.2.0'
        CandidateCount = [int]$PlannerResult.candidateCount
        TopCandidateCount = [int]$PlannerResult.topCandidateCount
        P1Count = [int]$PlannerResult.p1Count
        P2Count = [int]$PlannerResult.p2Count
        PrivilegedTopCandidateCount = [int]$PlannerResult.privilegedTopCandidateCount
        ConsolidatedActionCount = [int]$PlannerResult.consolidatedActionCount
        IdentityContextPath = $IdentityContextPath
        PlanCsvPath = $PlanCsvPath
        OfficePlanPath = $OfficePlanPath
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
