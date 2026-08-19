<#
.SYNOPSIS
Tests the end-to-end offline ADCS evidence-to-candidate pipeline.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PipelinePath,
    [Parameter(Mandatory=$true)][string]$FactBuilderPath,
    [Parameter(Mandatory=$true)][string]$CorrelationEnginePath,
    [Parameter(Mandatory=$true)][string]$CatalogPath,
    [Parameter(Mandatory=$true)][string]$TemplateConfigurationPath,
    [Parameter(Mandatory=$true)][string]$TemplateAccessPath,
    [Parameter(Mandatory=$true)][string]$IdentityPrerequisitePath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter()][string]$ConsoleModulePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

foreach ($Path in @(
    $PipelinePath,
    $FactBuilderPath,
    $CorrelationEnginePath,
    $CatalogPath,
    $TemplateConfigurationPath,
    $TemplateAccessPath,
    $IdentityPrerequisitePath
)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file not found: $Path"
    }
}

$Tokens = $null
$ParseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($PipelinePath,[ref]$Tokens,[ref]$ParseErrors)
if ($ParseErrors.Count -gt 0) {
    throw "Pipeline parse failed: $($ParseErrors.Message -join '; ')"
}

$Output = @(
    & $PipelinePath `
        -FactBuilderPath $FactBuilderPath `
        -CorrelationEnginePath $CorrelationEnginePath `
        -CatalogPath $CatalogPath `
        -TemplateConfigurationPath $TemplateConfigurationPath `
        -TemplateAccessPath $TemplateAccessPath `
        -IdentityPrerequisitePath $IdentityPrerequisitePath `
        -OutputRoot $OutputRoot `
        -ConsoleModulePath $ConsoleModulePath `
        -Quiet
)

$Terminal = @(
    $Output |
        Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['pipelineVersion'] -and
            [string]$_.status -eq 'Completed'
        }
) | Select-Object -Last 1

if ($null -eq $Terminal) {
    throw 'PipelineTerminalResultMissing: No completed terminal result was returned.'
}

$FactsPath = Join-Path $OutputRoot 'Facts\adcs-facts.json'
$CandidatePath = Join-Path $OutputRoot 'Correlation\adcs-technique-candidates.json'
$EventPath = Join-Path $OutputRoot 'adcs-offline-pipeline-events.json'
$SummaryPath = Join-Path $OutputRoot 'adcs-offline-pipeline-summary.json'

$Facts = @((Get-Content -LiteralPath $FactsPath -Raw | ConvertFrom-Json).facts)
$Candidates = @(Get-Content -LiteralPath $CandidatePath -Raw | ConvertFrom-Json)
$Events = @(Get-Content -LiteralPath $EventPath -Raw | ConvertFrom-Json)
$RuntimeTechniques = @('ESC3','ESC6','ESC7','ESC8','ESC9','ESC10','ESC11','ESC12','ESC15','ESC16')
$RuntimeCandidateRows = @($Candidates | Where-Object { $_.Technique -in $RuntimeTechniques })

$Checks = @(
    [pscustomobject]@{Test='PipelineParsed';Passed=($ParseErrors.Count -eq 0)},
    [pscustomobject]@{Test='TerminalCompleted';Passed=([string]$Terminal.status -eq 'Completed')},
    [pscustomobject]@{Test='NeutralFactsCreated';Passed=($Facts.Count -ge 12)},
    [pscustomobject]@{Test='AllSixteenTechniquesCreated';Passed=($Candidates.Count -eq 16)},
    [pscustomobject]@{Test='RuntimeEvidenceNotProvided';Passed=(-not [bool]$Terminal.runtimeEvidenceProvided)},
    [pscustomobject]@{Test='RuntimeTechniquesNotSatisfied';Passed=(@($RuntimeCandidateRows | Where-Object Disposition -eq 'Prerequisites satisfied').Count -eq 0)},
    [pscustomobject]@{Test='StructuredEventsCreated';Passed=($Events.Count -ge 4)},
    [pscustomobject]@{Test='SummaryCreated';Passed=(Test-Path -LiteralPath $SummaryPath -PathType Leaf)},
    [pscustomobject]@{Test='NoVulnerabilityDeclarations';Passed=((Get-Content -LiteralPath $CandidatePath -Raw) -notmatch '(?i)"Disposition"\s*:\s*"(Vulnerable|Exploitable|Critical|Domain compromise)"')}
)

$Checks | Format-Table -AutoSize
$Failed = @($Checks | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) {
    throw "$($Failed.Count) end-to-end offline ADCS pipeline test(s) failed."
}

[pscustomobject][ordered]@{
    Status = 'Passed'
    TestCount = $Checks.Count
    PipelineVersion = '0.1.0'
    BuilderVersion = [string]$Terminal.builderVersion
    EngineVersion = [string]$Terminal.engineVersion
    FactCount = $Facts.Count
    TechniqueCount = $Candidates.Count
    PrerequisitesSatisfiedCount = [int]$Terminal.prerequisitesSatisfiedCount
    BlockedCount = [int]$Terminal.blockedCount
    IncompleteEvidenceCount = [int]$Terminal.incompleteEvidenceCount
    OutputRoot = $OutputRoot
}
