<#
.SYNOPSIS
Validates the MSADPT v1.9.0 core-correctness and reporting contracts offline.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Assert-Contains {
    param([string]$Text,[string]$Marker)
    if (-not $Text.Contains($Marker)) { throw "ContractMissing: $Marker" }
}

$Orchestrator = Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1'
$Importer = Join-Path $RepositoryRoot 'Modules\SMB\Import-MSADPTNmapSMBTargets.ps1'
foreach ($Path in @($Orchestrator,$Importer)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing: $Path" }
    $Tokens=$null; $ParseErrors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$ParseErrors)
    if (@($ParseErrors).Count -gt 0) { throw "ParserFailure[$Path]: $(@($ParseErrors|ForEach-Object{$_.Message}) -join '; ')" }
}

$Text = [IO.File]::ReadAllText($Orchestrator)
foreach ($Marker in @(
    "Version: 1.10.0",
    "`$OrchestratorVersion = '1.10.0'",
    "[string[]]`$ExpectedStatus = @('Completed')",
    "-BaseDirectory `$SMBCollectorDirectory -ExpectedStatus @('Completed','CompletedWithErrors')",
    'SMBCollectionMethodErrorCount',
    'PatchCollectionMethodErrorCount',
    '$SMBStageObject',
    'Posture at a Glance',
    '$KerberosPostureReportDisposition',
    'ConvertTo-MSADPTNormalizedSMBResult',
    'Actual remote changes this execution',
    'DirectoryControlDisposition',
    'DirectoryControlReductionSummaryPath',
    'Validation Priority',
    'DIRPLAN',
    'Discovered domain controllers plus operator-supplied Nmap-confirmed TCP/445 targets when provided',
    "MSADPT-Full-Audit-{0}"
)) { Assert-Contains $Text $Marker }
if ($Text.Contains('Convert-HtmlText (if(')) { throw 'InvalidInlineIfExpressionDetected' }

$Quick = @(& $Orchestrator -Mode Plan -Profile Quick -NoColor)
$QuickResult = @($Quick | Where-Object { $null -ne $_.PSObject.Properties['Status'] }) | Select-Object -Last 1
if ($null -eq $QuickResult -or [string]$QuickResult.Status -ne 'Passed' -or [int]$QuickResult.LiveModulesExecuted -ne 0) { throw 'QuickPlanRegressionFailed' }

$Full = @(& $Orchestrator -Mode Plan -Profile Full -NoColor)
$FullResult = @($Full | Where-Object { $null -ne $_.PSObject.Properties['Status'] }) | Select-Object -Last 1
if ($null -eq $FullResult -or [string]$FullResult.Status -ne 'Passed' -or [int]$FullResult.LiveModulesExecuted -ne 0) { throw 'FullPlanRegressionFailed' }

$ImporterText = [IO.File]::ReadAllText($Importer)
Assert-Contains $ImporterText 'Version: 1.0.6'
Assert-Contains $ImporterText "ImporterVersion='1.0.6'"

[pscustomobject][ordered]@{
    Status = 'Passed'
    TestVersion = '1.0.1'
    OrchestratorVersion = '1.10.0'
    QuickPlanStatus = [string]$QuickResult.Status
    FullPlanStatus = [string]$FullResult.Status
    PlanLiveModulesExecuted = [int]$FullResult.LiveModulesExecuted
    SMBResumeContract = 'ValidatedOffline'
    ErrorAccountingContract = 'ValidatedOffline'
    CoverageLedgerSMBContract = 'ValidatedOffline'
    ProfileAwarePathContract = 'ValidatedOffline'
    ReportPostureContract = 'ValidatedOffline'
    NetworkActivity = 'None'
    RemoteChanges = 'None'
}
