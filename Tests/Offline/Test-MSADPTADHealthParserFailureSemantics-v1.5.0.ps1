<#
.SYNOPSIS
Checks that AD Health parser and pipeline sources retain explicit degraded-collection semantics.
.NOTES
Version: 1.5.0. Static offline contract validation only.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path

$Files = @(
    'Modules\ADHealth\ConvertFrom-MSADPTADHealthOutput-v1.0.0.ps1',
    'Modules\ADHealth\Merge-MSADPTADHealthEvidence-v1.0.0.ps1',
    'Modules\ADHealth\Import-MSADPTADHealthEvidence-v1.1.0.ps1',
    'Modules\ADHealth\Test-MSADPTADHealthEvidenceCompleteness-v1.1.0.ps1',
    'Modules\ADHealth\Invoke-MSADPTADHealthOfflineAssessment-v1.1.0.ps1'
)
$Source = ''
foreach ($RelativePath in $Files) {
    $Path = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required AD Health semantic source missing: $RelativePath"
    }
    $Source += "`n" + (Get-Content -LiteralPath $Path -Raw)
}

$Contracts = @(
    [pscustomobject]@{Name='AccessDeniedExplicit'; Pattern='AccessDenied|access denied'},
    [pscustomobject]@{Name='TimeoutExplicit'; Pattern='TimedOut|Timeout|timed out'},
    [pscustomobject]@{Name='ToolUnavailableExplicit'; Pattern='ToolUnavailable|tool unavailable'},
    [pscustomobject]@{Name='InvalidInvocationExplicit'; Pattern='InvalidInvocation|usage|help output'},
    [pscustomobject]@{Name='PartialCollectionExplicit'; Pattern='Partial'},
    [pscustomobject]@{Name='InconclusiveDispositionExplicit'; Pattern='Inconclusive'},
    [pscustomobject]@{Name='HealthDispositionSeparated'; Pattern='HealthDisposition'},
    [pscustomobject]@{Name='CollectionStatusSeparated'; Pattern='CollectionStatus'},
    [pscustomobject]@{Name='ExecutionStatusSeparated'; Pattern='ExecutionStatus'},
    [pscustomobject]@{Name='NotDetectedExplicit'; Pattern='NotDetected|Not detected'}
)

$Results = foreach ($Contract in $Contracts) {
    [pscustomobject]@{
        Contract = $Contract.Name
        Passed = [bool]($Source -match $Contract.Pattern)
        Pattern = $Contract.Pattern
    }
}
$Results | Format-Table Contract,Passed,Pattern -AutoSize | Out-Host
$Failures = @($Results | Where-Object { -not $_.Passed })
if ($Failures.Count -gt 0) {
    throw "AD Health semantic contract failures: $($Failures.Contract -join ', ')"
}

[pscustomobject]@{
    Status = 'Passed'
    TestVersion = '1.5.0'
    ContractCount = $Results.Count
    AccessDeniedExplicit = $true
    TimeoutExplicit = $true
    InvalidInvocationExplicit = $true
    HealthAndCollectionStatesSeparated = $true
    NetworkActivity = 'None'
    ActiveDirectoryQueries = 'None'
    RemoteChanges = 'None'
}
