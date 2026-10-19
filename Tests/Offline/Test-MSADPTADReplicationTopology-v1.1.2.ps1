<#
.SYNOPSIS
Runs offline regression tests for MSADPT AD replication and topology v1.1.2.
.NOTES
Version: 1.1.2
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Failures = [System.Collections.Generic.List[string]]::new()
$TemporaryRoot = Join-Path $env:TEMP ('MSADPT-ReplTopology-v112-' + [guid]::NewGuid().ToString('N'))

try {
    $EvidenceDirectory = Join-Path $TemporaryRoot 'Evidence'
    $RawDirectory = Join-Path $EvidenceDirectory 'Raw'
    New-Item -ItemType Directory -Path $RawDirectory -Force | Out-Null

    $Fixtures = [ordered]@{
        'forest.json' = [pscustomobject]@{
            Name = 'example.test'
            ExpectedNamingContexts = @(
                'DC=example,DC=test'
                'CN=Configuration,DC=example,DC=test'
            )
        }
        'domain-controllers.json' = @(
            [pscustomobject]@{ HostName = 'DC01.example.test'; Site = 'Site-A' }
            [pscustomobject]@{ HostName = 'DC02.example.test'; Site = 'Site-B' }
        )
        'sites.json' = @(
            [pscustomobject]@{ Name = 'Site-A' }
            [pscustomobject]@{ Name = 'Site-B' }
        )
        'subnets.json' = @()
        'site-links.json' = @()
        'reachability.json' = @(
            [pscustomobject]@{ Target = 'DC01.example.test'; Tcp9389Succeeded = $true }
            [pscustomobject]@{ Target = 'DC02.example.test'; Tcp9389Succeeded = $false }
        )
        'partner-metadata.json' = @(
            [pscustomobject]@{
                Server = 'DC01.example.test'
                Partner = 'CN=NTDS Settings,CN=DC02'
                Partition = 'DC=example,DC=test'
                LastReplicationSuccess = (Get-Date).ToUniversalTime().AddMinutes(-10).ToString('o')
                LastReplicationResult = 0
                ConsecutiveReplicationFailures = 0
            }
        )
        'operational-errors.json' = @()
    }

    foreach ($FixtureName in $Fixtures.Keys) {
        ConvertTo-Json -InputObject $Fixtures[$FixtureName] -Depth 10 |
            Set-Content -LiteralPath (Join-Path $RawDirectory $FixtureName) -Encoding UTF8
    }

    $CollectorPath = Join-Path $RepositoryRoot 'Modules\ADHealth\Collect-MSADPTADReplicationTopology-v1.1.1.ps1'
    $AnalyzerPath = Join-Path $RepositoryRoot 'Modules\ADHealth\Analyze-MSADPTADReplicationTopology-v1.1.2.ps1'

    foreach ($ScriptPath in @($CollectorPath, $AnalyzerPath)) {
        if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
            $Failures.Add("Missing script: $ScriptPath")
            continue
        }

        $Tokens = $null
        $ParserErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $ScriptPath,
            [ref]$Tokens,
            [ref]$ParserErrors
        )

        if (@($ParserErrors).Count -gt 0) {
            $Failures.Add("Parser errors in: $ScriptPath")
        }
    }

    if ($Failures.Count -eq 0) {
        $SavedLocation = Get-Location
        try {
            Set-Location -LiteralPath $TemporaryRoot
            $Result = & $AnalyzerPath -EvidenceDirectory '.\Evidence' -OutputDirectory '.\Output'
        }
        finally {
            Set-Location -LiteralPath $SavedLocation
        }

        $SummaryPath = Join-Path $TemporaryRoot 'Output\replication-topology-summary.json'
        $Summary = Get-Content -LiteralPath $SummaryPath -Raw | ConvertFrom-Json

        if ($Result.Status -ne 'Completed') {
            $Failures.Add('Analyzer status was not Completed.')
        }
        if ($Summary.OverallDisposition -ne 'Inconclusive') {
            $Failures.Add('Expected Inconclusive overall disposition.')
        }
        if ($Summary.DiscoveredControllerCount -ne 2) {
            $Failures.Add('Expected two discovered controllers.')
        }
        if ($Summary.AssessedControllerCount -ne 1) {
            $Failures.Add('Expected one assessed controller.')
        }
        if ($Summary.UnavailableControllerCount -ne 1) {
            $Failures.Add('Expected one unavailable controller.')
        }
        if ($Summary.MissingNamingContextCount -ne 1) {
            $Failures.Add('Expected one missing naming context.')
        }

        foreach ($OutputName in @(
            'controller-coverage.csv'
            'naming-context-coverage.csv'
            'replication-relationships.csv'
            'replication-topology-findings.csv'
            'replication-topology-summary.json'
            'MSADPT-AD-Replication-Topology.html'
        )) {
            $OutputPath = Join-Path $TemporaryRoot ('Output\' + $OutputName)
            if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
                $Failures.Add("Missing output: $OutputName")
            }
        }
    }

    if ($Failures.Count -gt 0) {
        $Failures | ForEach-Object {
            Write-Host "[FAIL] $_" -ForegroundColor Red
        }
        throw "Regression failures: $($Failures.Count)"
    }

    Write-Host '[PASS] AD replication and topology v1.1.2 regression passed.' -ForegroundColor Green
    [pscustomobject][ordered]@{
        Status = 'Passed'
        Version = '1.1.2'
        FailureCount = 0
    }
}
finally {
    if (Test-Path -LiteralPath $TemporaryRoot) {
        Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force
    }
}
