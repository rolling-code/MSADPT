<#
.SYNOPSIS
Proves that the AD Health collection gate accepts complete evidence and rejects incomplete or altered evidence.
.NOTES
Version: 1.5.0. Offline synthetic regression only.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$GatePath = Join-Path $RepositoryRoot 'Tests\Offline\Test-MSADPTADHealthCollectionEvidence-v1.4.0.ps1'

function New-SyntheticCollection {
    param(
        [Parameter(Mandatory)][string]$Root,
        [string[]]$Targets = @('DC01.example.test','DC02.example.test')
    )

    $RawRoot = Join-Path $Root 'Raw'
    $HtmlRoot = Join-Path $Root 'OfflineAssessment\Assessment'
    New-Item -ItemType Directory -Path $RawRoot,$HtmlRoot -Force | Out-Null

    $Records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Target in $Targets) {
        $SafeTarget = $Target -replace '[^A-Za-z0-9._-]','_'
        $Definitions = @(
            @('dcdiag.exe',"DCDiag-$SafeTarget.txt"),
            @('repadmin.exe',"Repadmin-ShowRepl-$SafeTarget.txt"),
            @('repadmin.exe',"Repadmin-Queue-$SafeTarget.txt"),
            @('nltest.exe',"Nltest-Query-$SafeTarget.txt"),
            @('nltest.exe',"Nltest-DSGetSite-$SafeTarget.txt"),
            @('w32tm.exe',"W32tm-Status-$SafeTarget.txt")
        )
        foreach ($Definition in $Definitions) {
            $OutputPath = Join-Path $RawRoot $Definition[1]
            Set-Content -LiteralPath $OutputPath -Value "synthetic evidence for $Target" -Encoding UTF8
            $Records.Add([pscustomobject]@{
                Target = $Target
                Utility = $Definition[0]
                OutputPath = $OutputPath
                SHA256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
            })
        }
    }

    $ReplSummaryPath = Join-Path $RawRoot 'Repadmin-ReplSummary.txt'
    Set-Content -LiteralPath $ReplSummaryPath -Value 'synthetic replication summary' -Encoding UTF8
    $Records.Add([pscustomobject]@{
        Target = 'Domain'
        Utility = 'repadmin.exe'
        OutputPath = $ReplSummaryPath
        SHA256 = (Get-FileHash -LiteralPath $ReplSummaryPath -Algorithm SHA256).Hash
    })

    @($Targets | ForEach-Object { [pscustomobject]@{ Target = $_ } }) |
        Export-Csv -LiteralPath (Join-Path $Root 'ExpectedTargets.csv') -NoTypeInformation -Encoding UTF8

    @($Records.ToArray()) |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $Root 'ADHealth-Collection-Manifest.json') -Encoding UTF8

    [pscustomobject]@{ Status='Completed'; TargetCount=$Targets.Count } |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $Root 'ADHealth-Collection-Summary.json') -Encoding UTF8

    Set-Content -LiteralPath (Join-Path $HtmlRoot 'MSADPT-AD-Health.html') -Value '<html><body>synthetic</body></html>' -Encoding UTF8

    [pscustomobject]@{
        Root = $Root
        RawRoot = $RawRoot
        HtmlRoot = $HtmlRoot
        Targets = $Targets
        ManifestPath = Join-Path $Root 'ADHealth-Collection-Manifest.json'
    }
}

function Invoke-GateScenario {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][scriptblock]$Mutation,
        [Parameter(Mandatory)][bool]$ShouldPass
    )

    $ScenarioRoot = Join-Path ([IO.Path]::GetTempPath()) ('MSADPT-ADHealth-v150-' + $Scenario + '-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ScenarioRoot -Force | Out-Null
    try {
        $Collection = New-SyntheticCollection -Root $ScenarioRoot
        & $Mutation $Collection

        $ObservedPass = $false
        $ErrorText = $null
        try {
            $GateResult = & $GatePath -CollectionRoot $ScenarioRoot
            $ObservedPass = ($GateResult.Status -eq 'Passed')
        }
        catch {
            $ErrorText = $_.Exception.Message
            $ObservedPass = $false
        }

        $ValidationPath = Join-Path $ScenarioRoot 'ADHealth-Collection-Validation.json'
        $ValidationStatus = 'NotGenerated'
        $FailedCheckCount = $null
        if (Test-Path -LiteralPath $ValidationPath -PathType Leaf) {
            $Validation = Get-Content -LiteralPath $ValidationPath -Raw | ConvertFrom-Json
            $ValidationStatus = [string]$Validation.Status
            $FailedCheckCount = [int]$Validation.FailedCheckCount
        }

        $ContractPassed = ($ObservedPass -eq $ShouldPass)
        if (-not $ContractPassed) {
            throw "Scenario '$Scenario' expected pass=$ShouldPass but observed pass=$ObservedPass. Error=$ErrorText"
        }
        if (-not $ShouldPass -and $ValidationStatus -ne 'Failed') {
            throw "Scenario '$Scenario' failed without a machine-readable Failed validation record."
        }
        if (-not $ShouldPass -and $FailedCheckCount -lt 1) {
            throw "Scenario '$Scenario' did not record a failed check."
        }

        [pscustomobject]@{
            Scenario = $Scenario
            ExpectedPass = $ShouldPass
            ObservedPass = $ObservedPass
            ValidationStatus = $ValidationStatus
            FailedCheckCount = $FailedCheckCount
            ContractPassed = $ContractPassed
        }
    }
    finally {
        Remove-Item -LiteralPath $ScenarioRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$NoMutation = { param($Collection) }
$Results = New-Object 'System.Collections.Generic.List[object]'
$Results.Add((Invoke-GateScenario -Scenario 'CompleteCollection' -Mutation $NoMutation -ShouldPass $true))
$Results.Add((Invoke-GateScenario -Scenario 'MissingDCDiag' -ShouldPass $false -Mutation {
    param($Collection)
    Remove-Item -LiteralPath (Join-Path $Collection.RawRoot 'DCDiag-DC01.example.test.txt') -Force
}))
$Results.Add((Invoke-GateScenario -Scenario 'MissingShowRepl' -ShouldPass $false -Mutation {
    param($Collection)
    Remove-Item -LiteralPath (Join-Path $Collection.RawRoot 'Repadmin-ShowRepl-DC02.example.test.txt') -Force
}))
$Results.Add((Invoke-GateScenario -Scenario 'EmptyW32tm' -ShouldPass $false -Mutation {
    param($Collection)
    Clear-Content -LiteralPath (Join-Path $Collection.RawRoot 'W32tm-Status-DC01.example.test.txt')
}))
$Results.Add((Invoke-GateScenario -Scenario 'HashMismatch' -ShouldPass $false -Mutation {
    param($Collection)
    Add-Content -LiteralPath (Join-Path $Collection.RawRoot 'Nltest-Query-DC01.example.test.txt') -Value 'tampered after manifest'
}))
$Results.Add((Invoke-GateScenario -Scenario 'ManifestOutputMissing' -ShouldPass $false -Mutation {
    param($Collection)
    Remove-Item -LiteralPath (Join-Path $Collection.RawRoot 'Repadmin-Queue-DC01.example.test.txt') -Force
}))
$Results.Add((Invoke-GateScenario -Scenario 'ExpectedTargetMissing' -ShouldPass $false -Mutation {
    param($Collection)
    @(
        [pscustomobject]@{Target='DC01.example.test'},
        [pscustomobject]@{Target='DC02.example.test'},
        [pscustomobject]@{Target='DC03.example.test'}
    ) | Export-Csv -LiteralPath (Join-Path $Collection.Root 'ExpectedTargets.csv') -NoTypeInformation -Encoding UTF8
}))
$Results.Add((Invoke-GateScenario -Scenario 'MissingReplSummary' -ShouldPass $false -Mutation {
    param($Collection)
    Remove-Item -LiteralPath (Join-Path $Collection.RawRoot 'Repadmin-ReplSummary.txt') -Force
}))
$Results.Add((Invoke-GateScenario -Scenario 'MissingHtmlReport' -ShouldPass $false -Mutation {
    param($Collection)
    Remove-Item -LiteralPath (Join-Path $Collection.HtmlRoot 'MSADPT-AD-Health.html') -Force
}))

$Results | Format-Table Scenario,ExpectedPass,ObservedPass,ValidationStatus,FailedCheckCount,ContractPassed -AutoSize | Out-Host
$FailedContracts = @($Results | Where-Object { -not $_.ContractPassed })
if ($FailedContracts.Count -gt 0) {
    throw "$($FailedContracts.Count) AD Health failure contract(s) failed."
}

[pscustomobject]@{
    Status = 'Passed'
    TestVersion = '1.5.0'
    ScenarioCount = $Results.Count
    CompleteCollectionAccepted = (@($Results | Where-Object Scenario -eq 'CompleteCollection')[0].ObservedPass)
    IncompleteCollectionsRejected = (@($Results | Where-Object { -not $_.ExpectedPass -and -not $_.ObservedPass }).Count -eq 8)
    HashMismatchRejected = (-not @($Results | Where-Object Scenario -eq 'HashMismatch')[0].ObservedPass)
    MissingTargetRejected = (-not @($Results | Where-Object Scenario -eq 'ExpectedTargetMissing')[0].ObservedPass)
    MachineReadableFailuresValidated = (@($Results | Where-Object { -not $_.ExpectedPass -and $_.ValidationStatus -eq 'Failed' }).Count -eq 8)
    NetworkActivity = 'None'
    ActiveDirectoryQueries = 'None'
    RemoteChanges = 'None'
}
