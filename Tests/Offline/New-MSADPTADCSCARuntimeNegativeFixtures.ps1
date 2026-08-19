<#
.SYNOPSIS
Creates deterministic malformed ADCS CA-runtime fixtures for negative offline testing.
.DESCRIPTION
Copies a previously generated valid SuccessSingleCa fixture and introduces one controlled defect per scenario.
The script does not contact Active Directory, resolve DNS, open sockets, invoke certutil, or alter an engagement.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ValidFixtureRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ValidEvidencePath = Join-Path $ValidFixtureRoot 'ca-runtime-evidence.json'
$ValidSummaryPath = Join-Path $ValidFixtureRoot 'ca-runtime-summary.csv'
$ValidScpPath = Join-Path $ValidFixtureRoot 'adcs-service-connection-points.json'

foreach ($RequiredPath in @($ValidEvidencePath, $ValidSummaryPath, $ValidScpPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Required valid fixture not found: $RequiredPath"
    }
}

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Copy-ValidFixture {
    param([string]$ScenarioName)

    $ScenarioDirectory = Join-Path $OutputDirectory $ScenarioName
    New-Item -ItemType Directory -Path $ScenarioDirectory -Force | Out-Null

    $EvidencePath = Join-Path $ScenarioDirectory 'ca-runtime-evidence.json'
    $SummaryPath = Join-Path $ScenarioDirectory 'ca-runtime-summary.csv'
    $ScpPath = Join-Path $ScenarioDirectory 'adcs-service-connection-points.json'

    Copy-Item -LiteralPath $ValidEvidencePath -Destination $EvidencePath -Force
    Copy-Item -LiteralPath $ValidSummaryPath -Destination $SummaryPath -Force
    Copy-Item -LiteralPath $ValidScpPath -Destination $ScpPath -Force

    [pscustomobject][ordered]@{
        Scenario = $ScenarioName
        ScenarioDirectory = $ScenarioDirectory
        EvidencePath = $EvidencePath
        SummaryPath = $SummaryPath
        ServiceConnectionPointPath = $ScpPath
    }
}

function Save-Evidence {
    param($Evidence, [string]$Path)
    $Evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$Index = New-Object 'System.Collections.Generic.List[object]'

# 1. Duplicate CA configuration.
$Fixture = Copy-ValidFixture 'DuplicateCaConfiguration'
$Evidence = @(Get-Content -LiteralPath $Fixture.EvidencePath -Raw | ConvertFrom-Json)
Save-Evidence -Evidence @($Evidence[0], $Evidence[0]) -Path $Fixture.EvidencePath
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='DuplicateCaConfiguration';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 2. Missing required CA property.
$Fixture = Copy-ValidFixture 'MissingRequiredProperty'
$Evidence = @(Get-Content -LiteralPath $Fixture.EvidencePath -Raw | ConvertFrom-Json)
[void]$Evidence[0].PSObject.Properties.Remove('DnsHostName')
Save-Evidence -Evidence $Evidence -Path $Fixture.EvidencePath
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='MissingProperty';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 3. Malformed JSON.
$Fixture = Copy-ValidFixture 'MalformedJson'
Set-Content -LiteralPath $Fixture.EvidencePath -Value '{"Name":"broken"' -Encoding UTF8
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='JsonParseFailure';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 4. Missing expected certutil query.
$Fixture = Copy-ValidFixture 'MissingCertutilQuery'
$Evidence = @(Get-Content -LiteralPath $Fixture.EvidencePath -Raw | ConvertFrom-Json)
$Evidence[0].CertutilQueries = @($Evidence[0].CertutilQueries | Where-Object Name -ne 'OfficerRights')
Save-Evidence -Evidence $Evidence -Path $Fixture.EvidencePath
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='MissingQuery';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 5. Unsupported query status.
$Fixture = Copy-ValidFixture 'UnexpectedQueryStatus'
$Evidence = @(Get-Content -LiteralPath $Fixture.EvidencePath -Raw | ConvertFrom-Json)
$Evidence[0].CertutilQueries[0].Result.Status = 'UnknownState'
Save-Evidence -Evidence $Evidence -Path $Fixture.EvidencePath
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='UnexpectedStatus';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 6. Query points at another CA.
$Fixture = Copy-ValidFixture 'QueryConfigurationMismatch'
$Evidence = @(Get-Content -LiteralPath $Fixture.EvidencePath -Raw | ConvertFrom-Json)
$Evidence[0].CertutilQueries[0].Result.CaConfiguration = 'other.example.test\OTHER-CA'
Save-Evidence -Evidence $Evidence -Path $Fixture.EvidencePath
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='ConfigurationMismatch';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 7. Explicit -config arguments removed.
$Fixture = Copy-ValidFixture 'MissingExplicitConfiguration'
$Evidence = @(Get-Content -LiteralPath $Fixture.EvidencePath -Raw | ConvertFrom-Json)
$Evidence[0].CertutilQueries[0].Result.Arguments = @('-ping')
Save-Evidence -Evidence $Evidence -Path $Fixture.EvidencePath
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='UnsafeOrMissingExplicitConfiguration';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 8. Reachable port incorrectly carries an error.
$Fixture = Copy-ValidFixture 'ReachablePortWithError'
$Evidence = @(Get-Content -LiteralPath $Fixture.EvidencePath -Raw | ConvertFrom-Json)
$ReachablePort = @($Evidence[0].PortEvidence | Where-Object Reachable | Select-Object -First 1)
$ReachablePort[0].Error = 'Synthetic inconsistent error'
Save-Evidence -Evidence $Evidence -Path $Fixture.EvidencePath
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='ReachableWithError';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 9. Summary completed-query count is incorrect.
$Fixture = Copy-ValidFixture 'SummaryCountMismatch'
$Summary = @(Import-Csv -LiteralPath $Fixture.SummaryPath)
$Summary[0].CompletedCertutilQueryCount = '999'
$Summary | Export-Csv -LiteralPath $Fixture.SummaryPath -NoTypeInformation -Encoding UTF8
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='CompletedQueryCountMismatch';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 10. Duplicate summary row.
$Fixture = Copy-ValidFixture 'DuplicateSummaryRow'
$Summary = @(Import-Csv -LiteralPath $Fixture.SummaryPath)
@($Summary[0], $Summary[0]) | Export-Csv -LiteralPath $Fixture.SummaryPath -NoTypeInformation -Encoding UTF8
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='MissingOrDuplicateSummaryRow';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

# 11. Malformed service-connection-point JSON.
$Fixture = Copy-ValidFixture 'MalformedServiceConnectionPointJson'
Set-Content -LiteralPath $Fixture.ServiceConnectionPointPath -Value '{"Name": invalid-json-token }' -Encoding UTF8
$Index.Add([pscustomobject][ordered]@{Scenario=$Fixture.Scenario;ExpectedValidatorResult='Rejected';ExpectedIssue='ServiceConnectionPointJsonParseFailure';EvidencePath=$Fixture.EvidencePath;SummaryPath=$Fixture.SummaryPath;ServiceConnectionPointPath=$Fixture.ServiceConnectionPointPath})

$IndexPath = Join-Path $OutputDirectory 'negative-fixture-index.json'
$Index.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $IndexPath -Encoding UTF8

[pscustomobject]@{
    Status = 'Completed'
    GeneratorVersion = '1.0.1'
    ScenarioCount = $Index.Count
    OutputDirectory = $OutputDirectory
    IndexPath = $IndexPath
}
