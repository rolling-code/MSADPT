<#
.SYNOPSIS
Validates ADCS CA-runtime evidence offline.
.NOTES
Version: 1.0.1
No network, Active Directory, certification authority, TCP, certutil, or registry operation is performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidencePath,
    [Parameter(Mandatory = $true)][string]$SummaryCsvPath,
    [Parameter()][string]$ServiceConnectionPointPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Add-ValidationIssue {
    param(
        [System.Collections.Generic.List[object]]$IssueList,
        [string]$CA,
        [string]$Area,
        [string]$Issue,
        [string]$Detail
    )
    $IssueList.Add([pscustomobject][ordered]@{
        CA = $CA
        Area = $Area
        Issue = $Issue
        Detail = $Detail
    })
}

foreach ($Path in @($EvidencePath, $SummaryCsvPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required evidence not found: $Path"
    }
}

$Issues = New-Object 'System.Collections.Generic.List[object]'

try {
    $CaEvidence = @(Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json -ErrorAction Stop)
}
catch {
    throw "JsonParseFailure: $($_.Exception.Message)"
}

$Summary = @(Import-Csv -LiteralPath $SummaryCsvPath)
$AllowedQueryStatus = @('Completed', 'Failed', 'TimedOut', 'FailedToStart')
$RequiredQueryNames = @('Ping', 'EditFlags', 'InterfaceFlags', 'RequestDisposition', 'RoleSeparationEnabled', 'EnrollmentAgentRights', 'OfficerRights')

if ($CaEvidence.Count -ne $Summary.Count) {
    Add-ValidationIssue $Issues '*' 'Summary' 'RowCountMismatch' "JSON=$($CaEvidence.Count);CSV=$($Summary.Count)"
}

$DuplicateConfigurations = @($CaEvidence | Group-Object CaConfiguration | Where-Object Count -gt 1)
foreach ($Duplicate in $DuplicateConfigurations) {
    Add-ValidationIssue $Issues $Duplicate.Name 'Identity' 'DuplicateCaConfiguration' ([string]$Duplicate.Count)
}

foreach ($Ca in $CaEvidence) {
    foreach ($Property in @('Name', 'DnsHostName', 'CaConfiguration', 'DistinguishedName', 'PublishedTemplates', 'DirectorySecurity', 'PortEvidence', 'CertutilQueries')) {
        if ($null -eq $Ca.PSObject.Properties[$Property]) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'Schema' 'MissingProperty' $Property
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$Ca.CaConfiguration)) {
        Add-ValidationIssue $Issues ([string]$Ca.Name) 'Identity' 'EmptyCaConfiguration' ''
    }

    $Ports = @($Ca.PortEvidence)
    foreach ($PortEvidence in $Ports) {
        if ([int]$PortEvidence.Port -notin @(80, 135, 443, 445, 5985, 5986)) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'PortEvidence' 'UnexpectedPort' ([string]$PortEvidence.Port)
        }
        if ([bool]$PortEvidence.Reachable -and -not [string]::IsNullOrWhiteSpace([string]$PortEvidence.Error)) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'PortEvidence' 'ReachableWithError' ([string]$PortEvidence.Error)
        }
    }

    $Queries = @($Ca.CertutilQueries)
    $QueryNames = @($Queries | ForEach-Object { [string]$_.Name })
    foreach ($RequiredName in $RequiredQueryNames) {
        if ($QueryNames -notcontains $RequiredName) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'CertutilQueries' 'MissingQuery' $RequiredName
        }
    }

    foreach ($Query in $Queries) {
        if ([string]$Query.Result.Status -notin $AllowedQueryStatus) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'CertutilQueries' 'UnexpectedStatus' ([string]$Query.Result.Status)
        }
        if ([string]$Query.Result.CaConfiguration -ne [string]$Ca.CaConfiguration) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'CertutilQueries' 'ConfigurationMismatch' ([string]$Query.Name)
        }
        $Arguments = @($Query.Result.Arguments | ForEach-Object { [string]$_ })
        if ($Arguments.Count -lt 3 -or $Arguments[0] -ne '-config' -or $Arguments[1] -ne [string]$Ca.CaConfiguration) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'CertutilQueries' 'UnsafeOrMissingExplicitConfiguration' ([string]$Query.Name)
        }
    }

    $SummaryRow = @($Summary | Where-Object { [string]$_.CaConfiguration -eq [string]$Ca.CaConfiguration })
    if ($SummaryRow.Count -ne 1) {
        Add-ValidationIssue $Issues ([string]$Ca.Name) 'Summary' 'MissingOrDuplicateSummaryRow' ([string]$SummaryRow.Count)
    }
    else {
        $Completed = @($Queries | Where-Object { $_.Result.Status -eq 'Completed' }).Count
        $Failed = $Queries.Count - $Completed
        $Reachable = @($Ports | Where-Object Reachable).Count
        if ([int]$SummaryRow[0].CompletedCertutilQueryCount -ne $Completed) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'Summary' 'CompletedQueryCountMismatch' ([string]$Completed)
        }
        if ([int]$SummaryRow[0].FailedCertutilQueryCount -ne $Failed) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'Summary' 'FailedQueryCountMismatch' ([string]$Failed)
        }
        if ([int]$SummaryRow[0].ReachablePortCount -ne $Reachable) {
            Add-ValidationIssue $Issues ([string]$Ca.Name) 'Summary' 'ReachablePortCountMismatch' ([string]$Reachable)
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ServiceConnectionPointPath)) {
    if (-not (Test-Path -LiteralPath $ServiceConnectionPointPath -PathType Leaf)) {
        throw "Service connection point evidence not found: $ServiceConnectionPointPath"
    }

    try {
        $ScpRaw = Get-Content -LiteralPath $ServiceConnectionPointPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($ScpRaw)) {
            throw 'The service-connection-point evidence is empty.'
        }
        $ScpEvidence = @($ScpRaw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "ServiceConnectionPointJsonParseFailure: $($_.Exception.Message)"
    }

    foreach ($Scp in $ScpEvidence) {
        foreach ($Property in @('Name', 'DistinguishedName', 'ServiceBindingInformation', 'Keywords')) {
            if ($null -eq $Scp.PSObject.Properties[$Property]) {
                Add-ValidationIssue $Issues '*' 'ServiceConnectionPoints' 'MissingServiceConnectionPointProperty' $Property
            }
        }
    }
}

try {
    $RoundTrip = @($CaEvidence | ConvertTo-Json -Depth 12 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
}
catch {
    throw "SerializationRoundTripFailure: $($_.Exception.Message)"
}

if ($RoundTrip.Count -ne $CaEvidence.Count) {
    Add-ValidationIssue $Issues '*' 'Serialization' 'RoundTripCountMismatch' "Before=$($CaEvidence.Count);After=$($RoundTrip.Count)"
}

if ($Issues.Count -gt 0) {
    $Issues | Format-Table -AutoSize
    $IssueCodes = @($Issues | Select-Object -ExpandProperty Issue -Unique)
    throw "ValidationIssues: $($IssueCodes -join ', '); Count=$($Issues.Count)"
}

[pscustomobject]@{
    Status = 'Passed'
    ValidatorVersion = '1.0.1'
    CaCount = $CaEvidence.Count
    SummaryRowCount = $Summary.Count
    ServiceConnectionPointCount = if ($null -ne $ScpEvidence) { @($ScpEvidence).Count } else { $null }
    IssueCount = 0
    EvidencePath = $EvidencePath
    SummaryCsvPath = $SummaryCsvPath
    ServiceConnectionPointPath = $ServiceConnectionPointPath
}
