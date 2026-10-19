<#
.SYNOPSIS
Analyzes MSADPT Active Directory replication and topology evidence offline with explicit controller and naming-context coverage.

.DESCRIPTION
Consumes structured evidence produced by Collect-MSADPTADReplicationTopology-v1.1.1.ps1.
Produces coverage-aware CSV, JSON, and HTML outputs without performing network activity or Active Directory queries.

.NOTES
Version: 1.1.2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter()]
    [ValidateRange(1, 168)]
    [int]$IntraSiteDelayHours = 1,

    [Parameter()]
    [ValidateRange(1, 336)]
    [int]$InterSiteDelayHours = 6
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.1.2'

function Resolve-MSADPTLocalPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath(
        (Join-Path (Get-Location).Path $Path)
    )
}

function Read-MSADPTJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "EvidenceMissing: $Path"
    }

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function ConvertTo-MSADPTHtmlText {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

$EvidenceDirectory = Resolve-MSADPTLocalPath -Path $EvidenceDirectory
$OutputDirectory = Resolve-MSADPTLocalPath -Path $OutputDirectory
$RawDirectory = Join-Path $EvidenceDirectory 'Raw'

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

Write-Host '[ANALYZE     ] Offline coverage-aware replication analysis' -ForegroundColor Cyan
Write-Host ("               Evidence : {0}" -f $EvidenceDirectory) -ForegroundColor Gray
Write-Host ("               Output   : {0}" -f $OutputDirectory) -ForegroundColor Gray
Write-Host '               Network  : None' -ForegroundColor Gray
Write-Host '               AD query : None' -ForegroundColor Gray

$Forest = Read-MSADPTJson -Path (Join-Path $RawDirectory 'forest.json')
$DomainControllers = @(Read-MSADPTJson -Path (Join-Path $RawDirectory 'domain-controllers.json'))
$Sites = @(Read-MSADPTJson -Path (Join-Path $RawDirectory 'sites.json'))
$Subnets = @(Read-MSADPTJson -Path (Join-Path $RawDirectory 'subnets.json'))
$SiteLinks = @(Read-MSADPTJson -Path (Join-Path $RawDirectory 'site-links.json'))
$PartnerMetadata = @(Read-MSADPTJson -Path (Join-Path $RawDirectory 'partner-metadata.json'))
$Reachability = @(Read-MSADPTJson -Path (Join-Path $RawDirectory 'reachability.json'))
$OperationalErrors = @(Read-MSADPTJson -Path (Join-Path $RawDirectory 'operational-errors.json'))

$SiteByDomainController = @{}
foreach ($DomainController in $DomainControllers) {
    $SiteByDomainController[[string]$DomainController.HostName] = [string]$DomainController.Site
}

$GeneratedUtc = (Get-Date).ToUniversalTime()

$Relationships = @(
    foreach ($PartnerRecord in $PartnerMetadata) {
        $DestinationServer = [string]$PartnerRecord.Server
        $SourcePartner = [string]$PartnerRecord.Partner
        $SourceServer = $null

        foreach ($DomainControllerName in $SiteByDomainController.Keys) {
            $ShortName = $DomainControllerName.Split('.')[0]

            if ($SourcePartner -match [regex]::Escape($ShortName)) {
                $SourceServer = $DomainControllerName
                break
            }
        }

        $DestinationSite = if ($SiteByDomainController.ContainsKey($DestinationServer)) {
            $SiteByDomainController[$DestinationServer]
        }
        else {
            'Unknown'
        }

        $SourceSite = if (
            -not [string]::IsNullOrWhiteSpace([string]$SourceServer) -and
            $SiteByDomainController.ContainsKey([string]$SourceServer)
        ) {
            $SiteByDomainController[[string]$SourceServer]
        }
        else {
            'Unknown'
        }

        $Scope = if (
            $SourceSite -ne 'Unknown' -and
            $DestinationSite -ne 'Unknown' -and
            $SourceSite -eq $DestinationSite
        ) {
            'IntraSite'
        }
        else {
            'InterSiteOrUnknown'
        }

        $ThresholdHours = if ($Scope -eq 'IntraSite') {
            $IntraSiteDelayHours
        }
        else {
            $InterSiteDelayHours
        }

        $LastSuccess = $null
        if ($PartnerRecord.LastReplicationSuccess) {
            $LastSuccess = [datetime]$PartnerRecord.LastReplicationSuccess
        }

        $AgeHours = if ($null -ne $LastSuccess) {
            [math]::Round(
                ($GeneratedUtc - $LastSuccess.ToUniversalTime()).TotalHours,
                2
            )
        }
        else {
            $null
        }

        $LastResult = [int]$PartnerRecord.LastReplicationResult
        $ConsecutiveFailures = [int]$PartnerRecord.ConsecutiveReplicationFailures

        $Disposition = if (
            $LastResult -ne 0 -or
            $ConsecutiveFailures -gt 0
        ) {
            'Failed'
        }
        elseif ($null -eq $AgeHours) {
            'Inconclusive'
        }
        elseif ($AgeHours -gt $ThresholdHours) {
            'Delayed'
        }
        else {
            'Healthy'
        }

        [pscustomobject][ordered]@{
            DestinationServer = $DestinationServer
            SourceServer = $SourceServer
            SourcePartner = $SourcePartner
            DestinationSite = $DestinationSite
            SourceSite = $SourceSite
            Scope = $Scope
            Partition = [string]$PartnerRecord.Partition
            LastReplicationSuccess = $PartnerRecord.LastReplicationSuccess
            AgeHours = $AgeHours
            ThresholdHours = $ThresholdHours
            LastReplicationResult = $LastResult
            ConsecutiveFailures = $ConsecutiveFailures
            Disposition = $Disposition
        }
    }
)

$ControllerCoverage = @(
    foreach ($DomainController in $DomainControllers) {
        $ControllerName = [string]$DomainController.HostName
        $ReachabilityRecord = @(
            $Reachability |
                Where-Object { $_.Target -eq $ControllerName } |
                Select-Object -First 1
        )

        $StructuredEvidenceCollected = @(
            $Relationships |
                Where-Object { $_.DestinationServer -eq $ControllerName }
        ).Count -gt 0

        $AdwsReachable = if ($ReachabilityRecord.Count -gt 0) {
            [bool]$ReachabilityRecord[0].Tcp9389Succeeded
        }
        else {
            $false
        }

        $CoverageDisposition = if ($StructuredEvidenceCollected) {
            'Assessed'
        }
        elseif (
            $ReachabilityRecord.Count -gt 0 -and
            -not [bool]$ReachabilityRecord[0].Tcp9389Succeeded
        ) {
            'Unavailable'
        }
        else {
            'Inconclusive'
        }

        [pscustomobject][ordered]@{
            DomainController = $ControllerName
            Site = [string]$DomainController.Site
            AdwsReachable = $AdwsReachable
            StructuredEvidenceCollected = $StructuredEvidenceCollected
            Disposition = $CoverageDisposition
        }
    }
)

$ExpectedNamingContexts = @($Forest.ExpectedNamingContexts)
$ObservedNamingContexts = @(
    $Relationships |
        ForEach-Object { $_.Partition } |
        Sort-Object -Unique
)

$NamingContextCoverage = @(
    foreach ($NamingContext in $ExpectedNamingContexts) {
        [pscustomobject][ordered]@{
            NamingContext = [string]$NamingContext
            Observed = $ObservedNamingContexts -contains [string]$NamingContext
        }
    }
)

$Findings = [System.Collections.Generic.List[object]]::new()

foreach ($Relationship in @($Relationships | Where-Object { $_.Disposition -ne 'Healthy' })) {
    $Findings.Add([pscustomobject][ordered]@{
        Disposition = $Relationship.Disposition
        Area = 'Replication'
        Object = $Relationship.DestinationServer
        Evidence = ('Partner={0}; Partition={1}; Result={2}; ConsecutiveFailures={3}; AgeHours={4}; ThresholdHours={5}' -f $Relationship.SourcePartner, $Relationship.Partition, $Relationship.LastReplicationResult, $Relationship.ConsecutiveFailures, $Relationship.AgeHours, $Relationship.ThresholdHours)
        RecommendedValidation = 'Confirm current replication state before remediation.'
    })
}

foreach ($CoverageRecord in @($ControllerCoverage | Where-Object { $_.Disposition -ne 'Assessed' })) {
    $Findings.Add([pscustomobject][ordered]@{
        Disposition = 'Inconclusive'
        Area = 'Coverage'
        Object = $CoverageRecord.DomainController
        Evidence = 'No structured ADWS partner metadata was collected for this controller.'
        RecommendedValidation = 'Use an approved alternate collection path or management host.'
    })
}

foreach ($NamingContextRecord in @($NamingContextCoverage | Where-Object { -not $_.Observed })) {
    $Findings.Add([pscustomobject][ordered]@{
        Disposition = 'Inconclusive'
        Area = 'NamingContextCoverage'
        Object = $NamingContextRecord.NamingContext
        Evidence = 'Expected naming context was not present in structured partner metadata.'
        RecommendedValidation = 'Collect or corroborate replication metadata for this naming context.'
    })
}

$Relationships |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'replication-relationships.csv') -NoTypeInformation -Encoding UTF8
$ControllerCoverage |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'controller-coverage.csv') -NoTypeInformation -Encoding UTF8
$NamingContextCoverage |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'naming-context-coverage.csv') -NoTypeInformation -Encoding UTF8
$Findings |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'replication-topology-findings.csv') -NoTypeInformation -Encoding UTF8

$UnassessedControllerCount = @(
    $ControllerCoverage |
        Where-Object { $_.Disposition -ne 'Assessed' }
).Count
$MissingNamingContextCount = @(
    $NamingContextCoverage |
        Where-Object { -not $_.Observed }
).Count
$FailedRelationshipCount = @(
    $Relationships |
        Where-Object { $_.Disposition -eq 'Failed' }
).Count

$OverallDisposition = if (
    $UnassessedControllerCount -gt 0 -or
    $MissingNamingContextCount -gt 0
) {
    'Inconclusive'
}
elseif ($FailedRelationshipCount -gt 0) {
    'Failed'
}
else {
    'ObservedRelationshipsHealthy'
}

$Summary = [pscustomobject][ordered]@{
    SchemaVersion = '1.1'
    AnalyzerVersion = $Version
    GeneratedUtc = $GeneratedUtc.ToString('o')
    Forest = $Forest.Name
    DiscoveredControllerCount = $DomainControllers.Count
    AssessedControllerCount = @($ControllerCoverage | Where-Object { $_.Disposition -eq 'Assessed' }).Count
    UnavailableControllerCount = @($ControllerCoverage | Where-Object { $_.Disposition -eq 'Unavailable' }).Count
    InconclusiveControllerCount = @($ControllerCoverage | Where-Object { $_.Disposition -eq 'Inconclusive' }).Count
    RelationshipCount = $Relationships.Count
    HealthyCount = @($Relationships | Where-Object { $_.Disposition -eq 'Healthy' }).Count
    DelayedCount = @($Relationships | Where-Object { $_.Disposition -eq 'Delayed' }).Count
    FailedCount = $FailedRelationshipCount
    InconclusiveRelationshipCount = @($Relationships | Where-Object { $_.Disposition -eq 'Inconclusive' }).Count
    ExpectedNamingContextCount = $ExpectedNamingContexts.Count
    ObservedNamingContextCount = $ObservedNamingContexts.Count
    MissingNamingContextCount = $MissingNamingContextCount
    SiteCount = $Sites.Count
    SubnetCount = $Subnets.Count
    SiteLinkCount = $SiteLinks.Count
    OperationalErrorCount = $OperationalErrors.Count
    OverallDisposition = $OverallDisposition
    ImpactReproduced = $false
    VulnerabilityConfirmed = $false
}

$Summary |
    ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'replication-topology-summary.json') -Encoding UTF8

$CoverageRows = @(
    foreach ($CoverageRecord in $ControllerCoverage) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-MSADPTHtmlText $CoverageRecord.DomainController), (ConvertTo-MSADPTHtmlText $CoverageRecord.Site), (ConvertTo-MSADPTHtmlText $CoverageRecord.AdwsReachable), (ConvertTo-MSADPTHtmlText $CoverageRecord.StructuredEvidenceCollected), (ConvertTo-MSADPTHtmlText $CoverageRecord.Disposition)
    }
) -join [Environment]::NewLine

$RelationshipRows = @(
    foreach ($Relationship in $Relationships) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-MSADPTHtmlText $Relationship.DestinationServer), (ConvertTo-MSADPTHtmlText $Relationship.SourceServer), (ConvertTo-MSADPTHtmlText $Relationship.Partition), (ConvertTo-MSADPTHtmlText $Relationship.Disposition), (ConvertTo-MSADPTHtmlText $Relationship.AgeHours)
    }
) -join [Environment]::NewLine

if ([string]::IsNullOrWhiteSpace($CoverageRows)) {
    $CoverageRows = '<tr><td colspan="5">No controller coverage evidence was available.</td></tr>'
}
if ([string]::IsNullOrWhiteSpace($RelationshipRows)) {
    $RelationshipRows = '<tr><td colspan="5">No structured replication relationships were available.</td></tr>'
}

$Html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MSADPT AD Replication and Topology</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:28px;color:#17202a}h1,h2{color:#0b5cab}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.card{border:1px solid #ccd6dd;border-radius:8px;padding:14px}.n{font-size:26px;font-weight:700}table{border-collapse:collapse;width:100%;margin-bottom:18px}th,td{border:1px solid #ccd6dd;padding:6px;text-align:left}th{background:#eaf2f8}.boundary{border-left:5px solid #d68910;padding:12px;background:#fff8e7}@media(max-width:800px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>AD Replication and Topology</h1>
<p>Forest: $(ConvertTo-MSADPTHtmlText $Forest.Name)</p>
<div class="grid">
<div class="card"><div class="n">$($Summary.DiscoveredControllerCount)</div>discovered controllers</div>
<div class="card"><div class="n">$($Summary.AssessedControllerCount)</div>assessed controllers</div>
<div class="card"><div class="n">$($Summary.UnavailableControllerCount)</div>unavailable controllers</div>
<div class="card"><div class="n">$($Summary.ObservedNamingContextCount)/$($Summary.ExpectedNamingContextCount)</div>naming contexts observed</div>
</div>
<p class="boundary"><strong>Overall disposition: $($Summary.OverallDisposition).</strong> Healthy rows apply only to observed relationships. Unavailable controllers and missing naming contexts remain inconclusive. Impact was not reproduced and vulnerabilities are not automatically confirmed.</p>
<h2>Controller coverage</h2>
<table><thead><tr><th>Controller</th><th>Site</th><th>ADWS reachable</th><th>Evidence collected</th><th>Disposition</th></tr></thead><tbody>$CoverageRows</tbody></table>
<h2>Observed relationships</h2>
<table><thead><tr><th>Destination</th><th>Source</th><th>Naming context</th><th>Disposition</th><th>Age hours</th></tr></thead><tbody>$RelationshipRows</tbody></table>
</body>
</html>
"@

$HtmlPath = Join-Path $OutputDirectory 'MSADPT-AD-Replication-Topology.html'
[System.IO.File]::WriteAllText(
    $HtmlPath,
    $Html,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host ("[PASS        ] Coverage-aware analysis complete: {0}" -f $OutputDirectory) -ForegroundColor Green

[pscustomobject][ordered]@{
    Status = 'Completed'
    Version = $Version
    OverallDisposition = $Summary.OverallDisposition
    OutputDirectory = $OutputDirectory
    DiscoveredControllerCount = $Summary.DiscoveredControllerCount
    AssessedControllerCount = $Summary.AssessedControllerCount
    UnavailableControllerCount = $Summary.UnavailableControllerCount
    RelationshipCount = $Summary.RelationshipCount
    FindingCount = $Findings.Count
    SummaryPath = Join-Path $OutputDirectory 'replication-topology-summary.json'
    HtmlReportPath = $HtmlPath
}
