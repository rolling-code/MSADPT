<#
.SYNOPSIS
Creates an offline comparison report for MSADPT effective-access evaluator v1.0.3.
.NOTES
Version: 1.0.2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EngagementDirectory,

    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$EngagementDirectory = [System.IO.Path]::GetFullPath($EngagementDirectory)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $EngagementDirectory 'reports\EffectiveAccess-v1.0.3'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$BaselinePath = Join-Path $EngagementDirectory 'analysis\DirectoryControlEffectiveAccess\directory-control-effective-access-evaluations.csv'
$CorrectedPath = Join-Path $EngagementDirectory 'analysis\DirectoryControlEffectiveAccess-v1.0.3\directory-control-effective-access-evaluations.csv'

foreach ($RequiredPath in @($BaselinePath, $CorrectedPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "RequiredEvidenceMissing: $RequiredPath"
    }
}

$Baseline = @(Import-Csv -LiteralPath $BaselinePath)
$Corrected = @(Import-Csv -LiteralPath $CorrectedPath)
$BaselineByCandidate = @{}
foreach ($Row in $Baseline) {
    $BaselineByCandidate[[string]$Row.CandidateId] = $Row
}

$Transitions = @(
    foreach ($Row in $Corrected) {
        $CandidateId = [string]$Row.CandidateId
        if (-not $BaselineByCandidate.ContainsKey($CandidateId)) {
            continue
        }

        $Previous = $BaselineByCandidate[$CandidateId]
        if ([string]$Previous.Disposition -ne [string]$Row.Disposition) {
            [pscustomobject][ordered]@{
                CandidateId = $CandidateId
                Trustee = $Row.Trustee
                TargetName = $Row.TargetName
                TargetObjectType = $Row.TargetObjectType
                Capability = $Row.Capability
                BaselineDisposition = $Previous.Disposition
                CorrectedDisposition = $Row.Disposition
                CorrectedReason = $Row.Reason
                ApplicableAceCount = $Row.ApplicableAceCount
                NonApplicableAceCount = $Row.NonApplicableAceCount
            }
        }
    }
)

$TransitionPath = Join-Path $OutputDirectory 'effective-access-v102-to-v103-transitions.csv'
$Transitions | Export-Csv -LiteralPath $TransitionPath -NoTypeInformation -Encoding UTF8

$DispositionCounts = @(
    $Corrected |
        Group-Object -Property Disposition |
        Sort-Object -Property Name |
        ForEach-Object {
            [pscustomobject]@{ Disposition = $_.Name; Count = $_.Count }
        }
)

$CapabilityCounts = @(
    $Corrected |
        Where-Object -Property Disposition -EQ 'EffectiveControlConfirmed' |
        Group-Object -Property Capability |
        Sort-Object -Property Count -Descending |
        ForEach-Object {
            [pscustomobject]@{ Capability = $_.Name; Count = $_.Count }
        }
)

$TopTrustees = @(
    $Corrected |
        Where-Object -Property Disposition -EQ 'EffectiveControlConfirmed' |
        Group-Object -Property Trustee |
        Sort-Object -Property Count -Descending |
        Select-Object -First 25 |
        ForEach-Object {
            [pscustomobject]@{ Trustee = $_.Name; Count = $_.Count }
        }
)

$ConfirmedCount = @(
    $Corrected | Where-Object -Property Disposition -EQ 'EffectiveControlConfirmed'
).Count

$Summary = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    ReportVersion = '1.0.2'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    BaselineCount = $Baseline.Count
    CorrectedCount = $Corrected.Count
    ConfirmedPermissionRelationshipCount = $ConfirmedCount
    TransitionCount = $Transitions.Count
    DispositionCounts = $DispositionCounts
    CapabilityCounts = $CapabilityCounts
    TopTrustees = $TopTrustees
    ImpactReproduced = $false
    VulnerabilityConfirmed = $false
    NetworkActivity = 'None'
    ActiveDirectoryQueries = 'None'
    RemoteChanges = 'None'
}

$SummaryPath = Join-Path $OutputDirectory 'effective-access-v103-transition-summary.json'
$Summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$null = Get-Content -LiteralPath $SummaryPath -Raw | ConvertFrom-Json -ErrorAction Stop

$DispositionRows = @(
    $DispositionCounts | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td></tr>' -f `
            [System.Net.WebUtility]::HtmlEncode([string]$_.Disposition),
            [int]$_.Count
    }
) -join [Environment]::NewLine

$CapabilityRows = @(
    $CapabilityCounts | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td></tr>' -f `
            [System.Net.WebUtility]::HtmlEncode([string]$_.Capability),
            [int]$_.Count
    }
) -join [Environment]::NewLine

$TrusteeRows = @(
    $TopTrustees | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td></tr>' -f `
            [System.Net.WebUtility]::HtmlEncode([string]$_.Trustee),
            [int]$_.Count
    }
) -join [Environment]::NewLine

$Html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MSADPT Directory Control Effective Access v1.0.3</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; color: #17202a; }
h1, h2 { color: #0b5cab; }
.grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.card { border: 1px solid #ccd6dd; border-radius: 9px; padding: 16px; margin: 12px 0; }
.number { font-size: 28px; font-weight: 700; }
.boundary { border-left: 5px solid #d68910; }
table { border-collapse: collapse; width: 100%; margin: 10px 0 24px 0; }
th, td { border: 1px solid #ccd6dd; padding: 7px; text-align: left; }
th { background: #eaf2f8; }
code { background: #f3f5f7; padding: 2px 4px; }
</style>
</head>
<body>
<h1>Directory Control Effective Access v1.0.3</h1>
<div class="grid">
<div class="card"><div class="number">$($Corrected.Count)</div>evaluations</div>
<div class="card"><div class="number">$ConfirmedCount</div>confirmed permission relationships</div>
<div class="card"><div class="number">$($Transitions.Count)</div>v1.0.2 classifications corrected</div>
</div>
<div class="card boundary"><strong>Interpretation boundary:</strong> These are confirmed directory permission relationships for collected tokens. Impact was not reproduced, and vulnerabilities are not automatically confirmed.</div>
<h2>Disposition</h2>
<table><thead><tr><th>Disposition</th><th>Count</th></tr></thead><tbody>$DispositionRows</tbody></table>
<h2>Confirmed capability families</h2>
<table><thead><tr><th>Capability</th><th>Count</th></tr></thead><tbody>$CapabilityRows</tbody></table>
<h2>Top trustees</h2>
<table><thead><tr><th>Trustee</th><th>Count</th></tr></thead><tbody>$TrusteeRows</tbody></table>
<h2>Evidence</h2>
<ul>
<li><code>effective-access-v102-to-v103-transitions.csv</code></li>
<li><code>effective-access-v103-transition-summary.json</code></li>
<li><code>analysis\DirectoryControlEffectiveAccess-v1.0.3</code></li>
</ul>
</body>
</html>
"@

$HtmlPath = Join-Path $OutputDirectory 'MSADPT-Directory-Control-Effective-Access-v1.0.3.html'
[System.IO.File]::WriteAllText($HtmlPath, $Html, (New-Object System.Text.UTF8Encoding($false)))

[pscustomobject][ordered]@{
    Status = 'Passed'
    ReportVersion = '1.0.2'
    EvaluationCount = $Corrected.Count
    ConfirmedPermissionRelationshipCount = $ConfirmedCount
    TransitionCount = $Transitions.Count
    OutputDirectory = $OutputDirectory
    HtmlReportPath = $HtmlPath
    NetworkActivity = 'None'
    ActiveDirectoryQueries = 'None'
    RemoteChanges = 'None'
}
