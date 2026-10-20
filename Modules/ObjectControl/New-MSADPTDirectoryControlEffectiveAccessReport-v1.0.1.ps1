<#
.SYNOPSIS
Creates offline baseline-to-corrected Directory Control effective-access transition evidence and an HTML review report.

.DESCRIPTION
Compares the baseline Directory Control effective-access evaluation CSV with the corrected v1.0.3 evaluation CSV.
Exports disposition transitions, a structured JSON summary, and a self-contained offline HTML review report.

This script performs no network activity, no Active Directory queries, and no remote changes.

.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EngagementDirectory,

    [Parameter()]
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-MSADPTStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'PASS', 'WARN', 'FAIL')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Color = switch ($Level) {
        'INFO' { 'Cyan' }
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }

    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $Color
}

function ConvertTo-MSADPTHtmlEncodedText {
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

try {
    $ResolvedEngagementDirectory = (Resolve-Path -LiteralPath $EngagementDirectory -ErrorAction Stop).Path

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $ResolvedEngagementDirectory 'reports\EffectiveAccess-v1.0.3'
    }

    $BaselinePath = Join-Path $ResolvedEngagementDirectory 'analysis\DirectoryControlEffectiveAccess\directory-control-effective-access-evaluations.csv'
    $CorrectedPath = Join-Path $ResolvedEngagementDirectory 'analysis\DirectoryControlEffectiveAccess-v1.0.3\directory-control-effective-access-evaluations.csv'

    Write-MSADPTStatus -Level INFO -Message 'Preparing offline Directory Control effective-access report generation.'
    Write-Host ("       Engagement directory : {0}" -f $ResolvedEngagementDirectory) -ForegroundColor Gray
    Write-Host ("       Baseline evidence     : {0}" -f $BaselinePath) -ForegroundColor Gray
    Write-Host ("       Corrected evidence    : {0}" -f $CorrectedPath) -ForegroundColor Gray
    Write-Host ("       Output directory      : {0}" -f $OutputDirectory) -ForegroundColor Gray
    Write-Host '       Network activity      : None' -ForegroundColor Gray
    Write-Host '       Active Directory      : No queries or changes' -ForegroundColor Gray

    foreach ($RequiredPath in @($BaselinePath, $CorrectedPath)) {
        if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
            throw "Required effective-access evidence file was not found: $RequiredPath"
        }
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $BaselineRows = @(Import-Csv -LiteralPath $BaselinePath)
    $CorrectedRows = @(Import-Csv -LiteralPath $CorrectedPath)

    $BaselineMap = @{}
    foreach ($Row in $BaselineRows) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Row.CandidateId)) {
            $BaselineMap[[string]$Row.CandidateId] = $Row
        }
    }

    $Transitions = @(
        foreach ($Row in $CorrectedRows) {
            $CandidateId = [string]$Row.CandidateId

            if (
                -not [string]::IsNullOrWhiteSpace($CandidateId) -and
                $BaselineMap.ContainsKey($CandidateId) -and
                [string]$BaselineMap[$CandidateId].Disposition -ne [string]$Row.Disposition
            ) {
                [pscustomobject][ordered]@{
                    CandidateId           = $CandidateId
                    Trustee               = $Row.Trustee
                    TargetName            = $Row.TargetName
                    TargetObjectType      = $Row.TargetObjectType
                    Capability            = $Row.Capability
                    BaselineDisposition   = $BaselineMap[$CandidateId].Disposition
                    CorrectedDisposition  = $Row.Disposition
                    CorrectedReason       = $Row.Reason
                    ApplicableAceCount    = $Row.ApplicableAceCount
                    NonApplicableAceCount = $Row.NonApplicableAceCount
                }
            }
        }
    )

    $TransitionCsvPath = Join-Path $OutputDirectory 'effective-access-v102-to-v103-transitions.csv'
    $SummaryJsonPath = Join-Path $OutputDirectory 'effective-access-v103-transition-summary.json'
    $HtmlReportPath = Join-Path $OutputDirectory 'MSADPT-Directory-Control-Effective-Access-v1.0.3.html'

    $Transitions |
        Export-Csv -LiteralPath $TransitionCsvPath -NoTypeInformation -Encoding utf8

    $DispositionCounts = @(
        $CorrectedRows |
            Group-Object -Property Disposition |
            Sort-Object -Property Name |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Disposition = $_.Name
                    Count       = $_.Count
                }
            }
    )

    $CapabilityCounts = @(
        $CorrectedRows |
            Where-Object { $_.Disposition -eq 'EffectiveControlConfirmed' } |
            Group-Object -Property Capability |
            Sort-Object -Property Count -Descending |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Capability = $_.Name
                    Count      = $_.Count
                }
            }
    )

    $TopTrustees = @(
        $CorrectedRows |
            Where-Object { $_.Disposition -eq 'EffectiveControlConfirmed' } |
            Group-Object -Property Trustee |
            Sort-Object -Property Count -Descending |
            Select-Object -First 25 |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Trustee = $_.Name
                    Count   = $_.Count
                }
            }
    )

    $ConfirmedRelationshipCount = @(
        $CorrectedRows |
            Where-Object { $_.Disposition -eq 'EffectiveControlConfirmed' }
    ).Count

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion          = '1.0'
        GeneratorVersion       = '1.0.1'
        GeneratedUtc           = (Get-Date).ToUniversalTime().ToString('o')
        BaselineCount          = $BaselineRows.Count
        CorrectedCount         = $CorrectedRows.Count
        TransitionCount        = $Transitions.Count
        DispositionCounts      = $DispositionCounts
        CapabilityCounts       = $CapabilityCounts
        TopTrustees            = $TopTrustees
        ImpactReproduced       = $false
        VulnerabilityConfirmed = $false
        NetworkActivity        = 'None'
        ActiveDirectoryQueries = 'None'
        RemoteChanges          = 'None'
    }

    $Summary |
        ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $SummaryJsonPath -Encoding utf8

    $DispositionRows = @(
        foreach ($Item in $DispositionCounts) {
            '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-MSADPTHtmlEncodedText -Value $Item.Disposition), (ConvertTo-MSADPTHtmlEncodedText -Value $Item.Count)
        }
    ) -join [Environment]::NewLine

    $CapabilityRows = @(
        foreach ($Item in $CapabilityCounts) {
            '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-MSADPTHtmlEncodedText -Value $Item.Capability), (ConvertTo-MSADPTHtmlEncodedText -Value $Item.Count)
        }
    ) -join [Environment]::NewLine

    $TrusteeRows = @(
        foreach ($Item in $TopTrustees) {
            '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-MSADPTHtmlEncodedText -Value $Item.Trustee), (ConvertTo-MSADPTHtmlEncodedText -Value $Item.Count)
        }
    ) -join [Environment]::NewLine

    if ([string]::IsNullOrWhiteSpace($DispositionRows)) {
        $DispositionRows = '<tr><td colspan="2">No disposition data was available.</td></tr>'
    }

    if ([string]::IsNullOrWhiteSpace($CapabilityRows)) {
        $CapabilityRows = '<tr><td colspan="2">No confirmed capability relationships were detected.</td></tr>'
    }

    if ([string]::IsNullOrWhiteSpace($TrusteeRows)) {
        $TrusteeRows = '<tr><td colspan="2">No confirmed trustee relationships were detected.</td></tr>'
    }

    $Html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MSADPT Directory Control Effective Access v1.0.3</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; color: #17202a; background: #ffffff; }
h1, h2 { color: #0b5cab; }
.card { border: 1px solid #ccd6dd; border-radius: 9px; padding: 16px; margin: 12px 0; }
.grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.number { font-size: 28px; font-weight: 700; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ccd6dd; padding: 7px; text-align: left; vertical-align: top; }
th { background: #eaf2f8; }
.warning { border-left: 5px solid #d68910; }
.boundary { color: #5d6d7e; }
@media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<h1>Directory Control Effective Access v1.0.3</h1>
<p class="boundary">Offline report generator version 1.0.1. No network activity, Active Directory queries, or remote changes were performed.</p>
<div class="grid">
  <div class="card"><div class="number">$($CorrectedRows.Count)</div>evaluations</div>
  <div class="card"><div class="number">$ConfirmedRelationshipCount</div>confirmed permission relationships</div>
  <div class="card"><div class="number">$($Transitions.Count)</div>v1.0.2 classifications corrected</div>
</div>
<div class="card warning"><strong>Interpretation boundary:</strong> These are confirmed directory permission relationships for collected tokens. Impact was not reproduced, and vulnerabilities are not automatically confirmed.</div>
<h2>Disposition</h2>
<table><thead><tr><th>Disposition</th><th>Count</th></tr></thead><tbody>$DispositionRows</tbody></table>
<h2>Confirmed capability families</h2>
<table><thead><tr><th>Capability</th><th>Count</th></tr></thead><tbody>$CapabilityRows</tbody></table>
<h2>Top trustees</h2>
<table><thead><tr><th>Trustee</th><th>Count</th></tr></thead><tbody>$TrusteeRows</tbody></table>
<h2>Evidence</h2>
<ul>
  <li>effective-access-v102-to-v103-transitions.csv</li>
  <li>effective-access-v103-transition-summary.json</li>
  <li>analysis\DirectoryControlEffectiveAccess-v1.0.3</li>
</ul>
</body>
</html>
"@

    [System.IO.File]::WriteAllText(
        $HtmlReportPath,
        $Html,
        [System.Text.UTF8Encoding]::new($false)
    )

    Write-MSADPTStatus -Level PASS -Message 'Offline Directory Control effective-access report generation completed.'
    Write-Host ("       Transition CSV : {0}" -f $TransitionCsvPath) -ForegroundColor Gray
    Write-Host ("       Summary JSON   : {0}" -f $SummaryJsonPath) -ForegroundColor Gray
    Write-Host ("       HTML report   : {0}" -f $HtmlReportPath) -ForegroundColor Gray

    [pscustomobject][ordered]@{
        Status                 = 'Passed'
        ReportVersion          = '1.0.1'
        EvaluationCount        = $CorrectedRows.Count
        ConfirmedRelationCount = $ConfirmedRelationshipCount
        TransitionCount        = $Transitions.Count
        TransitionCsvPath      = $TransitionCsvPath
        SummaryJsonPath        = $SummaryJsonPath
        HtmlReportPath         = $HtmlReportPath
        OutputDirectory        = $OutputDirectory
        NetworkActivity        = 'None'
        ActiveDirectoryQueries = 'None'
        RemoteChanges          = 'None'
    }
}
catch {
    Write-MSADPTStatus -Level FAIL -Message $_.Exception.Message
    throw
}
