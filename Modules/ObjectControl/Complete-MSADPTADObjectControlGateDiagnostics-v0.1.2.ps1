<#
.SYNOPSIS
Completes interrupted MSADPT AD object-control gate diagnostics without repeating candidate evaluation.
.DESCRIPTION
Consumes the diagnostic, exclusion, final-queue, and waterfall evidence already written by gate diagnostics
v0.1.0. Reconstructs distributions, summary JSON, HTML report, and evidence manifest using explicit Object[]
materialization for PowerShell 7 and StrictMode compatibility.

This completion is local only. It performs no network operations, AD queries, or directory changes.
.NOTES
Version: 0.1.2
Package identity: MSADPT-AD-OBJECT-CONTROL-GATE-DIAGNOSTICS-COMPLETION
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DiagnosticsDirectory,

    [string]$StartingIdentity,
    [string]$StartingIdentityGroupsPath,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-AD-OBJECT-CONTROL-GATE-DIAGNOSTICS-COMPLETION'
$PackageVersion = '0.1.2'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-10}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}
function Require-File {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) { throw "RequiredFileEmpty [$Label]: $Path" }
}
function Read-JsonArray {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
}
function Read-JsonDocument {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=15)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}
function Normalize-Identity {
    param([object]$Value)
    $Text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return $Text.Trim().ToLowerInvariant()
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local completion only. Candidate gates will not be recalculated.' DarkGray

    if (-not (Test-Path -LiteralPath $DiagnosticsDirectory -PathType Container)) {
        throw "DiagnosticsDirectoryMissing: $DiagnosticsDirectory"
    }

    $DiagnosticsPath = Join-Path $DiagnosticsDirectory 'candidate-gate-diagnostics.json'
    $ExclusionsPath = Join-Path $DiagnosticsDirectory 'candidate-exclusions.json'
    $FinalPath = Join-Path $DiagnosticsDirectory 'final-attack-path-queue.json'
    $WaterfallPath = Join-Path $DiagnosticsDirectory 'gate-waterfall.json'

    $Diagnostics = [object[]]@(Read-JsonArray $DiagnosticsPath 'Candidate diagnostics')
    $Exclusions = [object[]]@(Read-JsonArray $ExclusionsPath 'Candidate exclusions')
    $FinalPaths = [object[]]@(Read-JsonArray $FinalPath 'Final attack-path queue')
    $GateWaterfall = [object[]]@(Read-JsonArray $WaterfallPath 'Gate waterfall')

    $DiagnosticCount = [int]@($Diagnostics).Count
    $ExclusionCount = [int]@($Exclusions).Count
    $FinalPathCount = [int]@($FinalPaths).Count
    $GateWaterfallCount = [int]@($GateWaterfall).Count

    Write-Step 'OK' "Loaded preserved outputs: diagnostics=$DiagnosticCount, exclusions=$ExclusionCount, final paths=$FinalPathCount, waterfall rows=$GateWaterfallCount." Green

    $ReachableTrustees = @{}
    if (-not [string]::IsNullOrWhiteSpace($StartingIdentity)) {
        $ReachableTrustees[(Normalize-Identity $StartingIdentity)] = 'ExactStartingIdentity'
    }
    if (-not [string]::IsNullOrWhiteSpace($StartingIdentityGroupsPath)) {
        Require-File $StartingIdentityGroupsPath 'Starting identity group evidence'
        $GroupEvidenceText = Get-Content -LiteralPath $StartingIdentityGroupsPath -Raw
        foreach ($Line in ($GroupEvidenceText -split "`r?`n")) {
            if ($Line -match '^\s*([^\s].*?\\[^\s].*?)\s{2,}') {
                $Identity = $Matches[1].Trim()
                $ReachableTrustees[(Normalize-Identity $Identity)] = 'TokenGroupEvidence'
            }
        }
    }

    $ReachableTrusteeCount = [int]$ReachableTrustees.Keys.Count
    $ReachabilityMode = 'Not evaluated'
    if ($ReachableTrusteeCount -gt 0) {
        $ReachabilityMode = 'Exact identity and token evidence'
    }

    $TrusteeDistribution = [object[]]@(
        $Diagnostics | Group-Object TrusteeClass | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{TrusteeClass=[string]$_.Name;Count=[int]$_.Count}
        }
    )
    $CapabilityDistribution = [object[]]@(
        $Diagnostics | Group-Object Capability | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{Capability=[string]$_.Name;Count=[int]$_.Count}
        }
    )
    $TargetDistribution = [object[]]@(
        $Diagnostics | Group-Object TargetClass | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{TargetClass=[string]$_.Name;Count=[int]$_.Count}
        }
    )
    $ExclusionDistribution = [object[]]@(
        $Exclusions | Group-Object Reason | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{Reason=[string]$_.Name;Count=[int]$_.Count}
        }
    )

    $SourceCorrelationDirectory = Split-Path -Parent $DiagnosticsDirectory
    $SourceSummaryPath = Join-Path $SourceCorrelationDirectory 'ad-object-control-correlation-summary.json'
    $SourceSummary = Read-JsonDocument $SourceSummaryPath 'Correlation summary'

    $PriorBehavioralCount = [int]$SourceSummary.Counts.BehavioralValidationCandidates

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion='1.0'
        PackageIdentity='MSADPT-AD-OBJECT-CONTROL-GATE-DIAGNOSTICS'
        PackageVersion='0.1.2'
        CompletionPackageIdentity=$PackageIdentity
        CompletionPackageVersion=$PackageVersion
        Status='Completed'
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Domain=[string]$SourceSummary.Domain
        CorrelationDirectory=$SourceCorrelationDirectory
        DiagnosticsDirectory=$DiagnosticsDirectory
        StartingPrincipal=[pscustomobject][ordered]@{
            Identity=$StartingIdentity
            GroupEvidencePath=$StartingIdentityGroupsPath
            ReachableTrusteeCount=$ReachableTrusteeCount
            ReachabilityMode=$ReachabilityMode
        }
        Counts=[pscustomobject][ordered]@{
            DeduplicatedCandidates=$DiagnosticCount
            PriorBehavioralCandidates=$PriorBehavioralCount
            DiagnosticRows=$DiagnosticCount
            ExclusionRows=$ExclusionCount
            FinalPathsReturned=$FinalPathCount
        }
        GateWaterfall=[object[]]$GateWaterfall
        TrusteeDistribution=$TrusteeDistribution
        CapabilityDistribution=$CapabilityDistribution
        TargetDistribution=$TargetDistribution
        ExclusionDistribution=$ExclusionDistribution
        InterpretationBoundary=@(
            'Reachability is exact-match only using the supplied identity and token-group evidence.',
            'Nested group expansion and graph reachability were not performed.',
            'A final queue entry is not a vulnerability finding.',
            'Effective access, deny precedence, protected-object behavior, and reversible impact remain to be validated.'
        )
        Safety=[pscustomobject]@{
            NetworkActivity='None during completion'
            DirectoryQueries='None during completion'
            DirectoryChanges='None'
            OllamaActivity='None'
        }
    }

    $SummaryPath = Join-Path $DiagnosticsDirectory 'ad-object-control-gate-diagnostics-summary.json'
    Write-JsonDocument $Summary $SummaryPath

    $WaterfallHtml = ($GateWaterfall | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
        (Convert-HtmlText $_.Gate),(Convert-HtmlText $_.InputCount),
        (Convert-HtmlText $_.PassedCount),(Convert-HtmlText $_.RemovedCount)
    }) -join "`n"
    $PathHtml = ($FinalPaths | Select-Object -First 100 | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f
        (Convert-HtmlText $_.Priority),(Convert-HtmlText $_.Trustee),
        (Convert-HtmlText $_.Capability),(Convert-HtmlText $_.TargetName),
        (Convert-HtmlText $_.NextValidator),(Convert-HtmlText $_.SafetyState)
    }) -join "`n"

    $ReportPath = Join-Path $DiagnosticsDirectory 'MSADPT-AD-Object-Control-Gate-Diagnostics.html'
    $Html = @"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT AD Object-Control Gate Diagnostics</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body>
<h1>MSADPT AD Object-Control Gate Diagnostics</h1><div class="card"><b>Domain:</b> $(Convert-HtmlText $Summary.Domain)<br><b>Deduplicated candidates:</b> $DiagnosticCount<br><b>Prior behavioral queue:</b> $PriorBehavioralCount<br><b>Final paths:</b> $FinalPathCount<br><b>Reachable trustee evidence:</b> $ReachableTrusteeCount<br><b>Reachability mode:</b> $(Convert-HtmlText $ReachabilityMode)<br><b>Network activity:</b> None</div>
<h2>Gate Waterfall</h2><table><tr><th>Gate</th><th>Input</th><th>Passed</th><th>Removed</th></tr>$WaterfallHtml</table>
<h2>Final Attack-Path Queue</h2><table><tr><th>Priority</th><th>Trustee</th><th>Capability</th><th>Target</th><th>Validator</th><th>Safety State</th></tr>$PathHtml</table>
<h2>Evidence</h2><ul><li><a href="gate-waterfall.csv">Gate waterfall</a></li><li><a href="candidate-gate-diagnostics.csv">Candidate diagnostics</a></li><li><a href="candidate-exclusions.csv">Exclusions</a></li><li><a href="final-attack-path-queue.csv">Final queue</a></li><li><a href="ad-object-control-gate-diagnostics-summary.json">Structured summary</a></li><li><a href="../MSADPT-AD-Object-Control-Correlation.html">Correlation report</a></li></ul>
<p class="note">Final queue entries are validation leads, not vulnerabilities. Real reversible impact must be reproduced.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files = @(Get-ChildItem -LiteralPath $DiagnosticsDirectory -File | Where-Object { $_.Name -ne 'evidence-manifest.json' } | Sort-Object Name)
    $ManifestRows = [object[]]@(
        foreach ($File in $Files) {
            [pscustomobject]@{
                Name=$File.Name
                Size=[int64]$File.Length
                SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
            }
        }
    )
    $ManifestPath = Join-Path $DiagnosticsDirectory 'evidence-manifest.json'
    Write-JsonDocument ([pscustomobject]@{
        SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows
    }) $ManifestPath

    Write-Step 'DONE' "Gate diagnostics completed locally: diagnostics=$DiagnosticCount, exclusions=$ExclusionCount, final paths=$FinalPathCount." Green
    [pscustomobject][ordered]@{
        Status='Passed'
        PackageIdentity=$PackageIdentity
        PackageVersion=$PackageVersion
        Domain=$Summary.Domain
        DeduplicatedCandidateCount=$DiagnosticCount
        PriorBehavioralCandidateCount=$PriorBehavioralCount
        ExclusionRecordCount=$ExclusionCount
        FinalPathCount=$FinalPathCount
        ReachableTrusteeCount=$ReachableTrusteeCount
        ReachabilityMode=$ReachabilityMode
        DiagnosticsDirectory=$DiagnosticsDirectory
        HtmlReportPath=$ReportPath
        SummaryPath=$SummaryPath
        ManifestPath=$ManifestPath
        NetworkActivity='None'
        DirectoryQueries='None'
        DirectoryChanges='None'
        OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
