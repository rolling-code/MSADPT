<#
.SYNOPSIS
Builds one self-contained MSADPT HTML posture report from normalized module report sections.

.DESCRIPTION
Loads normalized report-section JSON files, validates each section, renders common module sections,
builds an at-a-glance dashboard, preserves module limitations and evidence links, and writes a
consolidated JSON index plus one offline HTML report. No Active Directory, network, Git, or external
service is contacted.

.NOTES
Version: 1.0.3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$SectionPath,

    [string]$OutputDirectory,

    [string]$ReportName = 'MSADPT-Unified-Report',

    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,

    [switch]$OpenReport,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.3'

function Write-Status {
    param(
        [ValidateSet('INFO','READ','VALIDATE','RENDER','PASS','WARN','REPORT')]
        [string]$State,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($NoColor) {
        Write-Host ('[{0,-8}] {1}' -f $State, $Message)
    }
    else {
        Write-Host ('[{0,-8}] {1}' -f $State, $Message) -ForegroundColor $Color
    }
}

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }

    return [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}

function Convert-HtmlText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-SectionRank {
    param([Parameter(Mandatory = $true)][string]$Disposition)

    switch ($Disposition) {
        'Confirmed' { return 1 }
        'Likely or probable' { return 2 }
        'Inconclusive' { return 3 }
        'Not detected' { return 4 }
        'Not applicable' { return 5 }
        default { return 6 }
    }
}

$RepositoryRoot = Resolve-FullPath -Path $RepositoryRoot
if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "Repository root not found: $RepositoryRoot"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepositoryRoot 'Output\UnifiedReport'
}
$OutputDirectory = Resolve-FullPath -Path $OutputDirectory
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

if ([string]::IsNullOrWhiteSpace($ReportName)) {
    throw 'ReportName cannot be empty.'
}
$SafeReportName = $ReportName -replace '[^A-Za-z0-9._-]','-'

$ReportingModulePath = Join-Path $RepositoryRoot 'Common\MSADPT.Reporting.psm1'
if (-not (Test-Path -LiteralPath $ReportingModulePath -PathType Leaf)) {
    throw "Reporting module not found: $ReportingModulePath"
}
Import-Module $ReportingModulePath -Force -ErrorAction Stop

$ResolvedSectionPaths = @(
    foreach ($Path in $SectionPath) {
        $Resolved = Resolve-FullPath -Path $Path
        if (-not (Test-Path -LiteralPath $Resolved -PathType Leaf)) {
            throw "Report section not found: $Resolved"
        }
        $Resolved
    }
)

if ($ResolvedSectionPaths.Count -eq 0) {
    throw 'At least one report section is required.'
}

Write-Status -State INFO -Message "Repository: $RepositoryRoot" -Color Cyan
Write-Status -State INFO -Message "Output: $OutputDirectory" -Color Cyan
Write-Status -State INFO -Message 'Network activity: None; directory changes: None.' -Color Green
Write-Status -State READ -Message ("Loading {0} normalized report sections." -f $ResolvedSectionPaths.Count) -Color Cyan

$Loaded = [Collections.Generic.List[object]]::new()
$ValidationRows = [Collections.Generic.List[object]]::new()
$SeenModuleIds = @{}

foreach ($Path in $ResolvedSectionPaths) {
    $Section = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    $Validation = Test-MSADPTReportSection -Section $Section
    $ValidationRows.Add([pscustomobject][ordered]@{
        sectionPath = $Path
        moduleId = [string]$Validation.moduleId
        valid = [bool]$Validation.valid
        errorCount = [int]$Validation.errorCount
        warningCount = [int]$Validation.warningCount
        errors = @($Validation.errors)
        warnings = @($Validation.warnings)
    })

    if (-not $Validation.valid) {
        throw "Invalid report section '$Path': $($Validation.errors -join '; ')"
    }

    $ModuleId = [string]$Section.moduleId
    if ($SeenModuleIds.ContainsKey($ModuleId)) {
        throw "Duplicate moduleId in consolidated report input: $ModuleId"
    }
    $SeenModuleIds[$ModuleId] = $true

    $AnalysisDirectory = Split-Path -Parent $Path
    $CollectionDirectory = Split-Path -Parent $AnalysisDirectory
    $CollectionPrefix = [IO.Path]::GetRelativePath($OutputDirectory, $CollectionDirectory) -replace '\\','/'
    if ($CollectionPrefix -eq '.') { $CollectionPrefix = '' }

    # Canonicalize every evidence target against its collection directory, then
    # express the final link directly from the unified-report output directory.
    # This removes embedded segments such as CollectionA/../CollectionB.
    foreach ($EvidenceLink in @($Section.evidenceLinks)) {
        if ($null -eq $EvidenceLink -or [string]::IsNullOrWhiteSpace([string]$EvidenceLink.relativePath)) { continue }
        $EvidenceTarget = [IO.Path]::GetFullPath((Join-Path $CollectionDirectory ([string]$EvidenceLink.relativePath)))
        $EvidenceLink.relativePath = ([IO.Path]::GetRelativePath($OutputDirectory,$EvidenceTarget) -replace '\\','/')
    }
    $CollectionPrefix = ''

    $Loaded.Add([pscustomobject][ordered]@{
        section = $Section
        sectionPath = $Path
        analysisDirectory = $AnalysisDirectory
        collectionDirectory = $CollectionDirectory
        evidenceLinkPrefix = $CollectionPrefix
        dispositionRank = Get-SectionRank -Disposition ([string]$Section.posture.disposition)
    })
}

$Ordered = @(
    $Loaded |
        Sort-Object dispositionRank, @{ Expression = { $_.section.category } }, @{ Expression = { $_.section.title } }
)

Write-Status -State VALIDATE -Message ("Validated {0} unique module sections with no contract errors." -f $Ordered.Count) -Color Green

$ModuleDispositionCounts = [ordered]@{
    Confirmed = @($Ordered | Where-Object { $_.section.posture.disposition -eq 'Confirmed' }).Count
    'Likely or probable' = @($Ordered | Where-Object { $_.section.posture.disposition -eq 'Likely or probable' }).Count
    Inconclusive = @($Ordered | Where-Object { $_.section.posture.disposition -eq 'Inconclusive' }).Count
    'Not detected' = @($Ordered | Where-Object { $_.section.posture.disposition -eq 'Not detected' }).Count
    'Not applicable' = @($Ordered | Where-Object { $_.section.posture.disposition -eq 'Not applicable' }).Count
}

$CompletedCount = @($Ordered | Where-Object { $_.section.execution.status -eq 'Completed' }).Count
$LimitedCount = @($Ordered | Where-Object { $_.section.execution.status -eq 'CompletedWithLimitations' }).Count
$FailedCount = @($Ordered | Where-Object { $_.section.execution.status -eq 'Failed' }).Count
$EvidenceCompleteCount = @($Ordered | Where-Object { $_.section.posture.evidenceComplete }).Count
$FindingCount = @($Ordered | ForEach-Object { @($_.section.findings).Count } | Measure-Object -Sum).Sum
if ($null -eq $FindingCount) { $FindingCount = 0 }

$PriorityOrder = [ordered]@{
    Immediate = 1
    High = 2
    Normal = 3
    Informational = 4
    NotApplicable = 5
}

$AllFindings = @(
    foreach ($Item in $Ordered) {
        foreach ($Finding in @($Item.section.findings)) {
            [pscustomobject][ordered]@{
                moduleId = [string]$Item.section.moduleId
                moduleTitle = [string]$Item.section.title
                id = [string]$Finding.id
                title = [string]$Finding.title
                disposition = [string]$Finding.disposition
                summary = [string]$Finding.summary
                recommendation = [string]$Finding.recommendation
                priority = [string]$Finding.priority
                priorityRank = if ($PriorityOrder.Contains([string]$Finding.priority)) {
                    [int]$PriorityOrder[[string]$Finding.priority]
                }
                else {
                    99
                }
            }
        }
    }
)
$PrioritizedFindings = @($AllFindings | Sort-Object priorityRank, moduleTitle, title)

$NavigationHtml = @(
    foreach ($Item in $Ordered) {
        $Anchor = 'module-' + [Net.WebUtility]::UrlEncode([string]$Item.section.moduleId)
        '<a href="#{0}" data-search="{1}"><span>{2}</span><small>{3}</small></a>' -f `
            (Convert-HtmlText $Anchor), `
            (Convert-HtmlText ([string]$Item.section.title + ' ' + [string]$Item.section.category + ' ' + [string]$Item.section.posture.disposition)), `
            (Convert-HtmlText $Item.section.title), `
            (Convert-HtmlText $Item.section.posture.disposition)
    }
) -join ''

$SectionHtml = @(
    foreach ($Item in $Ordered) {
        Write-Status -State RENDER -Message ("Rendering {0} with evidence prefix '{1}'." -f $Item.section.moduleId,$Item.evidenceLinkPrefix) -Color Cyan
        ConvertTo-MSADPTReportSectionHtml `
            -Section $Item.section `
            -EvidenceLinkPrefix $Item.evidenceLinkPrefix
    }
) -join "`n"

$FindingDispositionCounts = [ordered]@{
    Confirmed = @($AllFindings | Where-Object { $_.disposition -eq 'Confirmed' }).Count
    'Likely or probable' = @($AllFindings | Where-Object { $_.disposition -eq 'Likely or probable' }).Count
    Inconclusive = @($AllFindings | Where-Object { $_.disposition -eq 'Inconclusive' }).Count
    'Not detected' = @($AllFindings | Where-Object { $_.disposition -eq 'Not detected' }).Count
    'Not applicable' = @($AllFindings | Where-Object { $_.disposition -eq 'Not applicable' }).Count
}

$FindingRows = if ($PrioritizedFindings.Count -eq 0) {
    '<tr><td colspan="5">No normalized findings were provided.</td></tr>'
}
else {
    @(
        foreach ($Finding in $PrioritizedFindings) {
            '<tr data-search="{0}"><td><span class="priority {1}">{2}</span></td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
                (Convert-HtmlText (($Finding.moduleTitle,$Finding.title,$Finding.disposition,$Finding.priority,$Finding.summary,$Finding.recommendation) -join ' ')), `
                (Convert-HtmlText $Finding.priority.ToLowerInvariant()), `
                (Convert-HtmlText $Finding.priority), `
                (Convert-HtmlText $Finding.moduleTitle), `
                (Convert-HtmlText $Finding.title), `
                (Convert-HtmlText $Finding.disposition), `
                (Convert-HtmlText $Finding.summary)
        }
    ) -join ''
}

$GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
$IndexPath = Join-Path $OutputDirectory ($SafeReportName + '.json')
$ValidationPath = Join-Path $OutputDirectory ($SafeReportName + '-validation.json')
$HtmlPath = Join-Path $OutputDirectory ($SafeReportName + '.html')

$Index = [pscustomobject][ordered]@{
    schemaVersion = '1.0'
    generatorVersion = $Version
    generatedUtc = $GeneratedUtc
    repositoryRoot = $RepositoryRoot
    sectionCount = $Ordered.Count
    findingCount = [int]$FindingCount
    completedCount = $CompletedCount
    completedWithLimitationsCount = $LimitedCount
    failedCount = $FailedCount
    evidenceCompleteCount = $EvidenceCompleteCount
    moduleDispositionCounts = [pscustomobject]$ModuleDispositionCounts
    findingDispositionCounts = [pscustomobject]$FindingDispositionCounts
    sections = @(
        foreach ($Item in $Ordered) {
            [pscustomobject][ordered]@{
                moduleId = [string]$Item.section.moduleId
                moduleVersion = [string]$Item.section.moduleVersion
                title = [string]$Item.section.title
                category = [string]$Item.section.category
                disposition = [string]$Item.section.posture.disposition
                executionStatus = [string]$Item.section.execution.status
                evidenceComplete = [bool]$Item.section.posture.evidenceComplete
                sourceSectionPath = [string]$Item.sectionPath
                collectionDirectory = [string]$Item.collectionDirectory
                evidenceLinkPrefix = [string]$Item.evidenceLinkPrefix
            }
        }
    )
    prioritizedFindings = $PrioritizedFindings
    networkActivity = 'None'
    directoryChanges = 'None'
}

ConvertTo-Json -InputObject $Index -Depth 16 |
    Set-Content -LiteralPath $IndexPath -Encoding UTF8
ConvertTo-Json -InputObject @($ValidationRows) -Depth 10 |
    Set-Content -LiteralPath $ValidationPath -Encoding UTF8

$Html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MSADPT unified Active Directory posture report</title>
<style>
:root{color-scheme:light dark;--bg:#eef3f9;--panel:#fff;--text:#152033;--muted:#5f6f88;--border:#d6dfeb;--hero1:#102d54;--hero2:#1769aa;--confirmed:#b42318;--likely:#b54708;--inconclusive:#8a5d00;--notdetected:#137a4a;--na:#65758b;--accent:#1769aa}@media(prefers-color-scheme:dark){:root{--bg:#0c1420;--panel:#152033;--text:#f0f4fb;--muted:#aab6c9;--border:#33415a;--hero1:#102d54;--hero2:#14588f}}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Segoe UI,Arial,sans-serif}a{color:var(--accent)}.layout{display:grid;grid-template-columns:280px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;overflow:auto;background:var(--panel);border-right:1px solid var(--border);padding:20px}.brand{font-size:21px;font-weight:800;margin-bottom:4px}.sidebar input{width:100%;padding:10px;border:1px solid var(--border);border-radius:10px;background:var(--bg);color:var(--text);margin:14px 0}.nav a{display:flex;justify-content:space-between;gap:8px;text-decoration:none;padding:10px;border-radius:9px;color:var(--text);border-bottom:1px solid var(--border)}.nav a:hover{background:var(--bg)}.nav small{color:var(--muted)}main{max-width:1500px;width:100%;padding:28px;margin:auto}.hero{background:linear-gradient(135deg,var(--hero1),var(--hero2));color:#fff;padding:28px;border-radius:18px;box-shadow:0 13px 36px #0002}.hero h1{font-size:30px;margin:0}.hero p{opacity:.9}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:18px 0}.card,.panel,.msadpt-report-section{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px}.card .value{font-size:27px;font-weight:800}.card .label,.muted,.msadpt-muted{color:var(--muted)}.panel{margin:16px 0;overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}th{background:var(--panel);position:sticky;top:0}.priority{padding:3px 8px;border-radius:999px;background:#78839422}.priority.immediate,.priority.high{color:var(--confirmed)}.priority.normal{color:var(--likely)}.priority.informational,.priority.notapplicable{color:var(--muted)}.msadpt-report-section{margin:18px 0;scroll-margin-top:18px}.msadpt-report-section header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.msadpt-report-section h2{margin:0}.msadpt-disposition{padding:6px 10px;border-radius:999px;font-weight:700;white-space:nowrap}.msadpt-disposition.confirmed{color:var(--confirmed);background:#d92d2022}.msadpt-disposition.likely{color:var(--likely);background:#f7900922}.msadpt-disposition.inconclusive{color:var(--inconclusive);background:#eaaa0822}.msadpt-disposition.not-detected{color:var(--notdetected);background:#12b76a22}.msadpt-disposition.not-applicable{color:var(--na);background:#78839422}.msadpt-summary{font-size:16px}.msadpt-execution{padding:10px;background:var(--bg);border-radius:10px}.msadpt-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:14px 0}.msadpt-metric{border:1px solid var(--border);border-radius:11px;padding:12px}.msadpt-metric-value{font-size:23px;font-weight:750}.msadpt-metric-label{font-weight:650}.msadpt-metric-description{color:var(--muted);font-size:12px}.msadpt-finding{border-left:4px solid var(--accent);padding:10px 14px;margin:10px 0;background:var(--bg);border-radius:0 10px 10px 0}.msadpt-finding h4{margin:0}.foot{color:var(--muted);margin:24px 0}@media(max-width:900px){.layout{display:block}.sidebar{position:static;height:auto;border-right:0;border-bottom:1px solid var(--border)}main{padding:16px}}
</style>
</head>
<body><div class="layout"><aside class="sidebar"><div class="brand">MSADPT</div><div class="muted">Unified AD posture</div><input id="moduleSearch" placeholder="Filter module navigation" oninput="filterNavigation()"><nav class="nav" id="moduleNav">$NavigationHtml</nav></aside><main>
<section class="hero"><h1>Active Directory security posture</h1><p>Evidence-first unified report from normalized MSADPT module sections.</p><p>Generated UTC: $(Convert-HtmlText $GeneratedUtc)</p></section>
<section class="cards">
<div class="card"><div class="value">$($Ordered.Count)</div><div class="label">Module sections</div></div>
<div class="card"><div class="value">$FindingCount</div><div class="label">Normalized findings</div></div>
<div class="card"><div class="value">$($FindingDispositionCounts['Confirmed'])</div><div class="label">Confirmed findings</div></div>
<div class="card"><div class="value">$($FindingDispositionCounts['Inconclusive'])</div><div class="label">Inconclusive findings</div></div>
<div class="card"><div class="value">$($FindingDispositionCounts['Not detected'])</div><div class="label">Not detected findings</div></div>
<div class="card"><div class="value">$EvidenceCompleteCount</div><div class="label">Evidence complete</div></div>
</section>
<section class="panel"><h2>At-a-glance interpretation</h2><p><b>Completed:</b> $CompletedCount &nbsp; <b>Completed with limitations:</b> $LimitedCount &nbsp; <b>Failed:</b> $FailedCount</p><p>Summary cards count finding dispositions. Module dispositions are tracked separately in the structured JSON index. Not detected does not mean confirmed absent beyond successful collection scope. Inconclusive preserves evidence limitations without treating the collection as failed.</p><p><b>Analysis network activity:</b> None &nbsp; <b>Directory changes:</b> None</p></section>
<section class="panel"><h2>Prioritized finding inventory</h2><input id="findingSearch" placeholder="Filter findings" oninput="filterFindings()" style="padding:10px;border:1px solid var(--border);border-radius:10px;background:var(--bg);color:var(--text);min-width:300px"><table><thead><tr><th>Priority</th><th>Module</th><th>Finding</th><th>Disposition</th><th>Summary</th></tr></thead><tbody id="findingRows">$FindingRows</tbody></table></section>
$SectionHtml
<p class="foot">Generated by New-MSADPTUnifiedReport-v$Version.ps1. Structured report index: $(Convert-HtmlText ([IO.Path]::GetFileName($IndexPath))).</p>
</main></div>
<script>function filterNavigation(){const q=document.getElementById('moduleSearch').value.toLowerCase();document.querySelectorAll('#moduleNav a').forEach(x=>x.style.display=x.dataset.search.toLowerCase().includes(q)?'flex':'none')}function filterFindings(){const q=document.getElementById('findingSearch').value.toLowerCase();document.querySelectorAll('#findingRows tr').forEach(x=>x.style.display=(x.dataset.search||'').toLowerCase().includes(q)?'':'none')}</script>
</body></html>
"@

[IO.File]::WriteAllText($HtmlPath, $Html, (New-Object Text.UTF8Encoding($false)))

foreach ($Path in @($IndexPath,$ValidationPath,$HtmlPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected output file was not created: $Path"
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "Expected output file is empty: $Path"
    }
}
$null = Get-Content -LiteralPath $IndexPath -Raw | ConvertFrom-Json -ErrorAction Stop
$null = Get-Content -LiteralPath $ValidationPath -Raw | ConvertFrom-Json -ErrorAction Stop

foreach ($Item in $Ordered) {
    $Anchor = 'module-' + [Net.WebUtility]::UrlEncode([string]$Item.section.moduleId)
    $ExpectedAnchorMarkup = 'id="{0}"' -f $Anchor
    if (-not $Html.Contains($ExpectedAnchorMarkup)) {
        throw "Rendered module anchor missing: $Anchor"
    }
}
if ($Html.Contains('ยท') -or $Html.Contains('·')) {
    throw 'HTML encoding safety validation failed.'
}

Write-Status -State PASS -Message ("Unified report completed: sections={0}; findings={1}; limited={2}; failed={3}." -f $Ordered.Count,$FindingCount,$LimitedCount,$FailedCount) -Color Green
Write-Status -State REPORT -Message $HtmlPath -Color Cyan

if ($OpenReport) {
    Start-Process -FilePath $HtmlPath
}

[pscustomobject][ordered]@{
    Status = 'Completed'
    Version = $Version
    SectionCount = $Ordered.Count
    FindingCount = [int]$FindingCount
    CompletedCount = $CompletedCount
    CompletedWithLimitationsCount = $LimitedCount
    FailedCount = $FailedCount
    EvidenceCompleteCount = $EvidenceCompleteCount
    ConfirmedCount = [int]$FindingDispositionCounts['Confirmed']
    LikelyCount = [int]$FindingDispositionCounts['Likely or probable']
    InconclusiveCount = [int]$FindingDispositionCounts['Inconclusive']
    NotDetectedCount = [int]$FindingDispositionCounts['Not detected']
    NotApplicableCount = [int]$FindingDispositionCounts['Not applicable']
    JsonIndexPath = $IndexPath
    ValidationPath = $ValidationPath
    HtmlReportPath = $HtmlPath
    NetworkActivity = 'None'
    DirectoryChanges = 'None'
}
