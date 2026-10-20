<#
.SYNOPSIS
Builds an offline MSADPT module-integration readiness report from the repository catalogs.

.DESCRIPTION
Validates module-registry structure, checks every registered entry point, summarizes lifecycle and
orchestration states, correlates coverage families, and writes JSON plus a self-contained HTML report.
No Active Directory, network, Git, or external service is contacted.

.NOTES
Version: 1.0.3
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputDirectory,
    [switch]$OpenReport,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.3'

function Write-Status {
    param(
        [ValidateSet('INFO','CHECK','PASS','WARN','FAIL','REPORT')][string]$State,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($NoColor) {
        Write-Host ('[{0,-7}] {1}' -f $State, $Message)
    }
    else {
        Write-Host ('[{0,-7}] {1}' -f $State, $Message) -ForegroundColor $Color
    }
}

function Resolve-FullPath {
    param([Parameter(Mandatory)][string]$Path)

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

function Get-PropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $Property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $Default }
    return $Property.Value
}

$RepositoryRoot = Resolve-FullPath -Path $RepositoryRoot
if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "Repository root not found: $RepositoryRoot"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepositoryRoot 'Output\IntegrationReadiness'
}
$OutputDirectory = Resolve-FullPath -Path $OutputDirectory
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$RegistryPath = Join-Path $RepositoryRoot 'Catalogs\module-registry.json'
$CoveragePath = Join-Path $RepositoryRoot 'Catalogs\attack-surface-coverage.json'

Write-Status -State INFO -Message "Repository: $RepositoryRoot" -Color Cyan
Write-Status -State CHECK -Message 'Loading module registry and attack-surface coverage catalog.' -Color Cyan

foreach ($RequiredPath in @($RegistryPath, $CoveragePath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Required catalog not found: $RequiredPath"
    }
}

$Registry = Get-Content -LiteralPath $RegistryPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$Coverage = Get-Content -LiteralPath $CoveragePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$Modules = @($Registry.Modules)
$Families = @($Coverage.Families)

Write-Status -State CHECK -Message ("Validating {0} registered modules." -f $Modules.Count) -Color Cyan

$Rows = [Collections.Generic.List[object]]::new()
$Issues = [Collections.Generic.List[object]]::new()
$SeenKeys = @{}

foreach ($Module in $Modules) {
    $ModuleId = [string](Get-PropertyValue -InputObject $Module -Name 'ModuleId' -Default '')
    $ModuleVersion = [string](Get-PropertyValue -InputObject $Module -Name 'Version' -Default '')
    $EntryPoint = [string](Get-PropertyValue -InputObject $Module -Name 'EntryPoint' -Default '')
    $Maturity = [string](Get-PropertyValue -InputObject $Module -Name 'Maturity' -Default 'Unspecified')
    $OrchestrationState = [string](Get-PropertyValue -InputObject $Module -Name 'OrchestrationState' -Default 'Unspecified')
    $ValidationState = [string](Get-PropertyValue -InputObject $Module -Name 'ValidationState' -Default $(if ($Maturity -eq 'Integrated') { 'Integrated' } else { 'Unvalidated' }))
    $Category = [string](Get-PropertyValue -InputObject $Module -Name 'Category' -Default 'Uncategorized')
    $ComponentType = [string](Get-PropertyValue -InputObject $Module -Name 'ComponentType' -Default 'Unknown')
    $SafetyClass = [string](Get-PropertyValue -InputObject $Module -Name 'SafetyClass' -Default 'Unspecified')
    $SupportedProfiles = @((Get-PropertyValue -InputObject $Module -Name 'SupportedProfiles' -Default @()))
    $KnownLimitations = @((Get-PropertyValue -InputObject $Module -Name 'KnownLimitations' -Default @()))
    $ReportSectionAvailable = [bool](Get-PropertyValue -InputObject $Module -Name 'ReportSectionAvailable' -Default ($Maturity -eq 'Integrated'))
    $ResumeSupported = [bool](Get-PropertyValue -InputObject $Module -Name 'ResumeSupported' -Default $false)
    $ManifestSupported = [bool](Get-PropertyValue -InputObject $Module -Name 'EvidenceManifestSupported' -Default $false)

    $ResolvedEntryPoint = if ([string]::IsNullOrWhiteSpace($EntryPoint)) {
        $null
    }
    else {
        Join-Path $RepositoryRoot ($EntryPoint -replace '/', [IO.Path]::DirectorySeparatorChar)
    }
    $EntryPointExists = $null -ne $ResolvedEntryPoint -and (Test-Path -LiteralPath $ResolvedEntryPoint -PathType Leaf)

    $Key = '{0}|{1}' -f $ModuleId, $ModuleVersion
    $Duplicate = $SeenKeys.ContainsKey($Key)
    if (-not $Duplicate) { $SeenKeys[$Key] = $true }

    $ValidatedStates = @(
        'CollectorValidated'
        'CollectorValidatedWithLimitations'
        'AnalyzerValidated'
        'OfflineTestValidated'
    )

    $Readiness = if ($Maturity -eq 'Integrated' -and $EntryPointExists -and $ReportSectionAvailable -and $SupportedProfiles.Count -gt 0) {
        'Integrated'
    }
    elseif ($ValidationState -in $ValidatedStates -and $EntryPointExists) {
        'IntegrationReady'
    }
    elseif (-not $EntryPointExists) {
        'BlockedMissingEntryPoint'
    }
    else {
        'Standalone'
    }

    $Rows.Add([pscustomobject][ordered]@{
        ModuleId = $ModuleId
        Version = $ModuleVersion
        Category = $Category
        ComponentType = $ComponentType
        EntryPoint = $EntryPoint
        EntryPointExists = $EntryPointExists
        DuplicateRegistryKey = $Duplicate
        Maturity = $Maturity
        OrchestrationState = $OrchestrationState
        ValidationState = $ValidationState
        SafetyClass = $SafetyClass
        SupportedProfiles = $SupportedProfiles
        ResumeSupported = $ResumeSupported
        EvidenceManifestSupported = $ManifestSupported
        ReportSectionAvailable = $ReportSectionAvailable
        KnownLimitations = $KnownLimitations
        IntegrationReadiness = $Readiness
    })

    if ([string]::IsNullOrWhiteSpace($ModuleId)) {
        $Issues.Add([pscustomobject]@{ Type='RegistryContract'; ModuleId=$ModuleId; Version=$ModuleVersion; Detail='ModuleId is empty.' })
    }
    if ([string]::IsNullOrWhiteSpace($ModuleVersion)) {
        $Issues.Add([pscustomobject]@{ Type='RegistryContract'; ModuleId=$ModuleId; Version=$ModuleVersion; Detail='Version is empty.' })
    }
    if (-not $EntryPointExists) {
        $Issues.Add([pscustomobject]@{ Type='MissingEntryPoint'; ModuleId=$ModuleId; Version=$ModuleVersion; Detail=$EntryPoint })
    }
    if ($Duplicate) {
        $Issues.Add([pscustomobject]@{ Type='DuplicateRegistryKey'; ModuleId=$ModuleId; Version=$ModuleVersion; Detail=$Key })
    }
    if ($Maturity -eq 'Integrated' -and $SupportedProfiles.Count -eq 0) {
        $Issues.Add([pscustomobject]@{ Type='IntegratedContract'; ModuleId=$ModuleId; Version=$ModuleVersion; Detail='Integrated module has no SupportedProfiles.' })
    }
}

$Summary = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    ToolVersion = $Version
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    RepositoryRoot = $RepositoryRoot
    RegistrySchemaVersion = [string]$Registry.SchemaVersion
    CoverageSchemaVersion = [string]$Coverage.SchemaVersion
    RegisteredModuleCount = $Rows.Count
    ExistingEntryPointCount = @($Rows | Where-Object EntryPointExists).Count
    MissingEntryPointCount = @($Rows | Where-Object { -not $_.EntryPointExists }).Count
    IntegratedCount = @($Rows | Where-Object { $_.IntegrationReadiness -eq 'Integrated' }).Count
    IntegrationReadyCount = @($Rows | Where-Object { $_.IntegrationReadiness -eq 'IntegrationReady' }).Count
    StandaloneCount = @($Rows | Where-Object { $_.IntegrationReadiness -eq 'Standalone' }).Count
    UnvalidatedStandaloneCount = @($Rows | Where-Object { $_.IntegrationReadiness -eq 'Standalone' -and $_.ValidationState -eq 'Unvalidated' }).Count
    BlockedCount = @($Rows | Where-Object { $_.IntegrationReadiness -eq 'BlockedMissingEntryPoint' }).Count
    CollectorValidatedCount = @($Rows | Where-Object { $_.ValidationState -eq 'CollectorValidated' }).Count
    CollectorValidatedWithLimitationsCount = @($Rows | Where-Object { $_.ValidationState -eq 'CollectorValidatedWithLimitations' }).Count
    ReportSectionAvailableCount = @($Rows | Where-Object ReportSectionAvailable).Count
    ResumeSupportedCount = @($Rows | Where-Object ResumeSupported).Count
    EvidenceManifestSupportedCount = @($Rows | Where-Object EvidenceManifestSupported).Count
    CoverageFamilyCount = $Families.Count
    RegistryIssueCount = $Issues.Count
    NetworkExecuted = $false
    DirectoryChanges = 'None'
}

$JsonPath = Join-Path $OutputDirectory 'MSADPT-Integration-Readiness.json'
$CsvPath = Join-Path $OutputDirectory 'MSADPT-Integration-Readiness.csv'
$IssuesPath = Join-Path $OutputDirectory 'MSADPT-Integration-Issues.json'
$HtmlPath = Join-Path $OutputDirectory 'MSADPT-Integration-Readiness.html'

[pscustomobject][ordered]@{
    Summary = $Summary
    Modules = @($Rows)
    CoverageFamilies = $Families
    Issues = @($Issues)
} | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $JsonPath -Encoding UTF8

$Rows | Select-Object ModuleId,Version,Category,ComponentType,EntryPoint,EntryPointExists,Maturity,OrchestrationState,ValidationState,SafetyClass,IntegrationReadiness,ReportSectionAvailable,ResumeSupported,EvidenceManifestSupported,@{N='SupportedProfiles';E={$_.SupportedProfiles -join ';'}},@{N='KnownLimitations';E={$_.KnownLimitations -join ' | '}} |
    Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
ConvertTo-Json -InputObject @($Issues) -Depth 8 | Set-Content -LiteralPath $IssuesPath -Encoding UTF8

$Cards = @(
    @{Label='Registered modules'; Value=$Summary.RegisteredModuleCount; Class='neutral'},
    @{Label='Integrated'; Value=$Summary.IntegratedCount; Class='good'},
    @{Label='Integration-ready'; Value=$Summary.IntegrationReadyCount; Class='info'},
    @{Label='Validated with limits'; Value=$Summary.CollectorValidatedWithLimitationsCount; Class='warn'},
    @{Label='Standalone / unvalidated'; Value=$Summary.UnvalidatedStandaloneCount; Class='neutral'},
    @{Label='Missing entry points'; Value=$Summary.MissingEntryPointCount; Class=if($Summary.MissingEntryPointCount){'bad'}else{'good'}}
) | ForEach-Object {
    '<div class="card {0}"><div class="value">{1}</div><div class="label">{2}</div></div>' -f $_.Class,$_.Value,(Convert-HtmlText $_.Label)
}

$RowsHtml = foreach ($Row in ($Rows | Sort-Object Category,ModuleId,Version)) {
    $Limitations = if ($Row.KnownLimitations.Count) { $Row.KnownLimitations -join ' ' } else { '' }
    '<tr data-search="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td><span class="pill {5}">{6}</span></td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td></tr>' -f `
        (Convert-HtmlText (($Row.ModuleId,$Row.Category,$Row.ValidationState,$Row.IntegrationReadiness,$Limitations) -join ' ')), `
        (Convert-HtmlText $Row.ModuleId),(Convert-HtmlText $Row.Version),(Convert-HtmlText $Row.Category),(Convert-HtmlText $Row.ComponentType), `
        ($(if($Row.IntegrationReadiness -eq 'Integrated'){'good'}elseif($Row.IntegrationReadiness -eq 'IntegrationReady'){'info'}elseif($Row.IntegrationReadiness -like 'Blocked*'){'bad'}else{'neutral'})), `
        (Convert-HtmlText $Row.IntegrationReadiness),(Convert-HtmlText $Row.ValidationState),(Convert-HtmlText ($Row.SupportedProfiles -join ', ')), `
        (Convert-HtmlText ($(if($Row.ReportSectionAvailable){'Yes'}else{'No'}))),(Convert-HtmlText $Limitations)
}

$CoverageHtml = foreach ($Family in ($Families | Sort-Object Id)) {
    '<div class="family"><h3>{0}</h3><div class="muted">{1}</div><ul>{2}</ul></div>' -f `
        (Convert-HtmlText $Family.Name),(Convert-HtmlText $Family.Id), `
        ((@($Family.Techniques) | ForEach-Object { '<li>{0}</li>' -f (Convert-HtmlText $_) }) -join '')
}

$IssueHtml = if ($Issues.Count -eq 0) {
    '<p class="good-text">No registry contract issues were detected.</p>'
}
else {
    $IssueRows = @(
        foreach ($Issue in $Issues) {
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
                (Convert-HtmlText $Issue.Type), `
                (Convert-HtmlText $Issue.ModuleId), `
                (Convert-HtmlText $Issue.Version), `
                (Convert-HtmlText $Issue.Detail)
        }
    )

    '<table><thead><tr><th>Type</th><th>Module</th><th>Version</th><th>Detail</th></tr></thead><tbody>{0}</tbody></table>' -f `
        ($IssueRows -join '')
}

$Html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MSADPT Integration Readiness</title>
<style>
:root{color-scheme:light dark;--bg:#f4f7fb;--panel:#fff;--text:#172033;--muted:#60708a;--border:#d9e1ec;--good:#137a4a;--info:#1769aa;--warn:#a86600;--bad:#b42318} @media(prefers-color-scheme:dark){:root{--bg:#0f1724;--panel:#172033;--text:#ecf2fb;--muted:#a8b4c7;--border:#33415a}}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Segoe UI,Arial,sans-serif} main{max-width:1500px;margin:auto;padding:28px}.hero{background:linear-gradient(135deg,#173b6c,#1769aa);color:#fff;padding:28px;border-radius:18px;box-shadow:0 12px 32px #0002}.hero h1{margin:0;font-size:30px}.hero p{margin:8px 0 0;opacity:.9}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}.card,.panel,.family{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px}.value{font-size:28px;font-weight:750}.label,.muted{color:var(--muted)}.good .value,.good-text{color:var(--good)}.info .value{color:var(--info)}.warn .value{color:var(--warn)}.bad .value{color:var(--bad)}.panel{margin:16px 0;overflow:auto}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}input{padding:10px 12px;border-radius:10px;border:1px solid var(--border);min-width:300px;background:var(--panel);color:var(--text)}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left}th{position:sticky;top:0;background:var(--panel)}.pill{padding:3px 8px;border-radius:999px;background:#7d879622}.pill.good{color:var(--good);background:#16a36a22}.pill.info{color:var(--info);background:#1884cf22}.pill.bad{color:var(--bad);background:#d92d2022}.families{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.family h3{margin:0}.family ul{padding-left:20px}code{font-family:Cascadia Mono,Consolas,monospace}.foot{color:var(--muted);margin-top:18px}
</style></head><body><main>
<section class="hero"><h1>MSADPT Integration Readiness</h1><p>Offline registry, entry-point, lifecycle, coverage, resume, manifest, and report-section inventory.</p><p>Generated UTC: $(Convert-HtmlText $Summary.GeneratedUtc)</p></section>
<section class="cards">$($Cards -join '')</section>
<section class="panel"><h2>What this proves</h2><p>This report validates repository metadata and entry-point presence. It does not claim that a module is operationally integrated unless the registry marks it integrated, it has a supported profile, its entry point exists, and a report section is declared.</p><p><b>Network executed:</b> No &nbsp; <b>Directory changes:</b> None</p></section>
<section class="panel"><div class="toolbar"><h2 style="margin-right:auto">Module lifecycle</h2><input id="search" placeholder="Filter modules, categories, or states" oninput="filterRows()"></div><table><thead><tr><th>Module</th><th>Version</th><th>Category</th><th>Type</th><th>Readiness</th><th>Validation</th><th>Profiles</th><th>Report</th><th>Limitations</th></tr></thead><tbody id="modules">$($RowsHtml -join '')</tbody></table></section>
<section class="panel"><h2>Registry issues</h2>$IssueHtml</section>
<section class="panel"><h2>Attack-surface coverage families</h2><div class="families">$($CoverageHtml -join '')</div></section>
<p class="foot">Generated by New-MSADPTIntegrationReadinessReport-v$Version.ps1. JSON and CSV evidence are stored beside this report.</p>
</main><script>function filterRows(){const q=document.getElementById('search').value.toLowerCase();document.querySelectorAll('#modules tr').forEach(r=>r.style.display=r.dataset.search.toLowerCase().includes(q)?'':'none')}</script></body></html>
"@

[IO.File]::WriteAllText($HtmlPath, $Html, (New-Object Text.UTF8Encoding($false)))

foreach ($Path in @($JsonPath,$CsvPath,$IssuesPath,$HtmlPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected output file was not created: $Path"
    }

    $OutputItem = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($OutputItem.Length -eq 0) {
        throw "Expected output file is empty: $Path"
    }
}

$null = Get-Content -LiteralPath $JsonPath -Raw -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop
$null = Get-Content -LiteralPath $IssuesPath -Raw -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop

Write-Status -State PASS -Message ("Validated {0} modules; {1} integrated; {2} integration-ready; {3} issues." -f $Summary.RegisteredModuleCount,$Summary.IntegratedCount,$Summary.IntegrationReadyCount,$Summary.RegistryIssueCount) -Color Green
Write-Status -State REPORT -Message $HtmlPath -Color Cyan

if ($OpenReport) {
    Start-Process -FilePath $HtmlPath
}

[pscustomobject][ordered]@{
    Status = 'Completed'
    Version = $Version
    RepositoryRoot = $RepositoryRoot
    RegisteredModuleCount = $Summary.RegisteredModuleCount
    IntegratedCount = $Summary.IntegratedCount
    IntegrationReadyCount = $Summary.IntegrationReadyCount
    RegistryIssueCount = $Summary.RegistryIssueCount
    JsonPath = $JsonPath
    CsvPath = $CsvPath
    IssuesPath = $IssuesPath
    HtmlReportPath = $HtmlPath
    NetworkExecuted = $false
    DirectoryChanges = 'None'
}
