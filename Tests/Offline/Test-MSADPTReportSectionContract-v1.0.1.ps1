[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ModulePath = Join-Path $RepositoryRoot 'Common\MSADPT.Reporting.psm1'
$SchemaPath = Join-Path $RepositoryRoot 'Schemas\report-section.schema.json'

foreach ($RequiredPath in @($ModulePath, $SchemaPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "RequiredFileMissing: $RequiredPath"
    }
}

$Tokens = $null
$ParseErrors = $null
[void][Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$Tokens, [ref]$ParseErrors)
if (@($ParseErrors).Count -gt 0) {
    throw "ParserFailure[$ModulePath]: $(@($ParseErrors | ForEach-Object { $_.Message }) -join '; ')"
}

$Schema = Get-Content -LiteralPath $SchemaPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ([string]$Schema.title -ne 'MSADPT Normalized Report Section') {
    throw 'SchemaTitleMismatch'
}

Import-Module $ModulePath -Force -ErrorAction Stop

$Section = New-MSADPTReportSection `
    -ModuleId 'Synthetic.ContractValidation' `
    -ModuleVersion '1.0.0' `
    -Title 'Synthetic Contract Validation' `
    -Category 'Testing' `
    -ExecutionStatus 'CompletedWithLimitations' `
    -Mode 'Analyze' `
    -Profile 'Standalone' `
    -Target 'offline-fixture' `
    -Disposition 'Inconclusive' `
    -Summary 'Synthetic evidence validates the normalized report-section contract.' `
    -Confidence 'High' `
    -EvidenceComplete $false `
    -Metrics @(
        [pscustomobject][ordered]@{
            id = 'objects'
            label = 'Objects assessed'
            value = 3
            state = 'Informational'
            description = 'Synthetic count.'
        }
    ) `
    -Findings @(
        [pscustomobject][ordered]@{
            id = 'finding-1'
            title = 'Synthetic limitation'
            disposition = 'Inconclusive'
            summary = 'A bounded limitation is preserved without becoming a failure.'
            evidence = @('Synthetic evidence record.')
            limitations = @('No live directory was queried.')
            recommendation = 'Use a targeted read-only validation when live evidence is required.'
            priority = 'Informational'
        }
    ) `
    -EvidenceLinks @(
        [pscustomobject][ordered]@{
            label = 'Synthetic evidence'
            relativePath = 'evidence/synthetic.json'
            mediaType = 'application/json'
            exists = $false
        }
    ) `
    -Limitations @('Offline synthetic validation only.') `
    -Recommendations @('Integrate only modules with validated execution and reporting contracts.')

$Validation = Test-MSADPTReportSection -Section $Section
if (-not $Validation.valid) {
    throw "ContractValidationFailed: $($Validation.errors -join '; ')"
}

$OriginalEvidencePath = [string]$Section.evidenceLinks[0].relativePath
$Html = ConvertTo-MSADPTReportSectionHtml -Section $Section -EvidenceLinkPrefix '../'
foreach ($Marker in @('Synthetic Contract Validation','Inconclusive','Objects assessed','Collection and interpretation limitations','Recommended follow-up','../evidence/synthetic.json','Synthetic.ContractValidation v1.0.0 - Testing')) {
    if (-not $Html.Contains($Marker)) {
        throw "HtmlContractMarkerMissing: $Marker"
    }
}

if ($Html.Contains('ยท') -or $Html.Contains('·')) {
    throw 'HtmlEncodingSafetyMarkerDetected'
}

if ([string]$Section.evidenceLinks[0].relativePath -ne $OriginalEvidencePath) {
    throw 'NormalizedEvidencePathWasMutatedByRenderer'
}

$RoundTrip = $Section | ConvertTo-Json -Depth 16 | ConvertFrom-Json -ErrorAction Stop
$RoundTripValidation = Test-MSADPTReportSection -Section $RoundTrip
if (-not $RoundTripValidation.valid) {
    throw "RoundTripValidationFailed: $($RoundTripValidation.errors -join '; ')"
}

[pscustomobject][ordered]@{
    Status = 'Passed'
    TestVersion = '1.0.1'
    SchemaVersion = [string]$Section.schemaVersion
    ModuleId = [string]$Section.moduleId
    ValidationErrors = $Validation.errorCount
    ValidationWarnings = $Validation.warningCount
    HtmlLength = $Html.Length
    NetworkActivity = 'None'
    DirectoryChanges = 'None'
}
