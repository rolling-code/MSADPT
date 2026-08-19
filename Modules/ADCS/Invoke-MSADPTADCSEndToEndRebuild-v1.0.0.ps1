<#
.SYNOPSIS
Runs and validates the deterministic ADCS end-to-end offline analysis after prerequisite refresh.
.DESCRIPTION
Locates and validates the installed ADCS offline-analysis components, consumes the refreshed v0.1.4
identity prerequisite evidence plus the preserved template configuration and ACL evidence, runs the
end-to-end fact and correlation pipeline once, and validates every generated JSON and CSV output.

CA-runtime evidence is deliberately omitted. This script performs no AD, LDAP, CA, certificate,
authentication, Ollama, registry, or ledger operation.
.NOTES
Version: 1.0.0
Package identity: MSADPT-ADCS-END-TO-END-REBUILD
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$EngagementPath = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example',
    [string]$OutputRoot,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-ADCS-END-TO-END-REBUILD'
$PackageVersion = '1.0.0'
$ExpectedRunnerHash = '9D8B23208F1BC3AFDB5CFEB92477647B02507722F484A37EBB19F2C4353350DD'
$ExpectedPrerequisiteVersion = '0.1.4'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    if (-not $Quiet) { Write-Host ('[{0,-7}] {1}' -f $Status,$Message) -ForegroundColor $Color }
}

function Find-OneFile {
    param([string]$Root,[string]$Filter,[string]$Label)
    $Matches = @(
        Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Recurse -ErrorAction Stop |
        Where-Object { $_.FullName -notmatch '\.backup-' } |
        Sort-Object FullName
    )
    if ($Matches.Count -ne 1) {
        throw "FileDiscoveryMismatch [$Label]: expected 1 active file matching '$Filter', found $($Matches.Count)."
    }
    return $Matches[0].FullName
}

function Validate-Script {
    param([string]$Path,[string]$Label)
    $Tokens = $null
    $ParseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$ParseErrors)
    if ($ParseErrors.Count -gt 0) { throw "ScriptParseFailure [$Label]: $($ParseErrors.Message -join '; ')" }
    return [pscustomobject]@{
        label = $Label
        path = $Path
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    }
}

function Read-JsonArray {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
    try { return @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "JsonParseFailure [$Label]: $($_.Exception.Message)" }
}

Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
Write-Step 'INFO' 'Offline analysis only; CA-runtime input is intentionally omitted.' DarkGray

if (-not (Test-Path -LiteralPath $MSADPTRoot -PathType Container)) { throw "MSADPTRootMissing: $MSADPTRoot" }
if (-not (Test-Path -LiteralPath $EngagementPath -PathType Container)) { throw "EngagementPathMissing: $EngagementPath" }

$RunnerPath = Find-OneFile $MSADPTRoot 'Invoke-MSADPTADCSEndToEndOfflineAnalysis.ps1' 'End-to-end runner'
$FactBuilderPath = Find-OneFile $MSADPTRoot 'Convert-MSADPTADCSEvidenceToFacts.ps1' 'Fact builder'
$CorrelationEnginePath = Find-OneFile $MSADPTRoot 'Invoke-MSADPTADCSPrerequisiteCorrelation.ps1' 'Correlation engine'
$CatalogPath = Find-OneFile $MSADPTRoot 'adcs-technique-prerequisites-v1.0.0.json' 'Technique catalog'
$ConsoleCandidates = @(
    Get-ChildItem -LiteralPath $MSADPTRoot -Filter 'MSADPT.Console.psm1' -File -Recurse -ErrorAction Stop |
    Where-Object { $_.FullName -notmatch '\.backup-' } |
    Sort-Object FullName
)
$ConsoleModulePath = if ($ConsoleCandidates.Count -gt 0) { $ConsoleCandidates[0].FullName } else { $null }

$RunnerValidation = Validate-Script $RunnerPath 'End-to-end runner'
if ($RunnerValidation.sha256 -ne $ExpectedRunnerHash) {
    throw "RunnerHashMismatch: expected $ExpectedRunnerHash, found $($RunnerValidation.sha256)"
}
$FactBuilderValidation = Validate-Script $FactBuilderPath 'Fact builder'
$CorrelationValidation = Validate-Script $CorrelationEnginePath 'Correlation engine'
if ($null -ne $ConsoleModulePath) { $ConsoleValidation = Validate-Script $ConsoleModulePath 'Console module' } else { $ConsoleValidation = $null }

$RunnerCommand = Get-Command -Name $RunnerPath -ErrorAction Stop
$RequiredRunnerParameters = @(
    'TemplateConfigurationPath','TemplateAccessPath','IdentityPrerequisitePath',
    'FactBuilderPath','CatalogPath','CorrelationEnginePath','OutputRoot'
)
foreach ($ParameterName in $RequiredRunnerParameters) {
    if ($ParameterName -notin @($RunnerCommand.Parameters.Keys)) {
        throw "RunnerParameterMissing: $ParameterName"
    }
}

$TemplateConfigurationPath = Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-configuration.json'
$TemplateAccessPath = Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-access.csv'
$IdentityPrerequisitePath = Join-Path $EngagementPath 'evidence\ADCSAttackPathPrerequisiteValidation\resolved-identity-prerequisites.json'
$PrerequisiteResultFiles = @(
    Get-ChildItem -LiteralPath (Join-Path $EngagementPath 'reasoning') -Filter 'module-result-*.json' -File -ErrorAction Stop |
    ForEach-Object {
        try {
            $Object = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
            if ([string]$Object.module -eq 'ADCSAttackPathPrerequisiteValidation' -and
                [string]$Object.moduleVersion -eq $ExpectedPrerequisiteVersion -and
                [string]$Object.status -eq 'Completed') {
                [pscustomobject]@{ File = $_; Result = $Object }
            }
        } catch { }
    } |
    Where-Object { $null -ne $_ } |
    Sort-Object { $_.File.LastWriteTimeUtc } -Descending
)
if ($PrerequisiteResultFiles.Count -ne 1) {
    throw "ActivePrerequisiteResultMismatch: expected 1 v$ExpectedPrerequisiteVersion result, found $($PrerequisiteResultFiles.Count)."
}
$PrerequisiteResult = $PrerequisiteResultFiles[0].Result

$TemplateConfiguration = @(Read-JsonArray $TemplateConfigurationPath 'Template configuration')
$IdentityPrerequisites = @(Read-JsonArray $IdentityPrerequisitePath 'Identity prerequisites')
$TemplateAccess = @(Import-Csv -LiteralPath $TemplateAccessPath -ErrorAction Stop)
if ($TemplateConfiguration.Count -eq 0 -or $TemplateAccess.Count -eq 0 -or $IdentityPrerequisites.Count -eq 0) {
    throw 'AnalysisInputEmpty'
}
if ($IdentityPrerequisites.Count -ne [int]$PrerequisiteResult.targetCount) {
    throw "PrerequisiteCountMismatch: evidence=$($IdentityPrerequisites.Count), result=$($PrerequisiteResult.targetCount)"
}

$Catalog = @(Read-JsonArray $CatalogPath 'Technique catalog')
if ($Catalog.Count -eq 0) { throw 'TechniqueCatalogEmpty' }

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputRoot = Join-Path $EngagementPath "analysis\ADCS\EndToEnd-v014-$Timestamp"
}
if (Test-Path -LiteralPath $OutputRoot) {
    $ExistingFiles = @(Get-ChildItem -LiteralPath $OutputRoot -File -Recurse -ErrorAction SilentlyContinue)
    if ($ExistingFiles.Count -gt 0) { throw "OutputRootNotEmpty: $OutputRoot" }
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$Parameters = @{
    TemplateConfigurationPath = $TemplateConfigurationPath
    TemplateAccessPath = $TemplateAccessPath
    IdentityPrerequisitePath = $IdentityPrerequisitePath
    FactBuilderPath = $FactBuilderPath
    CatalogPath = $CatalogPath
    CorrelationEnginePath = $CorrelationEnginePath
    OutputRoot = $OutputRoot
}
if ($null -ne $ConsoleModulePath -and 'ConsoleModulePath' -in @($RunnerCommand.Parameters.Keys)) {
    $Parameters['ConsoleModulePath'] = $ConsoleModulePath
}
if ('Quiet' -in @($RunnerCommand.Parameters.Keys)) { $Parameters['Quiet'] = [bool]$Quiet }

Write-Step 'ACTION' "Running ADCS end-to-end offline analysis using refreshed v$ExpectedPrerequisiteVersion evidence." Yellow
$Warnings = @()
$Parameters['WarningVariable'] = 'Warnings'
$RunnerOutput = @(& $RunnerPath @Parameters)
if ($Warnings.Count -gt 0) { throw "AnalysisWarningsDetected: $($Warnings -join '; ')" }

$GeneratedFiles = @(Get-ChildItem -LiteralPath $OutputRoot -File -Recurse -ErrorAction Stop | Sort-Object FullName)
if ($GeneratedFiles.Count -eq 0) { throw 'AnalysisGeneratedNoFiles' }
$JsonFiles = @($GeneratedFiles | Where-Object { $_.Extension -eq '.json' })
$CsvFiles = @($GeneratedFiles | Where-Object { $_.Extension -eq '.csv' })
$JsonInventory = @()
foreach ($JsonFile in $JsonFiles) {
    try {
        $Object = Get-Content -LiteralPath $JsonFile.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
        $JsonInventory += ,[pscustomobject]@{
            path = $JsonFile.FullName
            recordCount = @($Object).Count
            size = [int64]$JsonFile.Length
            sha256 = (Get-FileHash -LiteralPath $JsonFile.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    } catch { throw "GeneratedJsonParseFailure [$($JsonFile.FullName)]: $($_.Exception.Message)" }
}
$CsvInventory = @()
foreach ($CsvFile in $CsvFiles) {
    try {
        $Rows = @(Import-Csv -LiteralPath $CsvFile.FullName -ErrorAction Stop)
        $CsvInventory += ,[pscustomobject]@{
            path = $CsvFile.FullName
            recordCount = $Rows.Count
            size = [int64]$CsvFile.Length
            sha256 = (Get-FileHash -LiteralPath $CsvFile.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    } catch { throw "GeneratedCsvParseFailure [$($CsvFile.FullName)]: $($_.Exception.Message)" }
}

$ManifestPath = Join-Path $OutputRoot 'end-to-end-rebuild-manifest.json'
$Manifest = [pscustomobject][ordered]@{
    schemaVersion = '1.0'
    packageIdentity = $PackageIdentity
    packageVersion = $PackageVersion
    status = 'Completed'
    generatedUtc = ([DateTime](Get-Date)).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    source = [pscustomobject]@{
        engagementPath = $EngagementPath
        prerequisiteModuleVersion = [string]$PrerequisiteResult.moduleVersion
        prerequisiteAnalysisVersion = [string]$PrerequisiteResult.analysisVersion
        prerequisiteTargetCount = [int]$PrerequisiteResult.targetCount
        templateConfigurationCount = $TemplateConfiguration.Count
        templateAccessRowCount = $TemplateAccess.Count
        techniqueCatalogCount = $Catalog.Count
        caRuntimeObservationPath = $null
    }
    tools = [pscustomobject]@{
        runner = $RunnerValidation
        factBuilder = $FactBuilderValidation
        correlationEngine = $CorrelationValidation
        consoleModule = $ConsoleValidation
    }
    runnerOutput = @($RunnerOutput | ForEach-Object { $_ })
    generatedFileCount = $GeneratedFiles.Count
    jsonFiles = @($JsonInventory)
    csvFiles = @($CsvInventory)
    safety = [pscustomobject]@{
        networkActivity = 'None'
        collectorActivity = 'None'
        ledgerChanges = 'None'
        caRuntimeActivity = 'None'
        ollamaActivity = 'None'
    }
}
$Manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
$RoundTrip = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
if ([string]$RoundTrip.status -ne 'Completed' -or [int]$RoundTrip.generatedFileCount -ne $GeneratedFiles.Count) {
    throw 'RebuildManifestRoundTripFailure'
}

Write-Step 'DONE' "Offline rebuild completed: files=$($GeneratedFiles.Count), JSON=$($JsonFiles.Count), CSV=$($CsvFiles.Count)." Green
[pscustomobject][ordered]@{
    Status = 'Passed'
    PackageIdentity = $PackageIdentity
    PackageVersion = $PackageVersion
    EngagementPath = $EngagementPath
    PrerequisiteModuleVersion = [string]$PrerequisiteResult.moduleVersion
    PrerequisiteTargetCount = [int]$PrerequisiteResult.targetCount
    TemplateConfigurationCount = $TemplateConfiguration.Count
    TemplateAccessRowCount = $TemplateAccess.Count
    TechniqueCatalogCount = $Catalog.Count
    GeneratedFileCount = $GeneratedFiles.Count
    JsonFileCount = $JsonFiles.Count
    CsvFileCount = $CsvFiles.Count
    OutputRoot = $OutputRoot
    ManifestPath = $ManifestPath
    RunnerSha256 = $RunnerValidation.sha256
    FactBuilderSha256 = $FactBuilderValidation.sha256
    CorrelationEngineSha256 = $CorrelationValidation.sha256
    CARuntimeInput = 'Omitted'
    NetworkActivity = 'None'
    LedgerChanges = 'None'
    OllamaActivity = 'None'
}
