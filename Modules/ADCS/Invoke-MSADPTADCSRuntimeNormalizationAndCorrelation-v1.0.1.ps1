<#
.SYNOPSIS
Normalizes authoritative nested ADCS CA-runtime evidence and reruns deterministic correlation.
.DESCRIPTION
Preserves raw collector output unchanged. Creates the flat observations expected by the canonical
ADCS fact builder. Completed queries are Observed. Failed or unavailable values remain Inconclusive.
Known flags are extracted only from explicit certutil output. The canonical aggregate pipeline is
then rerun and compared with the validated no-runtime baseline.
.NOTES
Version: 1.0.1
Package identity: MSADPT-ADCS-RUNTIME-NORMALIZATION-AND-CORRELATION
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$EngagementPath = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example',
    [string]$NoRuntimeBaselineRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example\analysis\ADCS\EndToEnd-v014-20260817-084053',
    [string]$OutputRoot,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-ADCS-RUNTIME-NORMALIZATION-AND-CORRELATION'
$PackageVersion = '1.0.1'
$ExpectedRunnerHash = '9D8B23208F1BC3AFDB5CFEB92477647B02507722F484A37EBB19F2C4353350DD'
$ExpectedFactBuilderHash = '80DB4BBCF80287FB4F68C6B93D80B7FFECBAE52D02B354B4B331FDFA0373A41C'
$ExpectedCorrelationHash = '93D0899D06342F5EF9D2D3818540DD392E3BC6935FEED4282AC104D55E4521CC'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    if (-not $Quiet) { Write-Host ('[{0,-7}] {1}' -f $Status,$Message) -ForegroundColor $Color }
}
function Require-File {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
}
function Validate-Script {
    param([string]$Path,[string]$Label,[string]$ExpectedHash)
    Require-File $Path $Label
    $Tokens=$null;$Errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$Errors)
    if ($Errors.Count -gt 0) { throw "ParseFailure [$Label]: $($Errors.Message -join '; ')" }
    $Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($Hash -ne $ExpectedHash) { throw "HashMismatch [$Label]: expected $ExpectedHash, found $Hash" }
    [pscustomobject]@{label=$Label;path=$Path;sha256=$Hash}
}
function Read-JsonDocument {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    try { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "JsonParseFailure [$Label]: $($_.Exception.Message)" }
}
function Get-Collection {
    param([object]$Document,[string]$Label)
    if ($Document -is [array]) { return @($Document) }
    foreach ($Name in @('facts','Facts','items','Items','records','Records')) {
        $Property=$Document.PSObject.Properties[$Name]
        if ($null -ne $Property) { return @($Property.Value) }
    }
    throw "CollectionNotFound [$Label]"
}
function Get-Value {
    param([object]$Object,[string[]]$Names)
    foreach ($Name in $Names) {
        $Property=$Object.PSObject.Properties[$Name]
        if ($null -ne $Property) { return $Property.Value }
    }
    return $null
}
function Get-Key {
    param([object]$Object,[string[]]$Names)
    foreach ($Name in $Names) {
        $Property=$Object.PSObject.Properties[$Name]
        if ($null -ne $Property -and -not [string]::IsNullOrWhiteSpace([string]$Property.Value)) { return [string]$Property.Value }
    }
    return $null
}

Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
Write-Step 'INFO' 'Raw runtime evidence remains unchanged; normalization and correlation are offline only.' DarkGray
foreach ($Directory in @($MSADPTRoot,$EngagementPath,$NoRuntimeBaselineRoot)) {
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { throw "DirectoryMissing: $Directory" }
}

$Runner=Join-Path $MSADPTRoot 'Analysis\ADCS\Invoke-MSADPTADCSEndToEndOfflineAnalysis.ps1'
$Builder=Join-Path $MSADPTRoot 'Analysis\ADCS\Convert-MSADPTADCSEvidenceToFacts.ps1'
$Correlation=Join-Path $MSADPTRoot 'Analysis\ADCS\Invoke-MSADPTADCSPrerequisiteCorrelation.ps1'
$CatalogMatches=@(
    Get-ChildItem -LiteralPath $MSADPTRoot -Filter 'adcs-technique-prerequisites-v1.0.0.json' -File -Recurse |
        Where-Object { $_.FullName -notmatch '\.backup-' -and $_.FullName -notmatch '\\Tests\\' }
)
if ($CatalogMatches.Count -ne 1) { throw "CatalogDiscoveryMismatch: $($CatalogMatches.Count)" }
$Catalog=$CatalogMatches[0].FullName
$Console=Join-Path $MSADPTRoot 'Common\MSADPT.Console.psm1'
$TemplateConfig=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-configuration.json'
$TemplateAccess=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-access.csv'
$Identities=Join-Path $EngagementPath 'evidence\ADCSAttackPathPrerequisiteValidation\resolved-identity-prerequisites.json'
$RawRuntime=Join-Path $EngagementPath 'evidence\ADCSCARuntimeConfigurationCollection\ca-runtime-evidence.json'
$BaseFacts=Join-Path $NoRuntimeBaselineRoot 'Facts\adcs-facts.json'
$BaseTech=Join-Path $NoRuntimeBaselineRoot 'Correlation\adcs-technique-candidates.json'
foreach ($File in @($Catalog,$TemplateConfig,$TemplateAccess,$Identities,$RawRuntime,$BaseFacts,$BaseTech)) { Require-File $File $File }

$RunnerInfo=Validate-Script $Runner 'Runner' $ExpectedRunnerHash
$BuilderInfo=Validate-Script $Builder 'Fact builder' $ExpectedFactBuilderHash
$CorrelationInfo=Validate-Script $Correlation 'Correlation' $ExpectedCorrelationHash
Write-Step 'OK' 'Canonical pipeline components validated.' Green

$Raw=@(Read-JsonDocument $RawRuntime 'Raw runtime evidence')
if ($Raw.Count -ne 1) { throw "CARowCountMismatch: $($Raw.Count)" }
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot=Join-Path $EngagementPath ('analysis\ADCS\RuntimeNormalized-v011-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if (Test-Path -LiteralPath $OutputRoot) {
    if (@(Get-ChildItem -LiteralPath $OutputRoot -Force -ErrorAction SilentlyContinue).Count -gt 0) { throw "OutputRootNotEmpty: $OutputRoot" }
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$NormalizedPath=Join-Path $OutputRoot 'ca-runtime-observations-normalized.json'

$Observations=New-Object 'Collections.Generic.List[object]'
foreach ($CA in $Raw) {
    $CaConfiguration=[string]$CA.CaConfiguration
    foreach ($Query in @($CA.CertutilQueries)) {
        $QueryStatus=[string]$Query.Result.Status
        $StandardOutput=[string]$Query.Result.StandardOutput
        $StandardError=[string]$Query.Result.StandardError
        $Flags=New-Object 'Collections.Generic.List[string]'
        if ($QueryStatus -eq 'Completed') {
            foreach ($Line in @($StandardOutput -split "`r?`n")) {
                if ($Line -match '^\s+([A-Z][A-Z0-9_]+)\s+--\s+') { $Flags.Add([string]$Matches[1]) }
            }
        }
        $EvidenceStatus=if ($QueryStatus -eq 'Completed') {'Observed'} else {'Inconclusive'}
        $FailureClass=$null
        if ($QueryStatus -ne 'Completed') {
            if ([int64]$Query.Result.ExitCode -eq -2147024894 -or $StandardOutput -match '0x80070002|ERROR_FILE_NOT_FOUND') { $FailureClass='ValueNotFound' }
            elseif ($QueryStatus -eq 'TimedOut') { $FailureClass='TimedOut' }
            elseif ($QueryStatus -eq 'FailedToStart') { $FailureClass='FailedToStart' }
            else { $FailureClass='QueryFailed' }
        }
        $Observations.Add([pscustomobject][ordered]@{
            schemaVersion='1.0';sourceSchema='ADCSCARuntimeConfigurationCollection/1.0.0';normalizerVersion=$PackageVersion
            CaConfiguration=$CaConfiguration;Setting=[string]$Query.Name;EvidenceStatus=$EvidenceStatus;QueryStatus=$QueryStatus
            ExitCode=$Query.Result.ExitCode;EnabledKnownFlags=@($Flags.ToArray());FailureClass=$FailureClass
            StandardOutput=$StandardOutput;StandardError=$StandardError;StartedUtc=$Query.Result.StartedUtc;CompletedUtc=$Query.Result.CompletedUtc
            SourcePath=$RawRuntime
        })
    }
}
if ($Observations.Count -ne 7) { throw "NormalizedObservationCountMismatch: $($Observations.Count)" }
foreach ($SettingName in @('Ping','EditFlags','InterfaceFlags','RequestDisposition','RoleSeparationEnabled','EnrollmentAgentRights','OfficerRights')) {
    $Matches=@($Observations | Where-Object { [string]$_.Setting -eq $SettingName })
    if ($Matches.Count -ne 1) { throw "SettingMultiplicityMismatch [$SettingName]: $($Matches.Count)" }
}
$EditMatches=@($Observations | Where-Object { [string]$_.Setting -eq 'EditFlags' })
$InterfaceMatches=@($Observations | Where-Object { [string]$_.Setting -eq 'InterfaceFlags' })
if ($EditMatches.Count -ne 1) { throw "EditFlagsObservationMultiplicityMismatch: $($EditMatches.Count)" }
if ($InterfaceMatches.Count -ne 1) { throw "InterfaceFlagsObservationMultiplicityMismatch: $($InterfaceMatches.Count)" }
$Edit=$EditMatches[0]
$Interface=$InterfaceMatches[0]
if ($Edit.EvidenceStatus -ne 'Observed' -or $Interface.EvidenceStatus -ne 'Observed') { throw 'CriticalFlagObservationMissing' }
$EditfSan=[bool](@($Edit.EnabledKnownFlags) -contains 'EDITF_ATTRIBUTESUBJECTALTNAME2')
$RpcEncrypted=[bool](@($Interface.EnabledKnownFlags) -contains 'IF_ENFORCEENCRYPTICERTREQUEST')
$Observations.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $NormalizedPath -Encoding UTF8
$NormalizedCheck=@(Read-JsonDocument $NormalizedPath 'Normalized runtime evidence')
if ($NormalizedCheck.Count -ne 7) { throw 'NormalizedRoundTripFailure' }
$ObservedCount=@($NormalizedCheck | Where-Object { [string]$_.EvidenceStatus -eq 'Observed' }).Count
$InconclusiveCount=@($NormalizedCheck | Where-Object { [string]$_.EvidenceStatus -eq 'Inconclusive' }).Count
Write-Step 'OK' "Normalized 7 observations: observed=$ObservedCount, inconclusive=$InconclusiveCount, ESC6 flag=$EditfSan, RPC encryption=$RpcEncrypted." Green

$PipelineWarnings=@()
$Parameters=@{
    TemplateConfigurationPath=$TemplateConfig;TemplateAccessPath=$TemplateAccess;IdentityPrerequisitePath=$Identities
    CaRuntimeObservationPath=$NormalizedPath;FactBuilderPath=$Builder;CatalogPath=$Catalog;CorrelationEnginePath=$Correlation
    OutputRoot=$OutputRoot;Quiet=$Quiet;WarningVariable='PipelineWarnings'
}
if (Test-Path -LiteralPath $Console -PathType Leaf) { $Parameters.ConsoleModulePath=$Console }
Write-Step 'ACTION' 'Running canonical aggregate pipeline with normalized runtime observations.' Yellow
$PipelineOutput=@(& $Runner @Parameters)
if ($PipelineWarnings.Count -gt 0) { throw "PipelineWarnings: $($PipelineWarnings -join '; ')" }

$CurrentFactsPath=Join-Path $OutputRoot 'Facts\adcs-facts.json'
$CurrentTechPath=Join-Path $OutputRoot 'Correlation\adcs-technique-candidates.json'
foreach ($File in @($CurrentFactsPath,$CurrentTechPath)) { Require-File $File $File }
$BaselineFacts=@(Get-Collection (Read-JsonDocument $BaseFacts 'Baseline facts') 'Baseline facts')
$CurrentFacts=@(Get-Collection (Read-JsonDocument $CurrentFactsPath 'Current facts') 'Current facts')
$BaselineTech=@(Read-JsonDocument $BaseTech 'Baseline techniques')
$CurrentTech=@(Read-JsonDocument $CurrentTechPath 'Current techniques')
if ($BaselineFacts.Count -ne 20 -or $CurrentFacts.Count -ne 20) { throw "FactCountMismatch: $($BaselineFacts.Count)/$($CurrentFacts.Count)" }
if ($BaselineTech.Count -ne 16 -or $CurrentTech.Count -ne 16) { throw "TechniqueCountMismatch: $($BaselineTech.Count)/$($CurrentTech.Count)" }

$FactKeyNames=@('factId','FactId','factKey','FactKey','name','Name','prerequisiteId','PrerequisiteId','prerequisite','Prerequisite')
$StateNames=@('state','State','status','Status','value','Value')
$BaselineMap=@{};foreach ($Fact in $BaselineFacts) {$Key=Get-Key $Fact $FactKeyNames;if($null-eq$Key){throw'BaselineFactKeyMissing'};$BaselineMap[$Key]=$Fact}
$CurrentMap=@{};foreach ($Fact in $CurrentFacts) {$Key=Get-Key $Fact $FactKeyNames;if($null-eq$Key){throw'CurrentFactKeyMissing'};$CurrentMap[$Key]=$Fact}
$FactDelta=@()
foreach ($Key in @($BaselineMap.Keys+$CurrentMap.Keys|Sort-Object -Unique)) {
    $Before=$BaselineMap[$Key];$After=$CurrentMap[$Key]
    $BeforeState=Get-Value $Before $StateNames;$AfterState=Get-Value $After $StateNames
    if ([string]$BeforeState -ne [string]$AfterState) { $FactDelta+=,[pscustomobject]@{fact=$Key;baselineState=$BeforeState;currentState=$AfterState;baseline=$Before;current=$After} }
}
$TechniqueDelta=@()
foreach ($Number in 1..16) {
    $Technique="ESC$Number"
    $Before=@($BaselineTech|Where-Object{[string](Get-Value $_ @('technique','Technique','id','Id')) -eq $Technique})[0]
    $After=@($CurrentTech|Where-Object{[string](Get-Value $_ @('technique','Technique','id','Id')) -eq $Technique})[0]
    $BeforeJson=$Before|ConvertTo-Json -Compress -Depth 15;$AfterJson=$After|ConvertTo-Json -Compress -Depth 15
    if ($BeforeJson -ne $AfterJson) { $TechniqueDelta+=,[pscustomobject]@{technique=$Technique;baselineDisposition=Get-Value $Before @('disposition','Disposition','status','Status');currentDisposition=Get-Value $After @('disposition','Disposition','status','Status');baseline=$Before;current=$After} }
}

$FactDeltaPath=Join-Path $OutputRoot 'runtime-fact-state-delta.json'
$TechniqueDeltaPath=Join-Path $OutputRoot 'runtime-technique-delta.json'
$SummaryPath=Join-Path $OutputRoot 'runtime-normalization-correlation-summary.json'
$FactDelta|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $FactDeltaPath -Encoding UTF8
$TechniqueDelta|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $TechniqueDeltaPath -Encoding UTF8
$Summary=[pscustomobject][ordered]@{
    schemaVersion='1.0';packageIdentity=$PackageIdentity;packageVersion=$PackageVersion;status='Completed'
    rawRuntimePath=$RawRuntime;normalizedRuntimePath=$NormalizedPath
    normalization=[pscustomobject]@{observationCount=7;observedCount=$ObservedCount;inconclusiveCount=$InconclusiveCount;editfAttributeSubjectAltName2Observed=$EditfSan;encryptedRpcRequestEnforced=$RpcEncrypted}
    delta=[pscustomobject]@{factStateChangeCount=$FactDelta.Count;changedFacts=@($FactDelta.fact);techniqueRecordChangeCount=$TechniqueDelta.Count;changedTechniques=@($TechniqueDelta.technique)}
    outputs=[pscustomobject]@{facts=$CurrentFactsPath;techniques=$CurrentTechPath;factDelta=$FactDeltaPath;techniqueDelta=$TechniqueDeltaPath}
    tools=[pscustomobject]@{runner=$RunnerInfo;builder=$BuilderInfo;correlation=$CorrelationInfo}
    safety=[pscustomobject]@{networkActivity='None';ledgerChanges='None';certificateActivity='None';authenticationActivity='None';ollamaActivity='None'}
}
$Summary|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$SummaryCheck=Read-JsonDocument $SummaryPath 'Final summary'
if ([string]$SummaryCheck.status -ne 'Completed') { throw 'SummaryValidationFailure' }
Write-Step 'DONE' "Runtime normalization and correlation completed: fact states changed=$($FactDelta.Count), technique records changed=$($TechniqueDelta.Count): $(@($TechniqueDelta.technique)-join', ')." Green
[pscustomobject][ordered]@{
    Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
    NormalizedObservationCount=7;ObservedRuntimeSettingCount=$ObservedCount;InconclusiveRuntimeSettingCount=$InconclusiveCount
    EditfAttributeSubjectAltName2Observed=$EditfSan;EncryptedRpcRequestEnforced=$RpcEncrypted
    FactStateChangeCount=$FactDelta.Count;ChangedFacts=@($FactDelta.fact)
    TechniqueRecordChangeCount=$TechniqueDelta.Count;ChangedTechniques=@($TechniqueDelta.technique)
    OutputRoot=$OutputRoot;SummaryPath=$SummaryPath;NormalizedRuntimePath=$NormalizedPath
    FactDeltaPath=$FactDeltaPath;TechniqueDeltaPath=$TechniqueDeltaPath
    NetworkActivity='None';LedgerChanges='None';CertificateActivity='None';AuthenticationActivity='None';OllamaActivity='None'
}
