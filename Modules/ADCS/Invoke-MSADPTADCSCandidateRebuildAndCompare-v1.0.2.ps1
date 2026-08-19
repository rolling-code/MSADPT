<#
.SYNOPSIS
Rebuilds candidate-specific ADCS analysis and compares it with the preserved pre-LAN baseline.
.DESCRIPTION
Consumes refreshed prerequisite evidence and preserved template evidence, then runs the canonical
MSADPT identity and candidate-analysis components in dependency order. It creates ESC1/ESC4,
ESC2/ESC15, ESC3/ESC13, a six-technique 774-route unified inventory, planner v0.4.1 output,
a strict snapshot manifest, and a baseline comparison.

Only canonical components under Analysis and Common are used. Test fixtures under Tests are excluded.
CA-runtime, ESC3 runtime, and ESC13 OID evidence are deliberately omitted, so those facts remain
inconclusive rather than being treated as absent.
.NOTES
Version: 1.0.2
Package identity: MSADPT-ADCS-CANDIDATE-REBUILD-AND-COMPARE
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$EngagementPath = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example',
    [string]$AggregateRebuildRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example\analysis\ADCS\EndToEnd-v014-20260817-084053',
    [string]$OutputRoot,
    [ValidateRange(1,1000)][int]$TopCandidateCount = 25,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-ADCS-CANDIDATE-REBUILD-AND-COMPARE'
$PackageVersion = '1.0.2'
$ExpectedRoutesPerTechnique = 129
$ExpectedTotalRoutes = 774
$Warnings = @()

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
    $Tokens=$null;$Errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$Errors)
    if ($Errors.Count -gt 0) { throw "ScriptParseFailure [$Label]: $($Errors.Message -join '; ')" }
    $Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    if (-not [string]::IsNullOrWhiteSpace($ExpectedHash) -and $Hash -ne $ExpectedHash) { throw "ScriptHashMismatch [$Label]: expected $ExpectedHash, found $Hash" }
    [pscustomobject]@{label=$Label;path=$Path;sha256=$Hash}
}

function Invoke-CheckedScript {
    param([string]$Path,[hashtable]$Parameters,[string]$Stage)
    Write-Step 'ACTION' $Stage Yellow
    $LocalWarnings=@()
    $Parameters['WarningVariable']='LocalWarnings'
    $Output=@(& $Path @Parameters)
    if ($LocalWarnings.Count -gt 0) { throw "WarningsDetected [$Stage]: $($LocalWarnings -join '; ')" }
    return $Output
}

function Read-JsonArray {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    try { return @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "JsonParseFailure [$Label]: $($_.Exception.Message)" }
}

function Get-AggregateFactRows {
    param([string]$Path)
    Require-File $Path 'Aggregate ADCS facts'
    try {
        $Document = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "JsonParseFailure [Aggregate ADCS facts]: $($_.Exception.Message)"
    }

    if ($Document -is [array]) {
        return @($Document)
    }

    foreach ($PropertyName in @('facts','Facts','items','Items','records','Records')) {
        $Property = $Document.PSObject.Properties[$PropertyName]
        if ($null -ne $Property) {
            return @($Property.Value)
        }
    }

    if ($null -ne $Document.PSObject.Properties['factCount']) {
        throw "AggregateFactsCollectionMissing: document declares factCount=$($Document.factCount) but no facts collection was found."
    }

    throw 'AggregateFactsSchemaUnsupported: expected a top-level array or a facts collection.'
}

function Find-JsonByShape {
    param([string]$Directory,[string]$Label,[scriptblock]$Predicate)
    $Matches=@()
    foreach($File in @(Get-ChildItem -LiteralPath $Directory -Filter '*.json' -File -Recurse -ErrorAction Stop)) {
        try {
            $Rows=@(Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json -ErrorAction Stop)
            if (& $Predicate $Rows) { $Matches+=,$File.FullName }
        } catch { }
    }
    if ($Matches.Count -ne 1) { throw "JsonShapeDiscoveryMismatch [$Label]: expected 1 match under $Directory, found $($Matches.Count): $($Matches -join '; ')" }
    return $Matches[0]
}

function Get-TerminalObject {
    param([object[]]$Output,[string]$Stage)
    $Terminal=@($Output | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['Status'] -or $null -ne $_.PSObject.Properties['status'] }) | Select-Object -Last 1
    if ($null -eq $Terminal) { throw "TerminalResultMissing [$Stage]" }
    return $Terminal
}

Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
Write-Step 'INFO' 'Offline candidate rebuild; CA-runtime, ESC3 runtime, and ESC13 OID evidence are omitted.' DarkGray

foreach($Directory in @($MSADPTRoot,$EngagementPath,$AggregateRebuildRoot)) {
    if (-not(Test-Path -LiteralPath $Directory -PathType Container)) { throw "RequiredDirectoryMissing: $Directory" }
}

$AnalysisRoot=Join-Path $MSADPTRoot 'Analysis'
$CommonRoot=Join-Path $MSADPTRoot 'Common'
$IdentityBuilder=Join-Path $AnalysisRoot 'Identity\Get-MSADPTADIdentityContext.ps1'
$Esc1Esc4Builder=Join-Path $AnalysisRoot 'ADCS\Convert-MSADPTADCSEvidenceToCandidateFacts.ps1'
$Esc2Esc15Builder=Join-Path $AnalysisRoot 'ADCS\Convert-MSADPTADCSEvidenceToESC2ESC15CandidateFacts.ps1'
$Esc3Esc13Builder=Join-Path $AnalysisRoot 'ADCS\Build-MSADPTADCSESC3ESC13CandidateFacts.ps1'
$Merger=Join-Path $AnalysisRoot 'ADCS\Merge-MSADPTADCSCandidateInventories.ps1'
$Expander=Join-Path $AnalysisRoot 'ADCS\Expand-MSADPTADCSUnifiedCandidateInventory.ps1'
$Planner=Join-Path $AnalysisRoot 'ADCS\Get-MSADPTADCSValidationPlan.ps1'
$SnapshotBuilder=Join-Path $AnalysisRoot 'New-MSADPTAssessmentSnapshotManifest.ps1'
$Comparator=Join-Path $AnalysisRoot 'Compare-MSADPTAssessmentSnapshots.ps1'
$Console=Join-Path $CommonRoot 'MSADPT.Console.psm1'

$Tools=@(
    Validate-Script $IdentityBuilder 'Identity context builder' '28504097229E31FB5D4B32E1979BFD62F82AC5CC3B10FC6234380C4F848912DD'
    Validate-Script $Esc1Esc4Builder 'ESC1/ESC4 builder' '186DDD8EE3B150B9F33743592B236B389820DB94EBFD5FC241929DFA2CFA1A97'
    Validate-Script $Esc2Esc15Builder 'ESC2/ESC15 builder' 'B9970B44E8840CFA0971B1C03EE973F6A050E6A45102F0FF14CDC9CE84D99EFB'
    Validate-Script $Esc3Esc13Builder 'ESC3/ESC13 builder' '8B8E742FDE2D6BDB9AB1CD76B72D52473EF6511838489E8715C72D68DDA5DA23'
    Validate-Script $Merger 'Candidate merger' '271E59B8B3578D0CAB1C8A76881CA7315A1529036A2093623DB576A3992403B8'
    Validate-Script $Expander 'Unified inventory expander' '6BC970594A60A9CC7FD4312490E40093ACF83920AA0A319BE6D7288ABB948A8E'
    Validate-Script $Planner 'Validation planner' '61BC895F956978C8D52FD3D6A002D7E5ED7360D8E29B25463ABA9FE7C1416379'
    Validate-Script $SnapshotBuilder 'Snapshot builder' 'E55167FC965AF92F09621A561B9B43586F567E0BC7DF4528EB62A2A8F204A52F'
    Validate-Script $Comparator 'Snapshot comparator' 'AF5373AD46C84F2F8E8BDD8D3B73B767985AA3CFB8BE4F596EFD4A3E5A8AE792'
)
if(Test-Path -LiteralPath $Console -PathType Leaf){$null=Validate-Script $Console 'Console module' $null}else{$Console=$null}
Write-Step 'OK' 'Canonical component paths, hashes, and syntax validated.' Green

$TemplateConfiguration=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-configuration.json'
$TemplateAccess=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-access.csv'
$IdentityPrerequisites=Join-Path $EngagementPath 'evidence\ADCSAttackPathPrerequisiteValidation\resolved-identity-prerequisites.json'
$AggregateFacts=Join-Path $AggregateRebuildRoot 'Facts\adcs-facts.json'
$BaselineRoot=Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSLanReadiness\ADCSBaseline-BeforeLanRefresh'
$BaselineManifest=Join-Path $BaselineRoot 'baseline-manifest.json'
$BaselineCandidates=Join-Path $BaselineRoot 'adcs-unified-candidate-inventory-v020.json'
$BaselinePlan=Join-Path $BaselineRoot 'adcs-validation-plan.json'
foreach($File in @($TemplateConfiguration,$TemplateAccess,$IdentityPrerequisites,$AggregateFacts,$BaselineManifest,$BaselineCandidates,$BaselinePlan)){Require-File $File $File}

$PrerequisiteRows=@(Read-JsonArray $IdentityPrerequisites 'Refreshed identity prerequisites')
$AggregateFactRows=@(Get-AggregateFactRows $AggregateFacts)
if($PrerequisiteRows.Count -ne 9){throw "RefreshedPrerequisiteCountMismatch: expected 9, found $($PrerequisiteRows.Count)"}
if($AggregateFactRows.Count -ne 20){throw "AggregateFactCountMismatch: expected 20, found $($AggregateFactRows.Count)"}
$NullFactRows = @($AggregateFactRows | Where-Object { $null -eq $_ })
if ($NullFactRows.Count -gt 0) { throw "AggregateFactNullRowsDetected: $($NullFactRows.Count)" }

$FactSchemaRows = @(
    foreach ($Fact in $AggregateFactRows) {
        $PropertyNames = @($Fact.PSObject.Properties.Name | Sort-Object)
        if ($PropertyNames.Count -eq 0) { throw 'AggregateFactWithoutPropertiesDetected' }
        [pscustomobject]@{
            PropertyCount = $PropertyNames.Count
            Schema = $PropertyNames -join '|'
        }
    }
)
$DistinctSchemas = @($FactSchemaRows.Schema | Sort-Object -Unique)
if ($DistinctSchemas.Count -gt 4) {
    throw "AggregateFactSchemaFragmentation: expected a small number of fact shapes, found $($DistinctSchemas.Count)."
}

$FactIdentityProperty = @(
    'factKey','FactKey','key','Key','name','Name','fact','Fact',
    'prerequisite','Prerequisite','prerequisiteId','PrerequisiteId'
) | Where-Object {
    @($AggregateFactRows | Where-Object { $null -ne $_.PSObject.Properties[$_] }).Count -eq $AggregateFactRows.Count
} | Select-Object -First 1

$IdentifiableFactCount = 0
$DuplicateIdentityCount = 0
if ($null -ne $FactIdentityProperty) {
    $FactIdentities = @(
        $AggregateFactRows |
        ForEach-Object { [string]$_.PSObject.Properties[$FactIdentityProperty].Value } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $IdentifiableFactCount = $FactIdentities.Count
    $DuplicateIdentityCount = @($FactIdentities | Group-Object | Where-Object { $_.Count -gt 1 }).Count
    if ($IdentifiableFactCount -ne 20) { throw "AggregateFactIdentityValueMismatch: expected 20 values, found $IdentifiableFactCount." }
    if ($DuplicateIdentityCount -gt 0) { throw "AggregateFactDuplicateIdentities: $DuplicateIdentityCount group(s)." }
}

Write-Step 'OK' "Validated aggregate fact document: 20 logical facts across $($DistinctSchemas.Count) schema shape(s); identity property=$(if($null-ne$FactIdentityProperty){$FactIdentityProperty}else{'not required by downstream candidate pipeline'})." Green

if([string]::IsNullOrWhiteSpace($OutputRoot)){$OutputRoot=Join-Path $EngagementPath ('analysis\ADCS\CandidateRefresh-v014-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
if(Test-Path -LiteralPath $OutputRoot){if(@(Get-ChildItem -LiteralPath $OutputRoot -Force -ErrorAction SilentlyContinue).Count -gt 0){throw "OutputRootNotEmpty: $OutputRoot"}}
$Dirs=@{
 Identity=Join-Path $OutputRoot 'IdentityContext';Esc1Esc4=Join-Path $OutputRoot 'ESC1ESC4';Esc2Esc15=Join-Path $OutputRoot 'ESC2ESC15';Merged=Join-Path $OutputRoot 'MergedFourTechnique';Esc3Esc13=Join-Path $OutputRoot 'ESC3ESC13';Unified=Join-Path $OutputRoot 'UnifiedSixTechnique';Planner=Join-Path $OutputRoot 'Planner';Snapshot=Join-Path $OutputRoot 'Snapshot';Comparison=Join-Path $OutputRoot 'Comparison'
}
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
foreach($Dir in $Dirs.Values){New-Item -ItemType Directory -Path $Dir -Force|Out-Null}

$Common=@{Quiet=$Quiet};if($null-ne$Console){$Common.ConsoleModulePath=$Console}
$Out=Invoke-CheckedScript $Esc1Esc4Builder (@{TemplateConfigurationPath=$TemplateConfiguration;TemplateAccessPath=$TemplateAccess;IdentityPrerequisitePath=$IdentityPrerequisites;OutputDirectory=$Dirs.Esc1Esc4;Quiet=$Quiet;ConsoleModulePath=$Console}) 'Building ESC1/ESC4 candidate facts from refreshed evidence.'
$Esc1Esc4Path=Find-JsonByShape $Dirs.Esc1Esc4 'ESC1/ESC4 candidates' {param($Rows) $Rows.Count -gt 0 -and @($Rows|Where-Object{$null-ne$_.PSObject.Properties['candidateId'] -and [string]$_.technique -in @('ESC1','ESC4')}).Count -eq $Rows.Count}

$Out=Invoke-CheckedScript $IdentityBuilder (@{CandidateFactsPath=$Esc1Esc4Path;IdentityPrerequisitePath=$IdentityPrerequisites;OutputDirectory=$Dirs.Identity;Quiet=$Quiet;ConsoleModulePath=$Console}) 'Rebuilding identity context.'
$IdentityContextPath=Find-JsonByShape $Dirs.Identity 'Identity context' {param($Rows) $Rows.Count -gt 0 -and @($Rows|Where-Object{$null-ne$_.PSObject.Properties['identityReference'] -and $null-ne$_.PSObject.Properties['category']}).Count -eq $Rows.Count}

$Out=Invoke-CheckedScript $Esc2Esc15Builder (@{CandidateFactsPath=$Esc1Esc4Path;TemplateConfigurationPath=$TemplateConfiguration;IdentityContextPath=$IdentityContextPath;OutputDirectory=$Dirs.Esc2Esc15;Quiet=$Quiet;ConsoleModulePath=$Console}) 'Building ESC2/ESC15 candidate facts without runtime evidence.'
$Esc2Esc15Path=Find-JsonByShape $Dirs.Esc2Esc15 'ESC2/ESC15 candidates' {param($Rows) $Rows.Count -gt 0 -and @($Rows|Where-Object{$null-ne$_.PSObject.Properties['candidateId'] -and [string]$_.technique -in @('ESC2','ESC15')}).Count -eq $Rows.Count}

$Out=Invoke-CheckedScript $Merger (@{Esc1Esc4CandidatePath=$Esc1Esc4Path;Esc2Esc15CandidatePath=$Esc2Esc15Path;OutputDirectory=$Dirs.Merged;Quiet=$Quiet}) 'Merging ESC1/ESC2/ESC4/ESC15 candidates.'
$MergedPath=Find-JsonByShape $Dirs.Merged 'Four-technique inventory' {param($Rows) $Rows.Count -eq 516 -and @($Rows.technique|Sort-Object -Unique).Count -eq 4}

$Out=Invoke-CheckedScript $Esc3Esc13Builder (@{UnifiedCandidateInventoryPath=$MergedPath;TemplateConfigurationPath=$TemplateConfiguration;IdentityContextPath=$IdentityContextPath;OutputDirectory=$Dirs.Esc3Esc13;Quiet=$Quiet;ConsoleModulePath=$Console}) 'Building ESC3/ESC13 candidates with missing runtime and OID evidence preserved as inconclusive.'
$Esc3Esc13Path=Find-JsonByShape $Dirs.Esc3Esc13 'ESC3/ESC13 candidates' {param($Rows) $Rows.Count -eq 258 -and @($Rows.technique|Sort-Object -Unique).Count -eq 2}

$Out=Invoke-CheckedScript $Expander (@{ExistingUnifiedInventoryPath=$MergedPath;Esc3Esc13CandidatePath=$Esc3Esc13Path;OutputDirectory=$Dirs.Unified;ExpectedRoutesPerTechnique=$ExpectedRoutesPerTechnique;Quiet=$Quiet}) 'Expanding to the six-technique unified inventory.'
$UnifiedPath=Find-JsonByShape $Dirs.Unified 'Six-technique inventory' {param($Rows) $Rows.Count -eq $ExpectedTotalRoutes -and @($Rows.technique|Sort-Object -Unique).Count -eq 6}
$UnifiedRows=@(Read-JsonArray $UnifiedPath 'Six-technique inventory')
$Duplicates=@($UnifiedRows|Group-Object candidateId|Where-Object{$_.Count -gt 1});if($Duplicates.Count -gt 0){throw "DuplicateCandidateIds: $($Duplicates.Count)"}
foreach($Technique in @('ESC1','ESC2','ESC3','ESC4','ESC13','ESC15')){$Count=@($UnifiedRows|Where-Object{[string]$_.technique -eq $Technique}).Count;if($Count-ne$ExpectedRoutesPerTechnique){throw "TechniqueCountMismatch [$Technique]: $Count"}}

$Out=Invoke-CheckedScript $Planner (@{CandidateInventoryPath=$UnifiedPath;IdentityContextPath=$IdentityContextPath;OutputDirectory=$Dirs.Planner;TopCandidateCount=$TopCandidateCount;Quiet=$Quiet;ConsoleModulePath=$Console}) 'Running planner v0.4.1.'
$PlanPath=Find-JsonByShape $Dirs.Planner 'Validation plan' {param($Rows) $Rows.Count -eq $ExpectedTotalRoutes -and @($Rows|Where-Object{$null-ne$_.PSObject.Properties['priorityBand'] -and $null-ne$_.PSObject.Properties['rank']}).Count -eq $Rows.Count}
$PlanRows=@(Read-JsonArray $PlanPath 'Validation plan')

$SnapshotManifest=Join-Path $Dirs.Snapshot 'post-refresh-manifest.json'
$Out=Invoke-CheckedScript $SnapshotBuilder (@{InputPath=@($Dirs.Identity,$Dirs.Esc1Esc4,$Dirs.Esc2Esc15,$Dirs.Esc3Esc13,$Dirs.Unified,$Dirs.Planner);SnapshotRoot=$OutputRoot;OutputManifestPath=$SnapshotManifest;SnapshotLabel='ADCS post-v0.1.4 candidate refresh';SourceScope='refreshed_real_evidence';FailOnJsonParseError=$true;Quiet=$true}) 'Building strict post-refresh snapshot manifest.'

$Out=Invoke-CheckedScript $Comparator (@{BaselineManifestPath=$BaselineManifest;CurrentManifestPath=$SnapshotManifest;BaselineCandidatePath=$BaselineCandidates;CurrentCandidatePath=$UnifiedPath;BaselinePlanPath=$BaselinePlan;CurrentPlanPath=$PlanPath;OutputDirectory=$Dirs.Comparison;FailOnUnexpectedShrinkage=$true;Quiet=$true}) 'Comparing post-refresh results with the preserved pre-LAN baseline.'
$ComparisonSummaryPath=Join-Path $Dirs.Comparison 'comparison-summary.json'
$Comparison=Get-Content -LiteralPath $ComparisonSummaryPath -Raw|ConvertFrom-Json -ErrorAction Stop

$SummaryPath=Join-Path $OutputRoot 'candidate-refresh-summary.json'
$TechniqueCounts=[ordered]@{};foreach($Technique in @('ESC1','ESC2','ESC3','ESC4','ESC13','ESC15')){$TechniqueCounts[$Technique]=@($UnifiedRows|Where-Object{[string]$_.technique -eq $Technique}).Count}
$Summary=[pscustomobject][ordered]@{
 schemaVersion='1.0';packageIdentity=$PackageIdentity;packageVersion=$PackageVersion;status='Completed';generatedUtc=([DateTime](Get-Date)).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
 inputs=[pscustomobject]@{prerequisiteVersion='0.1.4';prerequisiteCount=$PrerequisiteRows.Count;aggregateFactCount=$AggregateFactRows.Count;aggregateFactSchemaCount=$DistinctSchemas.Count;aggregateFactIdentityProperty=$FactIdentityProperty;caRuntimeEvidence=$null;esc3RuntimeEvidence=$null;esc13OidEvidence=$null}
 outputs=[pscustomobject]@{identityContextPath=$IdentityContextPath;esc1Esc4Path=$Esc1Esc4Path;esc2Esc15Path=$Esc2Esc15Path;esc3Esc13Path=$Esc3Esc13Path;unifiedInventoryPath=$UnifiedPath;validationPlanPath=$PlanPath;snapshotManifestPath=$SnapshotManifest;comparisonSummaryPath=$ComparisonSummaryPath}
 counts=[pscustomobject]@{identityContext=@(Read-JsonArray $IdentityContextPath 'Identity context').Count;candidateCount=$UnifiedRows.Count;techniqueCounts=[pscustomobject]$TechniqueCounts;p1=@($PlanRows|Where-Object{$_.priorityBand-eq'P1'}).Count;p2=@($PlanRows|Where-Object{$_.priorityBand-eq'P2'}).Count;p3=@($PlanRows|Where-Object{$_.priorityBand-eq'P3'}).Count;p4=@($PlanRows|Where-Object{$_.priorityBand-eq'P4'}).Count}
 comparison=$Comparison;safety=[pscustomobject]@{networkActivity='None';collectorActivity='None';ledgerChanges='None';caRuntimeActivity='None';ollamaActivity='None'}
}
$Summary|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$RoundTrip=Get-Content -LiteralPath $SummaryPath -Raw|ConvertFrom-Json -ErrorAction Stop;if([string]$RoundTrip.status-ne'Completed'){throw'FinalSummaryRoundTripFailure'}

Write-Step 'DONE' "Candidate rebuild and comparison completed: candidates=$($UnifiedRows.Count), facts changed=$($Comparison.factChangeCount), priorities changed=$($Comparison.priorityChangeCount)." Green
[pscustomobject][ordered]@{Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;PrerequisiteVersion='0.1.4';IdentityContextCount=$Summary.counts.identityContext;CandidateCount=$UnifiedRows.Count;ESC1Count=$TechniqueCounts.ESC1;ESC2Count=$TechniqueCounts.ESC2;ESC3Count=$TechniqueCounts.ESC3;ESC4Count=$TechniqueCounts.ESC4;ESC13Count=$TechniqueCounts.ESC13;ESC15Count=$TechniqueCounts.ESC15;P1Count=$Summary.counts.p1;P2Count=$Summary.counts.p2;P3Count=$Summary.counts.p3;P4Count=$Summary.counts.p4;FactChangeCount=[int]$Comparison.factChangeCount;DispositionChangeCount=[int]$Comparison.dispositionChangeCount;PriorityChangeCount=[int]$Comparison.priorityChangeCount;CandidateAddedCount=[int]$Comparison.candidateAddedCount;CandidateRemovedCount=[int]$Comparison.candidateRemovedCount;OutputRoot=$OutputRoot;SummaryPath=$SummaryPath;UnifiedInventoryPath=$UnifiedPath;ValidationPlanPath=$PlanPath;ComparisonSummaryPath=$ComparisonSummaryPath;CARuntimeEvidence='Omitted';ESC3RuntimeEvidence='Omitted';ESC13OidEvidence='Omitted';NetworkActivity='None';LedgerChanges='None';OllamaActivity='None'}
