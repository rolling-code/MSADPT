<#
.SYNOPSIS
Performs offline ADCS LAN-readiness validation and preserves the pre-LAN MSADPT baseline.
.DESCRIPTION
Read-only preflight for the next controlled LAN session. Verifies required MSADPT components, hashes,
PowerShell parsing, manifests, final 774-route inventory, planner v0.4.1 outputs, engagement evidence,
write access, and CA-runtime disabled state. Creates a hash-verified baseline snapshot, JSON readiness
report, text runbook, and component inventory.

This script never invokes collectors and performs no AD, CA, LDAP, DNS, TCP, SMB, Kerberos,
certificate, authentication, credential/hash replay, Ollama, registry, or ledger operation.
.NOTES
Version: 1.0.1
Package identity: MSADPT-ADCS-LAN-READINESS-BASELINE
Execution class: offline_preflight_and_baseline
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$OutputRoot,
    [switch]$KeepTemporaryWriteTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageVersion = '1.0.1'
$PackageIdentity = 'MSADPT-ADCS-LAN-READINESS-BASELINE'
$ExpectedPlannerHash = '61BC895F956978C8D52FD3D6A002D7E5ED7360D8E29B25463ABA9FE7C1416379'
$ExpectedPlannerTestHash = 'A7B5E1039B1D6251D2AB134536908822994A45DA47C5728D069CFF973CA61228'
$ExpectedCandidateCount = 774
$ExpectedRoutesPerTechnique = 129
$ExpectedTechniques = @('ESC1','ESC2','ESC3','ESC4','ESC13','ESC15')

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSLanReadiness'
}
$BaselineRoot = Join-Path $OutputRoot 'ADCSBaseline-BeforeLanRefresh'
$ReportPath = Join-Path $OutputRoot 'adcs-lan-readiness-report-v101.json'
$RunbookPath = Join-Path $OutputRoot 'adcs-lan-office-runbook-v101.txt'
$InventoryPath = Join-Path $OutputRoot 'adcs-lan-component-inventory-v101.csv'
$BaselineManifestPath = Join-Path $BaselineRoot 'baseline-manifest.json'
$Utf8NoBom = New-Object Text.UTF8Encoding($false)
$Checks = New-Object 'Collections.Generic.List[object]'
$Components = New-Object 'Collections.Generic.List[object]'
$BaselineFiles = New-Object 'Collections.Generic.List[object]'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    Write-Host ('[{0,-5}] {1}' -f $Status,$Message) -ForegroundColor $Color
}

function Add-Check {
    param(
        [string]$Id,
        [ValidateSet('Passed','Warning','Blocked')][string]$Status,
        [string]$Message,
        [string]$Path,
        [string]$Evidence
    )
    $Checks.Add([pscustomobject][ordered]@{
        id=$Id;status=$Status;message=$Message;path=$Path;evidence=$Evidence
    })
    $Color = if ($Status -eq 'Passed') { 'Green' } elseif ($Status -eq 'Warning') { 'DarkYellow' } else { 'Red' }
    Write-Step $Status.ToUpperInvariant() $Message $Color
}

function Test-PowerShellFile {
    param([string]$Path,[string]$Id,[string]$ExpectedHash,[string]$ExpectedVersion)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $Id 'Blocked' "Required PowerShell file is missing: $Path" $Path $null
        return
    }
    $Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    $Tokens = $null
    $ParseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$ParseErrors)
    $ParseStatus = if ($ParseErrors.Count -eq 0) { 'Passed' } else { 'Blocked' }
    $HashStatus = if ([string]::IsNullOrWhiteSpace($ExpectedHash) -or $Hash -eq $ExpectedHash) { 'Passed' } else { 'Blocked' }
    $Text = [IO.File]::ReadAllText($Path)
    $VersionStatus = if ([string]::IsNullOrWhiteSpace($ExpectedVersion) -or $Text -match [regex]::Escape($ExpectedVersion)) { 'Passed' } else { 'Blocked' }
    $Status = if ($ParseStatus -eq 'Blocked' -or $HashStatus -eq 'Blocked' -or $VersionStatus -eq 'Blocked') { 'Blocked' } else { 'Passed' }
    $Evidence = "SHA256=$Hash; ParseErrors=$($ParseErrors.Count); ExpectedVersion=$ExpectedVersion"
    $Components.Add([pscustomobject]@{id=$Id;path=$Path;sha256=$Hash;parseErrorCount=$ParseErrors.Count;expectedHash=$ExpectedHash;expectedVersion=$ExpectedVersion;status=$Status})
    Add-Check $Id $Status "Validated component: $Id" $Path $Evidence
}

function Read-JsonArray {
    param([string]$Path,[string]$Id)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $Id 'Blocked' "Required JSON file is missing: $Path" $Path $null
        return @()
    }
    try {
        $Rows = @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
        Add-Check $Id 'Passed' "JSON parsed successfully: $Id" $Path "Count=$($Rows.Count)"
        return $Rows
    }
    catch {
        Add-Check $Id 'Blocked' "JSON parse failed: $Id" $Path $_.Exception.Message
        return @()
    }
}

function Add-BaselineFile {
    param([string]$SourcePath,[string]$DestinationName,[string]$Id)
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        Add-Check $Id 'Blocked' "Baseline source is missing: $SourcePath" $SourcePath $null
        return
    }
    $DestinationPath = Join-Path $BaselineRoot $DestinationName
    Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force
    $SourceHash = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash.ToUpperInvariant()
    $DestinationHash = (Get-FileHash -LiteralPath $DestinationPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($SourceHash -ne $DestinationHash) {
        Add-Check $Id 'Blocked' "Baseline copy hash mismatch: $DestinationName" $DestinationPath "Source=$SourceHash; Destination=$DestinationHash"
        return
    }
    $FileInfo = Get-Item -LiteralPath $DestinationPath
    $BaselineFiles.Add([pscustomobject][ordered]@{
        id=$Id;sourcePath=$SourcePath;baselinePath=$DestinationPath;size=$FileInfo.Length;sha256=$DestinationHash
    })
    Add-Check $Id 'Passed' "Baseline preserved and hash verified: $DestinationName" $DestinationPath $DestinationHash
}

Write-Step 'START' 'MSADPT ADCS LAN READINESS AND BASELINE PACKAGE v1.0.1' Cyan
Write-Step 'INFO' "Package identity: $PackageIdentity" DarkGray
Write-Step 'INFO' 'Safety mode: offline preflight only; collectors cannot be invoked by this script.' DarkGray

if (-not (Test-Path -LiteralPath $MSADPTRoot -PathType Container)) {
    throw "MSADPTRootNotFound: $MSADPTRoot"
}
New-Item -ItemType Directory -Path $OutputRoot,$BaselineRoot -Force | Out-Null

$WriteTestPath = Join-Path $OutputRoot '.msadpt-write-test.tmp'
try {
    [IO.File]::WriteAllText($WriteTestPath,'MSADPT offline write test',$Utf8NoBom)
    Add-Check 'OutputWritable' 'Passed' 'Output directory write test passed.' $OutputRoot $WriteTestPath
}
catch {
    Add-Check 'OutputWritable' 'Blocked' 'Output directory write test failed.' $OutputRoot $_.Exception.Message
}
finally {
    if (-not $KeepTemporaryWriteTest -and (Test-Path -LiteralPath $WriteTestPath -PathType Leaf)) {
        Remove-Item -LiteralPath $WriteTestPath -Force
    }
}

$PlannerPath = Join-Path $MSADPTRoot 'Analysis\ADCS\Get-MSADPTADCSValidationPlan.ps1'
$PlannerTestPath = Join-Path $MSADPTRoot 'Tests\Offline\Test-MSADPTADCSValidationPlan.ps1'
$ConsolePath = Join-Path $MSADPTRoot 'Common\MSADPT.Console.psm1'
$InventoryFile = Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSUnifiedCandidateInventory-v020\adcs-unified-candidate-inventory-v020.json'
$FinalPlanRoot = Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSFinalValidationPlan'
$IdentityContextFile = Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADIdentityContext\ad-identity-context.json'

Test-PowerShellFile $PlannerPath 'Planner-v0.4.1' $ExpectedPlannerHash 'Version: 0.4.1'
Test-PowerShellFile $PlannerTestPath 'PlannerTest-v1.0.1' $ExpectedPlannerTestHash 'Version: 1.0.1'
Test-PowerShellFile $ConsolePath 'ConsoleModule' $null $null

$InventoryRows = @(Read-JsonArray $InventoryFile 'UnifiedInventory')
if ($InventoryRows.Count -gt 0) {
    $DuplicateIds = @($InventoryRows | Group-Object candidateId | Where-Object { $_.Count -gt 1 })
    $Status = if ($InventoryRows.Count -eq $ExpectedCandidateCount -and $DuplicateIds.Count -eq 0) { 'Passed' } else { 'Blocked' }
    Add-Check 'UnifiedInventoryShape' $Status "Unified inventory count=$($InventoryRows.Count), duplicate groups=$($DuplicateIds.Count)." $InventoryFile "ExpectedCount=$ExpectedCandidateCount"
    foreach ($Technique in $ExpectedTechniques) {
        $Count = @($InventoryRows | Where-Object { [string]$_.technique -eq $Technique }).Count
        $TechniqueStatus = if ($Count -eq $ExpectedRoutesPerTechnique) { 'Passed' } else { 'Blocked' }
        Add-Check "Technique-$Technique" $TechniqueStatus "$Technique route count: $Count" $InventoryFile "Expected=$ExpectedRoutesPerTechnique"
    }
}

$IdentityRows = @(Read-JsonArray $IdentityContextFile 'IdentityContext')
if ($IdentityRows.Count -gt 0) {
    Add-Check 'IdentityContextCount' 'Passed' "Identity context contains $($IdentityRows.Count) records." $IdentityContextFile $null
}

$PlannerSummaryFile = Join-Path $FinalPlanRoot 'adcs-planner-summary.json'
$PlannerSummary = $null
if (Test-Path -LiteralPath $PlannerSummaryFile -PathType Leaf) {
    try {
        $PlannerSummary = Get-Content -LiteralPath $PlannerSummaryFile -Raw | ConvertFrom-Json -ErrorAction Stop
        $SummaryStatus = if ([string]$PlannerSummary.plannerVersion -eq '0.4.1' -and [int]$PlannerSummary.candidateCount -eq 774) { 'Passed' } else { 'Blocked' }
        Add-Check 'PlannerSummary' $SummaryStatus "Planner summary version=$($PlannerSummary.plannerVersion), candidates=$($PlannerSummary.candidateCount)." $PlannerSummaryFile $null
    }
    catch {
        Add-Check 'PlannerSummary' 'Blocked' 'Planner summary could not be parsed.' $PlannerSummaryFile $_.Exception.Message
    }
}
else {
    Add-Check 'PlannerSummary' 'Blocked' 'Final planner summary is missing.' $PlannerSummaryFile $null
}

$RequiredFinalOutputs = @(
    'adcs-validation-plan.json',
    'adcs-validation-plan.csv',
    'adcs-top-candidates.json',
    'adcs-next-lan-plan.json',
    'adcs-planner-summary.json'
)
foreach ($Name in $RequiredFinalOutputs) {
    $Path = Join-Path $FinalPlanRoot $Name
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
        Add-Check "FinalOutput-$Name" 'Passed' "Final planner output found: $Name" $Path $Hash
    }
    else {
        Add-Check "FinalOutput-$Name" 'Blocked' "Final planner output missing: $Name" $Path $null
    }
}

$ManifestFiles = @(Get-ChildItem -LiteralPath $MSADPTRoot -Filter '*.module.json' -File -Recurse -ErrorAction SilentlyContinue)
$DisabledManifestFiles = @(Get-ChildItem -LiteralPath $MSADPTRoot -Filter '*.module.json.disabled' -File -Recurse -ErrorAction SilentlyContinue)
$CARuntimeEnabled = @($ManifestFiles | Where-Object { $_.Name -match 'CARuntime' })
$CARuntimeDisabled = @($DisabledManifestFiles | Where-Object { $_.Name -match 'CARuntime' })
if ($CARuntimeEnabled.Count -gt 0) {
    Add-Check 'CARuntimeManifestState' 'Blocked' 'CA-runtime manifest is enabled. Do not proceed with tomorrow readiness until deliberately reviewed.' $CARuntimeEnabled[0].FullName "EnabledCount=$($CARuntimeEnabled.Count)"
}
elseif ($CARuntimeDisabled.Count -gt 0) {
    Add-Check 'CARuntimeManifestState' 'Passed' 'CA-runtime manifest remains disabled as required.' $CARuntimeDisabled[0].FullName "DisabledCount=$($CARuntimeDisabled.Count)"
}
else {
    Add-Check 'CARuntimeManifestState' 'Warning' 'No CA-runtime manifest was found. Confirm its intended repository location tomorrow.' $MSADPTRoot $null
}

$PrerequisiteCollectors = @(Get-ChildItem -LiteralPath $MSADPTRoot -Filter 'Invoke-MSADPTADCSAttackPathPrerequisiteValidation.ps1' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\.backup-' })
if ($PrerequisiteCollectors.Count -eq 0) {
    Add-Check 'PrerequisiteCollector' 'Blocked' 'ADCS prerequisite collector was not found.' $MSADPTRoot 'Expected v0.1.4'
}
else {
    foreach ($Collector in $PrerequisiteCollectors) {
        Test-PowerShellFile $Collector.FullName 'PrerequisiteCollectorCandidate' $null 'Version: 0.1.4'
    }
}

$SerializationTests = @(Get-ChildItem -LiteralPath $MSADPTRoot -Filter 'Test-MSADPTEvidenceSerialization.ps1' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\.backup-' })
if ($SerializationTests.Count -eq 0) {
    Add-Check 'SerializationTest' 'Blocked' 'Evidence serialization test was not found.' $MSADPTRoot $null
}
else {
    foreach ($SerializationTest in $SerializationTests) {
        Test-PowerShellFile $SerializationTest.FullName 'SerializationTest' $null $null
    }
}

$LedgerCandidates = @(Get-ChildItem -LiteralPath $MSADPTRoot -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ledger' -and $_.FullName -notmatch '\\Generated\\' })
if ($LedgerCandidates.Count -gt 0) {
    Add-Check 'LedgerPresence' 'Passed' "Located $($LedgerCandidates.Count) ledger-related file(s). This script did not read or modify ledger content." $LedgerCandidates[0].DirectoryName $null
}
else {
    Add-Check 'LedgerPresence' 'Warning' 'No ledger-related file was discovered. Confirm the authoritative ledger location tomorrow.' $MSADPTRoot $null
}

$BackupFiles = @(Get-ChildItem -LiteralPath $MSADPTRoot -Filter '*.backup-*' -File -Recurse -ErrorAction SilentlyContinue)
if ($BackupFiles.Count -gt 0) {
    Add-Check 'BackupInventory' 'Warning' "Located $($BackupFiles.Count) backup file(s). They were not deleted." $MSADPTRoot (@($BackupFiles.FullName) -join '; ')
}
else {
    Add-Check 'BackupInventory' 'Passed' 'No timestamped backup files were found.' $MSADPTRoot $null
}

Add-BaselineFile $InventoryFile 'adcs-unified-candidate-inventory-v020.json' 'Baseline-UnifiedInventory'
foreach ($Name in $RequiredFinalOutputs) {
    Add-BaselineFile (Join-Path $FinalPlanRoot $Name) $Name "Baseline-$Name"
}

$BaselineFileArray = @($BaselineFiles | ForEach-Object { $_ })
$ComponentArray = @($Components | ForEach-Object { $_ })

$BaselineManifest = [pscustomobject][ordered]@{
    schemaVersion='1.0'
    packageIdentity=$PackageIdentity
    packageVersion=$PackageVersion
    createdUtc=(Get-Date).ToUniversalTime().ToString('o')
    executionClass='offline_preflight_and_baseline'
    networkActivity='None'
    collectorActivity='None'
    ledgerChanges='None'
    sourceScope='preserved_real_evidence'
    plannerVersion=if($null -ne $PlannerSummary){[string]$PlannerSummary.plannerVersion}else{$null}
    candidateCount=if($null -ne $PlannerSummary){[int]$PlannerSummary.candidateCount}else{$InventoryRows.Count}
    techniqueCounts=[pscustomobject][ordered]@{
        ESC1=@($InventoryRows|Where-Object{[string]$_.technique -eq 'ESC1'}).Count
        ESC2=@($InventoryRows|Where-Object{[string]$_.technique -eq 'ESC2'}).Count
        ESC3=@($InventoryRows|Where-Object{[string]$_.technique -eq 'ESC3'}).Count
        ESC4=@($InventoryRows|Where-Object{[string]$_.technique -eq 'ESC4'}).Count
        ESC13=@($InventoryRows|Where-Object{[string]$_.technique -eq 'ESC13'}).Count
        ESC15=@($InventoryRows|Where-Object{[string]$_.technique -eq 'ESC15'}).Count
    }
    baselineFiles=@($BaselineFileArray)
}
$BaselineManifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $BaselineManifestPath -Encoding UTF8
$ManifestRoundTrip = Get-Content -LiteralPath $BaselineManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
if (@($ManifestRoundTrip.baselineFiles).Count -ne $BaselineFileArray.Count) {
    throw "BaselineManifestCountMismatch: expected $($BaselineFileArray.Count), found $(@($ManifestRoundTrip.baselineFiles).Count)."
}
Add-Check 'BaselineManifest' 'Passed' "Baseline manifest created with $($BaselineFileArray.Count) file records." $BaselineManifestPath ((Get-FileHash -LiteralPath $BaselineManifestPath -Algorithm SHA256).Hash)

$ComponentArray | Export-Csv -LiteralPath $InventoryPath -NoTypeInformation -Encoding UTF8

$BlockedCount = @($Checks | Where-Object { $_.status -eq 'Blocked' }).Count
$WarningCount = @($Checks | Where-Object { $_.status -eq 'Warning' }).Count
$PassedCount = @($Checks | Where-Object { $_.status -eq 'Passed' }).Count
$ReadinessStatus = if ($BlockedCount -eq 0) { 'ReadyForControlledLanValidation' } else { 'BlockedPendingRemediation' }

$Report = [pscustomobject][ordered]@{
    schemaVersion='1.0'
    packageIdentity=$PackageIdentity
    packageVersion=$PackageVersion
    status=$ReadinessStatus
    generatedUtc=(Get-Date).ToUniversalTime().ToString('o')
    msadptRoot=$MSADPTRoot
    outputRoot=$OutputRoot
    safety=[pscustomobject]@{
        networkActivity='None';collectorActivity='None';ledgerChanges='None';certificateActivity='None';ollamaActivity='None'
    }
    summary=[pscustomobject]@{passed=$PassedCount;warnings=$WarningCount;blocked=$BlockedCount}
    baseline=[pscustomobject]@{root=$BaselineRoot;manifest=$BaselineManifestPath;fileCount=$BaselineFileArray.Count}
    checks=@($Checks | ForEach-Object { $_ })
    recommendedNextAction=if($BlockedCount -eq 0){'Tomorrow, explicitly confirm LAN context, rerun this preflight, then begin the controlled v0.1.4 dry-run sequence.'}else{'Resolve blocked readiness checks before executing any collector.'}
}
$Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

$Runbook = @"
MSADPT ADCS CONTROLLED LAN RUNBOOK
Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))
Package: $PackageIdentity v$PackageVersion
Current readiness: $ReadinessStatus

SAFETY BOUNDARY
- This preflight performed no network, AD, CA, LDAP, SMB, Kerberos, certificate, authentication, Ollama, or ledger action.
- Do not enable CA-runtime collection automatically.
- Do not request certificates, test certificate authentication, replay credentials/hashes, or modify CA, templates, or groups.

CONTROLLED OFFICE SEQUENCE
1. Explicitly confirm that Mario is on the authorized ExampleOrg LAN.
2. Rerun this readiness package and require ReadyForControlledLanValidation.
3. Review warnings and preserve the baseline manifest.
4. Confirm the active prerequisite collector is v0.1.4 and the intended manifest is eligible.
5. Archive existing v0.1.3 prerequisite evidence without overwriting it.
6. Run exactly one deterministic prerequisite dry run.
7. Review the dry-run target paths, versions, and intended operations.
8. Execute exactly one approved v0.1.4 prerequisite refresh.
9. Confirm no JSON depth warning or serialization truncation occurred.
10. Run Test-MSADPTEvidenceSerialization.ps1.
11. Validate ledger supersession and evidence counts without deleting prior evidence.
12. Rebuild aggregate facts and identity context.
13. Rebuild candidate inventories and the 774-route unified inventory.
14. Rerun planner v0.4.1.
15. Compare refreshed outputs with ADCSBaseline-BeforeLanRefresh.
16. Review the 34 consolidated evidence actions.
17. Deliberately decide whether CA-runtime collection should be activated.
18. Stop before any active certificate or authentication test unless separately planned.

AUTHORITATIVE BASELINE
- Candidate count: 774
- ESC1: 129
- ESC2: 129
- ESC3: 129
- ESC4: 129
- ESC13: 129
- ESC15: 129
- Planner: v0.4.1
- Planner SHA-256: $ExpectedPlannerHash
- Planner test SHA-256: $ExpectedPlannerTestHash
- Baseline manifest: $BaselineManifestPath

READINESS REPORT
$ReportPath
"@
[IO.File]::WriteAllText($RunbookPath,$Runbook,$Utf8NoBom)

$FinalColor = if ($ReadinessStatus -eq 'ReadyForControlledLanValidation') { 'Green' } else { 'Red' }
Write-Step 'DONE' "Readiness status: $ReadinessStatus; passed=$PassedCount, warnings=$WarningCount, blocked=$BlockedCount" $FinalColor

[pscustomobject][ordered]@{
    Status=$ReadinessStatus
    PackageIdentity=$PackageIdentity
    PackageVersion=$PackageVersion
    PassedCheckCount=$PassedCount
    WarningCheckCount=$WarningCount
    BlockedCheckCount=$BlockedCount
    BaselineFileCount=$BaselineFileArray.Count
    BaselineRoot=$BaselineRoot
    BaselineManifestPath=$BaselineManifestPath
    ReadinessReportPath=$ReportPath
    RunbookPath=$RunbookPath
    ComponentInventoryPath=$InventoryPath
    NetworkActivity='None'
    CollectorActivity='None'
    LedgerChanges='None'
}
