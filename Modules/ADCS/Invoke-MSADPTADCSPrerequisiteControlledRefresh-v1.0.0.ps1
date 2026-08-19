<#
.SYNOPSIS
Archives, executes once, validates, and persists the MSADPT ADCS prerequisite refresh.
.DESCRIPTION
Performs one controlled execution of ADCSAttackPathPrerequisiteValidation v0.1.4 against an explicit
engagement. Before execution, it verifies the collector, manifest, required evidence, BootstrapServer,
existing v0.1.3 module result, and ledger schema. It creates a hash manifest and complete rollback
archive. After exactly one collector invocation, it validates JSON/CSV serialization, writes a new
module-result file, atomically supersedes the v0.1.3 ledger entry, and verifies the persisted state.

The collector is read-only against Active Directory. This script does not request certificates, test
authentication, query CA runtime configuration, modify directory objects, or invoke Ollama.
.NOTES
Version: 1.0.0
Package identity: MSADPT-ADCS-PREREQUISITE-CONTROLLED-REFRESH
Execution class: controlled_read_only_collection_and_local_persistence
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$EngagementPath = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example',
    [PSCredential]$Credential,
    [switch]$KeepRollbackArchive
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageVersion = '1.0.0'
$PackageIdentity = 'MSADPT-ADCS-PREREQUISITE-CONTROLLED-REFRESH'
$ExpectedCollectorHash = '5AEDF727050272B33ED56A32977C76CBDEDBC8B219912B9EC9B07E9B86A392FD'
$ExpectedCollectorVersion = '0.1.4'
$ExpectedManifestVersion = '1.0.4'
$ExpectedPreviousVersion = '0.1.3'
$Utf8NoBom = New-Object Text.UTF8Encoding($false)
$CollectorInvocationCount = 0
$RollbackRequired = $false
$ArchiveEntries = New-Object 'Collections.Generic.List[object]'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    Write-Host ('[{0,-7}] {1}' -f $Status,$Message) -ForegroundColor $Color
}

function Get-Sha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Read-JsonArray {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
    try { return @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "JsonParseFailure [$Label]: $($_.Exception.Message)" }
}

function Set-ObjectProperty {
    param([object]$Object,[string]$Name,[object]$Value)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
    else { $Property.Value = $Value }
}

function Add-ArchiveFile {
    param([string]$SourcePath,[string]$ArchiveRoot,[string]$RelativePath,[string]$Label)
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) { throw "ArchiveSourceMissing [$Label]: $SourcePath" }
    $Destination = Join-Path $ArchiveRoot $RelativePath
    New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $SourcePath -Destination $Destination -Force
    $SourceHash = Get-Sha256 $SourcePath
    $DestinationHash = Get-Sha256 $Destination
    if ($SourceHash -ne $DestinationHash) { throw "ArchiveHashMismatch [$Label]" }
    $Info = Get-Item -LiteralPath $Destination
    $ArchiveEntries.Add([pscustomobject][ordered]@{label=$Label;sourcePath=$SourcePath;archivePath=$Destination;relativePath=$RelativePath;size=[int64]$Info.Length;sha256=$DestinationHash})
}

function Restore-FromArchive {
    param([object[]]$Entries)
    foreach ($Entry in $Entries) {
        if (Test-Path -LiteralPath $Entry.archivePath -PathType Leaf) {
            New-Item -ItemType Directory -Path (Split-Path $Entry.sourcePath -Parent) -Force | Out-Null
            Copy-Item -LiteralPath $Entry.archivePath -Destination $Entry.sourcePath -Force
        }
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'One collector execution maximum; CA-runtime collection remains disabled.' DarkGray

    $CollectorPath = Join-Path $MSADPTRoot 'Modules\ADCSAttackPathPrerequisiteValidation\Invoke-MSADPTADCSAttackPathPrerequisiteValidation.ps1'
    $ManifestPath = Join-Path $MSADPTRoot 'Modules\ADCSAttackPathPrerequisiteValidation\ADCSAttackPathPrerequisiteValidation.module.json'
    $StatePath = Join-Path $EngagementPath 'state\engagement-state.json'
    $LedgerPath = Join-Path $EngagementPath 'state\module-execution-ledger.json'
    $ConfigurationPath = Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-configuration.json'
    $AccessPath = Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-access.csv'
    $OutputDirectory = Join-Path $EngagementPath 'evidence\ADCSAttackPathPrerequisiteValidation'
    $CandidatePath = Join-Path $OutputDirectory 'candidate-principals.json'
    $ResolvedPath = Join-Path $OutputDirectory 'resolved-identity-prerequisites.json'
    $SummaryCsvPath = Join-Path $OutputDirectory 'identity-prerequisite-summary.csv'
    $ReasoningPath = Join-Path $EngagementPath 'reasoning'

    foreach ($Required in @($CollectorPath,$ManifestPath,$StatePath,$LedgerPath,$ConfigurationPath,$AccessPath,$CandidatePath,$ResolvedPath,$SummaryCsvPath)) {
        if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) { throw "RequiredFileMissing: $Required" }
    }

    $CollectorHash = Get-Sha256 $CollectorPath
    if ($CollectorHash -ne $ExpectedCollectorHash) { throw "CollectorHashMismatch: expected $ExpectedCollectorHash, found $CollectorHash" }
    $CollectorText = [IO.File]::ReadAllText($CollectorPath)
    if ($CollectorText -notmatch [regex]::Escape("Version: $ExpectedCollectorVersion")) { throw 'CollectorVersionMarkerMismatch' }
    $Tokens=$null;$ParseErrors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($CollectorPath,[ref]$Tokens,[ref]$ParseErrors)
    if ($ParseErrors.Count -gt 0) { throw "CollectorParseFailure: $($ParseErrors.Message -join '; ')" }

    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ([string]$Manifest.moduleVersion -ne $ExpectedCollectorVersion -or [string]$Manifest.manifestVersion -ne $ExpectedManifestVersion -or [string]$Manifest.executionClass -ne 'read_only') { throw 'ManifestContractMismatch' }
    $Prohibited = @('certificateEnrollment','authenticationTesting','caRuntimeQuery','directoryModification','stateChange')
    foreach ($Operation in $Prohibited) { if ($Operation -notin @($Manifest.doesNotPerform)) { throw "ManifestSafetyBoundaryMissing: $Operation" } }

    $State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    $BootstrapServer = [string]$State.BootstrapServer
    if ([string]::IsNullOrWhiteSpace($BootstrapServer)) { throw 'BootstrapServerMissing' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $Domain = Get-ADDomain -Server $BootstrapServer -ErrorAction Stop
    Write-Step 'OK' "Bootstrap server validated: $BootstrapServer ($($Domain.DNSRoot), $($Domain.DomainMode))." Green

    $Configuration = @(Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    $AccessRows = @(Import-Csv -LiteralPath $AccessPath -ErrorAction Stop)
    if ($Configuration.Count -eq 0 -or $AccessRows.Count -eq 0) { throw 'RequiredEvidenceEmpty' }

    $Ledger = @(Get-Content -LiteralPath $LedgerPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($Ledger.Count -eq 0) { throw 'LedgerEmpty' }
    $PreviousEntries = @($Ledger | Where-Object { [string]$_.module -eq 'ADCSAttackPathPrerequisiteValidation' -and [string]$_.moduleVersion -eq $ExpectedPreviousVersion -and -not [bool]$_.superseded })
    if ($PreviousEntries.Count -ne 1) { throw "ActivePreviousLedgerEntryMismatch: expected 1 active v$ExpectedPreviousVersion entry, found $($PreviousEntries.Count)" }
    $PreviousEntry = $PreviousEntries[0]
    $IdPropertyName = @('ledgerId','id','entryId') | Where-Object { $null -ne $PreviousEntry.PSObject.Properties[$_] } | Select-Object -First 1
    if ($null -eq $IdPropertyName) { throw 'LedgerIdPropertyNotDetected' }
    $PreviousLedgerId = [string]$PreviousEntry.PSObject.Properties[$IdPropertyName].Value
    if ([string]::IsNullOrWhiteSpace($PreviousLedgerId)) { throw 'PreviousLedgerIdEmpty' }

    $PreviousResults = @(
        Get-ChildItem -LiteralPath $ReasoningPath -Filter 'module-result-*.json' -File -ErrorAction Stop |
        ForEach-Object {
            try {
                $Object = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                if ([string]$Object.module -eq 'ADCSAttackPathPrerequisiteValidation' -and [string]$Object.moduleVersion -eq $ExpectedPreviousVersion) {
                    [pscustomobject]@{File=$_;Object=$Object}
                }
            } catch { }
        } |
        Where-Object { $null -ne $_ }
    )
    if ($PreviousResults.Count -eq 0) { throw 'PreviousModuleResultNotFound' }
    $PreviousResult = $PreviousResults | Sort-Object { $_.File.LastWriteTimeUtc } -Descending | Select-Object -First 1

    $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
    $ArchiveRoot = Join-Path $EngagementPath "archive\ADCSAttackPathPrerequisiteValidation\pre-v014-$Timestamp"
    New-Item -ItemType Directory -Path $ArchiveRoot -Force | Out-Null
    Add-ArchiveFile $CandidatePath $ArchiveRoot 'evidence\candidate-principals.json' 'Candidate evidence v0.1.3'
    Add-ArchiveFile $ResolvedPath $ArchiveRoot 'evidence\resolved-identity-prerequisites.json' 'Resolved evidence v0.1.3'
    Add-ArchiveFile $SummaryCsvPath $ArchiveRoot 'evidence\identity-prerequisite-summary.csv' 'Summary evidence v0.1.3'
    Add-ArchiveFile $LedgerPath $ArchiveRoot 'state\module-execution-ledger.json' 'Ledger before v0.1.4'
    Add-ArchiveFile $PreviousResult.File.FullName $ArchiveRoot "reasoning\$($PreviousResult.File.Name)" 'Module result v0.1.3'
    $ArchiveManifestPath = Join-Path $ArchiveRoot 'archive-manifest.json'
    [pscustomobject][ordered]@{schemaVersion='1.0';packageIdentity=$PackageIdentity;createdUtc=([DateTime](Get-Date)).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture);engagementPath=$EngagementPath;previousModuleVersion=$ExpectedPreviousVersion;targetModuleVersion=$ExpectedCollectorVersion;collectorSha256=$CollectorHash;entries=@($ArchiveEntries|ForEach-Object{$_})} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ArchiveManifestPath -Encoding UTF8
    $ManifestRoundTrip = Get-Content -LiteralPath $ArchiveManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if (@($ManifestRoundTrip.entries).Count -ne $ArchiveEntries.Count) { throw 'ArchiveManifestRoundTripFailure' }
    Write-Step 'OK' "Rollback archive created and verified: $ArchiveRoot" Green
    $RollbackRequired = $true

    $Warnings = @()
    $CollectorInvocationCount++
    if ($CollectorInvocationCount -ne 1) { throw 'CollectorInvocationCountGuardTriggered' }
    Write-Step 'ACTION' "Executing collector v$ExpectedCollectorVersion exactly once against $BootstrapServer." Yellow
    $CollectorParameters = @{EngagementPath=$EngagementPath;WarningVariable='Warnings'}
    if ($null -ne $Credential) { $CollectorParameters['Credential']=$Credential }
    $CollectorOutput = @(& $CollectorPath @CollectorParameters)
    $Result = @($CollectorOutput | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['module'] -and [string]$_.module -eq 'ADCSAttackPathPrerequisiteValidation' -and [string]$_.status -eq 'Completed' }) | Select-Object -Last 1
    if ($null -eq $Result) { throw 'CollectorTerminalResultMissing' }
    if ([string]$Result.moduleVersion -ne $ExpectedCollectorVersion -or [string]$Result.analysisVersion -ne '1.2.0' -or [string]$Result.executionClass -ne 'read_only') { throw 'CollectorTerminalContractMismatch' }
    if ($Warnings.Count -gt 0) { throw "CollectorWarningsDetected: $($Warnings -join '; ')" }

    foreach ($OutputPath in @($CandidatePath,$ResolvedPath,$SummaryCsvPath)) {
        if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) { throw "CollectorOutputMissing: $OutputPath" }
        if ((Get-Item -LiteralPath $OutputPath).Length -eq 0) { throw "CollectorOutputEmpty: $OutputPath" }
    }
    $CandidateRows = @(Get-Content -LiteralPath $CandidatePath -Raw | ConvertFrom-Json -ErrorAction Stop)
    $ResolvedRows = @(Get-Content -LiteralPath $ResolvedPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    $SummaryRows = @(Import-Csv -LiteralPath $SummaryCsvPath -ErrorAction Stop)
    $UniqueCandidatePrincipals = @($CandidateRows.IdentityReference | Sort-Object -Unique)
    if ($UniqueCandidatePrincipals.Count -ne [int]$Result.candidatePrincipalCount) { throw "CandidatePrincipalCountMismatch: file=$($UniqueCandidatePrincipals.Count), result=$($Result.candidatePrincipalCount)" }
    if ($ResolvedRows.Count -ne [int]$Result.targetCount -or $SummaryRows.Count -ne [int]$Result.targetCount) { throw "ResolvedOutputCountMismatch: JSON=$($ResolvedRows.Count), CSV=$($SummaryRows.Count), target=$($Result.targetCount)" }
    if ([int]$Result.serializationDepth -ne 8) { throw 'UnexpectedSerializationDepth' }
    $RequiredResolvedProperties = @('IdentityReference','ResolutionStatus','DirectMembers','RecursiveMembers','ControlEntries','Limitations')
    foreach ($Row in $ResolvedRows) {
        foreach ($PropertyName in $RequiredResolvedProperties) {
            if ($null -eq $Row.PSObject.Properties[$PropertyName]) { throw "ResolvedSchemaPropertyMissing [$($Row.IdentityReference)]: $PropertyName" }
        }
        foreach ($ArrayProperty in @('DirectMembers','RecursiveMembers','ControlEntries','Limitations')) {
            $null = @($Row.PSObject.Properties[$ArrayProperty].Value)
        }
    }
    Write-Step 'OK' "Serialization validated: candidates=$($UniqueCandidatePrincipals.Count), resolved=$($ResolvedRows.Count), CSV=$($SummaryRows.Count)." Green

    New-Item -ItemType Directory -Path $ReasoningPath -Force | Out-Null
    $ResultTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $NewResultPath = Join-Path $ReasoningPath "module-result-$ResultTimestamp.json"
    if (Test-Path -LiteralPath $NewResultPath) { throw "ModuleResultCollision: $NewResultPath" }
    $Result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $NewResultPath -Encoding UTF8
    $PersistedResult = Get-Content -LiteralPath $NewResultPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ([string]$PersistedResult.moduleVersion -ne $ExpectedCollectorVersion -or [string]$PersistedResult.status -ne 'Completed') { throw 'ModuleResultPersistenceValidationFailed' }

    $NewLedgerId = 'ledger-' + [Guid]::NewGuid().ToString('N')
    $NewEntry = ($PreviousEntry | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
    Set-ObjectProperty $NewEntry $IdPropertyName $NewLedgerId
    Set-ObjectProperty $NewEntry 'moduleVersion' $ExpectedCollectorVersion
    Set-ObjectProperty $NewEntry 'analysisVersion' ([string]$Result.analysisVersion)
    Set-ObjectProperty $NewEntry 'status' 'Completed'
    Set-ObjectProperty $NewEntry 'executionClass' 'read_only'
    Set-ObjectProperty $NewEntry 'evidence' @($Result.evidence)
    Set-ObjectProperty $NewEntry 'completedUtc' ([string]$Result.completedUtc)
    Set-ObjectProperty $NewEntry 'superseded' $false
    Set-ObjectProperty $NewEntry 'supersededBy' $null
    Set-ObjectProperty $NewEntry 'refreshReason' "Collector upgraded from $ExpectedPreviousVersion to $ExpectedCollectorVersion"
    foreach ($CountName in @('candidateTemplateCount','candidatePrincipalCount','resolvedPrincipalCount','wellKnownPrincipalCount','unresolvedPrincipalCount','targetCount','serializationDepth')) {
        if ($null -ne $Result.PSObject.Properties[$CountName]) { Set-ObjectProperty $NewEntry $CountName $Result.PSObject.Properties[$CountName].Value }
    }
    Set-ObjectProperty $PreviousEntry 'superseded' $true
    Set-ObjectProperty $PreviousEntry 'supersededBy' $NewLedgerId
    $UpdatedLedger = @($Ledger) + @($NewEntry)
    $LedgerTempPath = "$LedgerPath.tmp-$Timestamp"
    $UpdatedLedger | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $LedgerTempPath -Encoding UTF8
    $ValidatedLedger = @(Get-Content -LiteralPath $LedgerTempPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    $NewEntries = @($ValidatedLedger | Where-Object { [string]$_.module -eq 'ADCSAttackPathPrerequisiteValidation' -and [string]$_.moduleVersion -eq $ExpectedCollectorVersion -and -not [bool]$_.superseded })
    $OldEntries = @($ValidatedLedger | Where-Object { [string]$_.module -eq 'ADCSAttackPathPrerequisiteValidation' -and [string]$_.moduleVersion -eq $ExpectedPreviousVersion })
    if ($ValidatedLedger.Count -ne ($Ledger.Count + 1) -or $NewEntries.Count -ne 1 -or @($OldEntries | Where-Object { [bool]$_.superseded -and [string]$_.supersededBy -eq $NewLedgerId }).Count -ne 1) { throw 'LedgerSupersessionValidationFailed' }
    Move-Item -LiteralPath $LedgerTempPath -Destination $LedgerPath -Force
    $FinalLedger = @(Get-Content -LiteralPath $LedgerPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($FinalLedger.Count -ne ($Ledger.Count + 1)) { throw 'FinalLedgerCountMismatch' }
    Write-Step 'OK' "Ledger atomically updated: records $($Ledger.Count) -> $($FinalLedger.Count); v$ExpectedPreviousVersion superseded by $NewLedgerId." Green

    $RollbackRequired = $false
    $PostManifestPath = Join-Path $ArchiveRoot 'post-refresh-manifest.json'
    $PostFiles = @($CandidatePath,$ResolvedPath,$SummaryCsvPath,$NewResultPath,$LedgerPath)
    $PostRows = @($PostFiles | ForEach-Object { $Info=Get-Item -LiteralPath $_;[pscustomobject]@{path=$_.ToString();size=[int64]$Info.Length;sha256=Get-Sha256 $_;lastWriteTimeUtc=([DateTime]$Info.LastWriteTimeUtc).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)} })
    [pscustomobject][ordered]@{schemaVersion='1.0';status='Completed';collectorInvocationCount=$CollectorInvocationCount;collectorResult=$Result;archiveRoot=$ArchiveRoot;newModuleResultPath=$NewResultPath;ledgerPath=$LedgerPath;newLedgerId=$NewLedgerId;postRefreshFiles=$PostRows} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $PostManifestPath -Encoding UTF8

    Write-Step 'DONE' 'Controlled prerequisite refresh completed and persisted successfully.' Green
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        CollectorVersion=$ExpectedCollectorVersion;AnalysisVersion=[string]$Result.analysisVersion
        CollectorInvocationCount=$CollectorInvocationCount;EngagementPath=$EngagementPath;BootstrapServer=$BootstrapServer
        CandidateTemplateCount=[int]$Result.candidateTemplateCount;CandidatePrincipalCount=[int]$Result.candidatePrincipalCount
        ResolvedPrincipalCount=[int]$Result.resolvedPrincipalCount;WellKnownPrincipalCount=[int]$Result.wellKnownPrincipalCount
        UnresolvedPrincipalCount=[int]$Result.unresolvedPrincipalCount;TargetCount=[int]$Result.targetCount
        LedgerRecordCountBefore=$Ledger.Count;LedgerRecordCountAfter=$FinalLedger.Count;NewLedgerId=$NewLedgerId
        RollbackArchive=$ArchiveRoot;ArchiveManifestPath=$ArchiveManifestPath;PostRefreshManifestPath=$PostManifestPath
        NewModuleResultPath=$NewResultPath;NetworkActivity='Read-only Active Directory queries';DirectoryChanges='None'
        CertificateActivity='None';CARuntimeActivity='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    if ($RollbackRequired) {
        Write-Step 'ROLLBACK' 'Restoring archived evidence, ledger, and prior module result.' DarkYellow
        try { Restore-FromArchive @($ArchiveEntries | ForEach-Object { $_ }); Write-Step 'OK' 'Rollback completed.' Green }
        catch { Write-Step 'FAIL' "RollbackFailure: $($_.Exception.Message)" Red }
    }
    throw
}
