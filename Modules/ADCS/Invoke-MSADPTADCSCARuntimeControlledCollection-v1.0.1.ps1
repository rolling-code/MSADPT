<#
.SYNOPSIS
Runs one controlled, read-only MSADPT AD CS CA-runtime collection.
.DESCRIPTION
Validates the canonical CA-runtime collector v0.1.1 and disabled manifest v1.0.1, confirms the
engagement and enterprise CA targets, archives any existing runtime evidence plus the ledger, invokes
the collector exactly once with bounded timeouts, validates all JSON and CSV outputs, persists a
module-result file, and atomically creates or supersedes the corresponding ledger entry.

The disabled manifest remains disabled. The operation performs LDAP discovery, bounded TCP checks,
and read-only certutil queries. It does not submit certificate requests, authenticate with
certificates, modify the registry, change CA configuration, restart services, modify Active Directory,
or invoke Ollama.
.NOTES
Version: 1.0.1
Package identity: MSADPT-ADCS-CA-RUNTIME-CONTROLLED-COLLECTION
Execution class: controlled_read_only_collection_and_local_persistence
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$EngagementPath = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example',
    [ValidateRange(1,30)][int]$TcpTimeoutSeconds = 3,
    [ValidateRange(5,120)][int]$CommandTimeoutSeconds = 20,
    [PSCredential]$Credential
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-ADCS-CA-RUNTIME-CONTROLLED-COLLECTION'
$PackageVersion = '1.0.1'
$ExpectedCollectorVersion = '0.1.1'
$ExpectedManifestVersion = '1.0.1'
$ExpectedCollectorHash = '5C029D085017F85062618D4BFAD0128F838D1972E3ABF7FEB21FA1CBA87E59E9'
$Utf8NoBom = New-Object Text.UTF8Encoding($false)
$InvocationCount = 0
$ArchiveEntries = New-Object 'Collections.Generic.List[object]'
$RollbackRequired = $false
$PreexistingOutputPaths = @{}

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    Write-Host ('[{0,-8}] {1}' -f $Status,$Message) -ForegroundColor $Color
}

function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Require-File {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
}

function Set-ObjectProperty {
    param([object]$Object,[string]$Name,[object]$Value)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
    else { $Property.Value = $Value }
}

function Add-ArchiveFile {
    param([string]$Source,[string]$ArchiveRoot,[string]$Relative,[string]$Label)
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return }
    $Destination = Join-Path $ArchiveRoot $Relative
    New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    $SourceHash = Get-Sha256 $Source
    $DestinationHash = Get-Sha256 $Destination
    if ($SourceHash -ne $DestinationHash) { throw "ArchiveHashMismatch [$Label]" }
    $Info = Get-Item -LiteralPath $Destination
    $ArchiveEntries.Add([pscustomobject]@{label=$Label;sourcePath=$Source;archivePath=$Destination;relativePath=$Relative;size=[int64]$Info.Length;sha256=$DestinationHash})
}

function Restore-Archive {
    foreach ($Entry in @($ArchiveEntries | ForEach-Object { $_ })) {
        if (Test-Path -LiteralPath $Entry.archivePath -PathType Leaf) {
            New-Item -ItemType Directory -Path (Split-Path $Entry.sourcePath -Parent) -Force | Out-Null
            Copy-Item -LiteralPath $Entry.archivePath -Destination $Entry.sourcePath -Force
        }
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Manifest remains disabled; one direct collector invocation maximum.' DarkGray

    $ModuleRoot = Join-Path $MSADPTRoot 'Modules\ADCSCARuntimeConfigurationCollection'
    $CollectorPath = Join-Path $ModuleRoot 'Invoke-MSADPTADCSCARuntimeConfigurationCollection.ps1'
    $DisabledManifestPath = Join-Path $ModuleRoot 'ADCSCARuntimeConfigurationCollection.module.json.disabled'
    $EnabledManifestPath = Join-Path $ModuleRoot 'ADCSCARuntimeConfigurationCollection.module.json'
    $StatePath = Join-Path $EngagementPath 'state\engagement-state.json'
    $LedgerPath = Join-Path $EngagementPath 'state\module-execution-ledger.json'
    $ReasoningPath = Join-Path $EngagementPath 'reasoning'
    $OutputDirectory = Join-Path $EngagementPath 'evidence\ADCSCARuntimeConfigurationCollection'
    $RuntimeEvidencePath = Join-Path $OutputDirectory 'ca-runtime-evidence.json'
    $RuntimeSummaryPath = Join-Path $OutputDirectory 'ca-runtime-summary.csv'
    $ServiceEvidencePath = Join-Path $OutputDirectory 'adcs-service-connection-points.json'

    foreach ($Required in @($CollectorPath,$DisabledManifestPath,$StatePath,$LedgerPath)) { Require-File $Required $Required }
    if (Test-Path -LiteralPath $EnabledManifestPath -PathType Leaf) { throw "EnabledManifestDetected: $EnabledManifestPath" }

    $CollectorHash = Get-Sha256 $CollectorPath
    if ($CollectorHash -ne $ExpectedCollectorHash) { throw "CollectorHashMismatch: expected $ExpectedCollectorHash, found $CollectorHash" }
    $Tokens=$null;$ParseErrors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($CollectorPath,[ref]$Tokens,[ref]$ParseErrors)
    if ($ParseErrors.Count -gt 0) { throw "CollectorParseFailure: $($ParseErrors.Message -join '; ')" }
    $CollectorText = [IO.File]::ReadAllText($CollectorPath)
    if ($CollectorText -notmatch [regex]::Escape("Version: $ExpectedCollectorVersion")) { throw 'CollectorVersionMarkerMismatch' }

    $Manifest = Get-Content -LiteralPath $DisabledManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ([string]$Manifest.moduleVersion -ne $ExpectedCollectorVersion -or [string]$Manifest.manifestVersion -ne $ExpectedManifestVersion -or [string]$Manifest.executionClass -ne 'read_only') { throw 'DisabledManifestContractMismatch' }
    foreach ($Operation in @('certificateEnrollment','certificateRequestSubmission','authenticationTesting','caRuntimeModification','registryModification','serviceRestart','directoryModification','exploitValidation','stateChange')) {
        if ($Operation -notin @($Manifest.doesNotPerform)) { throw "ManifestSafetyBoundaryMissing: $Operation" }
    }

    $State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    $BootstrapServer = [string]$State.BootstrapServer
    if ([string]::IsNullOrWhiteSpace($BootstrapServer)) { throw 'BootstrapServerMissing' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $RootDse = Get-ADRootDSE -Server $BootstrapServer -ErrorAction Stop
    $EnrollmentBase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $RootDse.ConfigurationNamingContext
    $CaObjects = @(Get-ADObject -SearchBase $EnrollmentBase -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName,cn,certificateTemplates -Server $BootstrapServer -ErrorAction Stop)
    if ($CaObjects.Count -eq 0) { throw 'NoEnterpriseCAsDiscovered' }
    $CaTargets = @($CaObjects | ForEach-Object { [pscustomobject]@{name=[string]$_.Name;dnsHostName=[string]$_.dNSHostName;publishedTemplateCount=@($_.certificateTemplates).Count} })
    foreach ($Target in $CaTargets) { if ([string]::IsNullOrWhiteSpace($Target.dnsHostName)) { throw "CADnsHostNameMissing: $($Target.name)" } }
    Write-Step 'OK' "Discovered $($CaTargets.Count) enterprise CA target(s): $($CaTargets.dnsHostName -join ', ')." Green

    $Ledger = @(Get-Content -LiteralPath $LedgerPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($Ledger.Count -eq 0) { throw 'LedgerEmpty' }
    $ActiveRuntimeEntries = @($Ledger | Where-Object { [string]$_.module -eq 'ADCSCARuntimeConfigurationCollection' -and -not [bool]$_.superseded })
    if ($ActiveRuntimeEntries.Count -gt 1) { throw "MultipleActiveRuntimeLedgerEntries: $($ActiveRuntimeEntries.Count)" }

    foreach ($TrackedOutputPath in @($RuntimeEvidencePath,$RuntimeSummaryPath,$ServiceEvidencePath)) {
        $PreexistingOutputPaths[$TrackedOutputPath] = Test-Path -LiteralPath $TrackedOutputPath -PathType Leaf
    }

    $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
    $ArchiveRoot = Join-Path $EngagementPath "archive\ADCSCARuntimeConfigurationCollection\pre-v011-$Timestamp"
    New-Item -ItemType Directory -Path $ArchiveRoot -Force | Out-Null
    Add-ArchiveFile $LedgerPath $ArchiveRoot 'state\module-execution-ledger.json' 'Ledger before runtime collection'
    Add-ArchiveFile $RuntimeEvidencePath $ArchiveRoot 'evidence\ca-runtime-evidence.json' 'Prior runtime evidence'
    Add-ArchiveFile $RuntimeSummaryPath $ArchiveRoot 'evidence\ca-runtime-summary.csv' 'Prior runtime summary'
    Add-ArchiveFile $ServiceEvidencePath $ArchiveRoot 'evidence\adcs-service-connection-points.json' 'Prior service evidence'
    if ($ActiveRuntimeEntries.Count -eq 1) {
        $ActiveVersion = [string]$ActiveRuntimeEntries[0].moduleVersion
        $PreviousResults = @(
            Get-ChildItem -LiteralPath $ReasoningPath -Filter 'module-result-*.json' -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    $Object=Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json -ErrorAction Stop
                    if ([string]$Object.module -eq 'ADCSCARuntimeConfigurationCollection' -and [string]$Object.moduleVersion -eq $ActiveVersion) {[pscustomobject]@{File=$_;Object=$Object}}
                } catch { }
            } | Where-Object { $null -ne $_ } | Sort-Object {$_.File.LastWriteTimeUtc} -Descending
        )
        if ($PreviousResults.Count -gt 0) { Add-ArchiveFile $PreviousResults[0].File.FullName $ArchiveRoot "reasoning\$($PreviousResults[0].File.Name)" 'Prior runtime module result' }
    }
    $ArchiveManifestPath = Join-Path $ArchiveRoot 'archive-manifest.json'
    [pscustomobject]@{schemaVersion='1.0';createdUtc=([DateTime](Get-Date)).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture);packageIdentity=$PackageIdentity;collectorSha256=$CollectorHash;caTargets=$CaTargets;entries=@($ArchiveEntries|ForEach-Object{$_})} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ArchiveManifestPath -Encoding UTF8
    $ArchiveCheck=Get-Content -LiteralPath $ArchiveManifestPath -Raw|ConvertFrom-Json -ErrorAction Stop
    if (@($ArchiveCheck.entries).Count -ne $ArchiveEntries.Count) { throw 'ArchiveManifestRoundTripFailure' }
    $RollbackRequired=$true
    Write-Step 'OK' "Rollback archive created: $ArchiveRoot" Green

    $InvocationCount++
    if ($InvocationCount -ne 1) { throw 'CollectorInvocationGuardTriggered' }
    $CollectorWarnings=@()
    $Parameters=@{EngagementPath=$EngagementPath;TcpTimeoutSeconds=$TcpTimeoutSeconds;CommandTimeoutSeconds=$CommandTimeoutSeconds;WarningVariable='CollectorWarnings'}
    if($null-ne$Credential){$Parameters.Credential=$Credential}
    Write-Step 'ACTION' "Executing collector v$ExpectedCollectorVersion once; TCP timeout=${TcpTimeoutSeconds}s, command timeout=${CommandTimeoutSeconds}s." Yellow
    $CollectorOutput=@(& $CollectorPath @Parameters)
    $Result=@($CollectorOutput|Where-Object{$null-ne$_ -and $null-ne$_.PSObject.Properties['module'] -and [string]$_.module -eq 'ADCSCARuntimeConfigurationCollection' -and [string]$_.status -eq 'Completed'})|Select-Object -Last 1
    if($null-eq$Result){throw'CollectorTerminalResultMissing'}
    if([string]$Result.moduleVersion-ne$ExpectedCollectorVersion -or [string]$Result.executionClass-ne'read_only'){throw'CollectorTerminalContractMismatch'}
    if($CollectorWarnings.Count-gt0){throw"CollectorWarningsDetected: $($CollectorWarnings-join'; ')"}

    foreach($OutputPath in @($RuntimeEvidencePath,$RuntimeSummaryPath)){
        Require-File $OutputPath $OutputPath
        if((Get-Item -LiteralPath $OutputPath).Length-eq0){throw "CollectorOutputEmpty: $OutputPath"}
    }

    $ServiceEvidenceNormalized = $false
    if (-not (Test-Path -LiteralPath $ServiceEvidencePath -PathType Leaf)) {
        # PowerShell produces no pipeline output for an empty collection, so Set-Content is never invoked.
        # Persist an explicit empty JSON array to distinguish zero discovered SCPs from collection failure.
        [IO.File]::WriteAllText($ServiceEvidencePath,"[]`n",$Utf8NoBom)
        $ServiceEvidenceNormalized = $true
        Write-Step 'INFO' 'No AD CS service connection points were returned; normalized evidence to an empty JSON array.' DarkGray
    }
    if((Get-Item -LiteralPath $ServiceEvidencePath).Length-eq0){throw "CollectorOutputEmpty: $ServiceEvidencePath"}

    $RuntimeRows=@(Get-Content -LiteralPath $RuntimeEvidencePath -Raw|ConvertFrom-Json -ErrorAction Stop)
    $ServiceRows=@(Get-Content -LiteralPath $ServiceEvidencePath -Raw|ConvertFrom-Json -ErrorAction Stop)
    $SummaryRows=@(Import-Csv -LiteralPath $RuntimeSummaryPath -ErrorAction Stop)
    if($RuntimeRows.Count-ne$CaTargets.Count -or $SummaryRows.Count-ne$CaTargets.Count){throw"CARowCountMismatch: targets=$($CaTargets.Count), runtime=$($RuntimeRows.Count), summary=$($SummaryRows.Count)"}
    $TotalQueries=0;$CompletedQueries=0;$FailedQueries=0
    foreach($Row in $RuntimeRows){
        if($null-eq$Row.PSObject.Properties['CertutilQueries']){throw"RuntimeSchemaMissingCertutilQueries: $($Row.CaConfiguration)"}
        $Queries=@($Row.CertutilQueries);$TotalQueries+=$Queries.Count
        foreach($Query in $Queries){if([string]$Query.Result.Status-eq'Completed'){$CompletedQueries++}else{$FailedQueries++}}
    }
    if($TotalQueries-ne($CaTargets.Count*7)){throw"UnexpectedQueryCount: expected $($CaTargets.Count*7), found $TotalQueries"}
    Write-Step 'OK' "Runtime evidence validated: CAs=$($RuntimeRows.Count), queries=$TotalQueries, completed=$CompletedQueries, non-completed=$FailedQueries." Green

    New-Item -ItemType Directory -Path $ReasoningPath -Force|Out-Null
    $ResultPath=Join-Path $ReasoningPath ('module-result-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')
    if(Test-Path -LiteralPath $ResultPath){throw"ModuleResultCollision: $ResultPath"}
    $Result|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $ResultPath -Encoding UTF8
    $Persisted=Get-Content -LiteralPath $ResultPath -Raw|ConvertFrom-Json -ErrorAction Stop
    if([string]$Persisted.moduleVersion-ne$ExpectedCollectorVersion){throw'ModuleResultValidationFailed'}

    $SchemaEntry=$Ledger|Select-Object -Last 1
    $IdProperty=@('ledgerId','id','entryId')|Where-Object{$null-ne$SchemaEntry.PSObject.Properties[$_]}|Select-Object -First 1
    if($null-eq$IdProperty){throw'LedgerIdPropertyNotDetected'}
    $NewLedgerId='ledger-'+[Guid]::NewGuid().ToString('N')
    $NewEntry=$SchemaEntry|ConvertTo-Json -Depth 20|ConvertFrom-Json
    Set-ObjectProperty $NewEntry $IdProperty $NewLedgerId
    Set-ObjectProperty $NewEntry 'module' 'ADCSCARuntimeConfigurationCollection'
    Set-ObjectProperty $NewEntry 'moduleVersion' $ExpectedCollectorVersion
    if($null-ne$Result.PSObject.Properties['evidenceSchemaVersion']){Set-ObjectProperty $NewEntry 'evidenceSchemaVersion' $Result.evidenceSchemaVersion}
    Set-ObjectProperty $NewEntry 'status' 'Completed';Set-ObjectProperty $NewEntry 'executionClass' 'read_only';Set-ObjectProperty $NewEntry 'evidence' @($Result.evidence);Set-ObjectProperty $NewEntry 'completedUtc' ([string]$Result.completedUtc);Set-ObjectProperty $NewEntry 'superseded' $false;Set-ObjectProperty $NewEntry 'supersededBy' $null
    Set-ObjectProperty $NewEntry 'caCount' $RuntimeRows.Count;Set-ObjectProperty $NewEntry 'certutilQueryCount' $TotalQueries;Set-ObjectProperty $NewEntry 'completedCertutilQueryCount' $CompletedQueries;Set-ObjectProperty $NewEntry 'failedCertutilQueryCount' $FailedQueries
    if($ActiveRuntimeEntries.Count-eq1){
        $Previous=$ActiveRuntimeEntries[0];$PreviousIdProperty=@('ledgerId','id','entryId')|Where-Object{$null-ne$Previous.PSObject.Properties[$_]}|Select-Object -First 1
        Set-ObjectProperty $Previous 'superseded' $true;Set-ObjectProperty $Previous 'supersededBy' $NewLedgerId;Set-ObjectProperty $NewEntry 'refreshReason' "CA-runtime collector refreshed from $([string]$Previous.moduleVersion) to $ExpectedCollectorVersion"
    } else {Set-ObjectProperty $NewEntry 'refreshReason' 'Initial controlled CA-runtime collection'}
    $UpdatedLedger=@($Ledger)+@($NewEntry)
    $TempLedger="$LedgerPath.tmp-$Timestamp"
    $UpdatedLedger|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $TempLedger -Encoding UTF8
    $ValidatedLedger=@(Get-Content -LiteralPath $TempLedger -Raw|ConvertFrom-Json -ErrorAction Stop)
    $ActiveNew=@($ValidatedLedger|Where-Object{[string]$_.module-eq'ADCSCARuntimeConfigurationCollection' -and [string]$_.moduleVersion-eq$ExpectedCollectorVersion -and -not[bool]$_.superseded})
    if($ValidatedLedger.Count-ne($Ledger.Count+1) -or $ActiveNew.Count-ne1){throw'LedgerValidationFailed'}
    Move-Item -LiteralPath $TempLedger -Destination $LedgerPath -Force
    $FinalLedger=@(Get-Content -LiteralPath $LedgerPath -Raw|ConvertFrom-Json -ErrorAction Stop)
    if($FinalLedger.Count-ne($Ledger.Count+1)){throw'FinalLedgerCountMismatch'}
    Write-Step 'OK' "Ledger updated atomically: $($Ledger.Count) -> $($FinalLedger.Count) records; active runtime entry=$NewLedgerId." Green

    $RollbackRequired=$false
    $PostManifestPath=Join-Path $ArchiveRoot 'post-collection-manifest.json'
    $PostFiles=@($RuntimeEvidencePath,$RuntimeSummaryPath,$ServiceEvidencePath,$ResultPath,$LedgerPath)
    $PostRows=@($PostFiles|ForEach-Object{$Info=Get-Item -LiteralPath $_;[pscustomobject]@{path=$_;size=[int64]$Info.Length;sha256=Get-Sha256 $_;lastWriteTimeUtc=([DateTime]$Info.LastWriteTimeUtc).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)}})
    [pscustomobject]@{schemaVersion='1.0';status='Completed';collectorInvocationCount=$InvocationCount;caTargets=$CaTargets;collectorResult=$Result;querySummary=[pscustomobject]@{total=$TotalQueries;completed=$CompletedQueries;nonCompleted=$FailedQueries};serviceConnectionPointCount=$ServiceRows.Count;serviceEvidenceNormalized=$ServiceEvidenceNormalized;newLedgerId=$NewLedgerId;newModuleResultPath=$ResultPath;postCollectionFiles=$PostRows}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $PostManifestPath -Encoding UTF8

    Write-Step 'DONE' 'Controlled CA-runtime collection completed and persisted.' Green
    [pscustomobject][ordered]@{Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;CollectorVersion=$ExpectedCollectorVersion;CollectorInvocationCount=$InvocationCount;EngagementPath=$EngagementPath;BootstrapServer=$BootstrapServer;EnterpriseCACount=$CaTargets.Count;EnterpriseCAHosts=@($CaTargets.dnsHostName);TcpTimeoutSeconds=$TcpTimeoutSeconds;CommandTimeoutSeconds=$CommandTimeoutSeconds;CertutilQueryCount=$TotalQueries;CompletedCertutilQueryCount=$CompletedQueries;NonCompletedCertutilQueryCount=$FailedQueries;ServiceConnectionPointCount=$ServiceRows.Count;ServiceEvidenceNormalized=$ServiceEvidenceNormalized;LedgerRecordCountBefore=$Ledger.Count;LedgerRecordCountAfter=$FinalLedger.Count;NewLedgerId=$NewLedgerId;RuntimeEvidencePath=$RuntimeEvidencePath;RuntimeSummaryPath=$RuntimeSummaryPath;ServiceEvidencePath=$ServiceEvidencePath;NewModuleResultPath=$ResultPath;RollbackArchive=$ArchiveRoot;PostCollectionManifestPath=$PostManifestPath;ManifestState='Disabled';DirectoryChanges='None';CertificateActivity='None';AuthenticationActivity='None';RegistryChanges='None';ServiceChanges='None';OllamaActivity='None'}
}
catch{
    Write-Step 'FAIL' $_.Exception.Message Red
    if($RollbackRequired){
        Write-Step 'ROLLBACK' 'Restoring archived local evidence and ledger.' DarkYellow
        try {
            Restore-Archive
            foreach ($TrackedOutputPath in @($RuntimeEvidencePath,$RuntimeSummaryPath,$ServiceEvidencePath)) {
                if ($PreexistingOutputPaths.ContainsKey($TrackedOutputPath) -and -not [bool]$PreexistingOutputPaths[$TrackedOutputPath] -and (Test-Path -LiteralPath $TrackedOutputPath -PathType Leaf)) {
                    Remove-Item -LiteralPath $TrackedOutputPath -Force
                }
            }
            Write-Step 'OK' 'Rollback completed, including removal of outputs that did not exist before execution.' Green
        }
        catch { Write-Step 'FAIL' "RollbackFailure: $($_.Exception.Message)" Red }
    }
    throw
}
