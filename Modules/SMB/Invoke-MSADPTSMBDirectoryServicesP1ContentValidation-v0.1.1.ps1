<#
.SYNOPSIS
Performs bounded, redacted content validation for P1 SYSVOL and NETLOGON metadata leads.

.DESCRIPTION
Consumes logical-directory-services-leads.json from completed MSADPT lead reduction. Selects only P1
artifacts, chooses one evidence-recorded source DC per logical path, and reads at most the configured
byte limit. If the preferred source fails, one alternate evidence-recorded DC may be tried.

The validator detects structural indicators such as Group Policy Preferences cpassword attributes,
unattended-installation credential fields, private-key or credential-container headers, autologon,
domain-join identities, product keys, and sensitive configuration element names. Potential values are
never emitted to the console, CSV, JSON, or HTML. Complete file contents are not saved.

No remote file is created, modified, renamed, or deleted. No credential is decrypted, validated, or used.

.NOTES
Version: 0.1.1
Package identity: MSADPT-SMB-DIRECTORY-SERVICES-P1-CONTENT-VALIDATION
Execution class: authorized_bounded_read_only_live_validation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$LeadReductionDirectory,

    [string]$OutputDirectory,

    [ValidateRange(4096,1048576)]
    [int]$MaximumBytesPerFile = 1048576,

    [ValidateRange(1,25)]
    [int]$MaximumP1Files = 10,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-SMB-DIRECTORY-SERVICES-P1-CONTENT-VALIDATION'
$PackageVersion = '0.1.1'
$OperationalErrors = New-Object 'System.Collections.Generic.List[object]'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-12}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}
function Require-File {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) { throw "RequiredFileEmpty [$Label]: $Path" }
}
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=18)
    $Array = [object[]]@($Rows)
    if (@($Array).Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    } else {
        $Array | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $Check = [object[]]@(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    if (@($Check).Count -ne @($Array).Count) { throw "JsonArrayRoundTripMismatch: $Path" }
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=18)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}
function Add-OperationalError {
    param([string]$LeadId,[string]$Target,[string]$UncPath,[string]$Stage,[string]$ErrorText)
    $OperationalErrors.Add([pscustomobject][ordered]@{
        LeadId=$LeadId;Target=$Target;UncPath=$UncPath;Stage=$Stage
        Protocol='SMB';Port=445;Error=$ErrorText
    })
}
function Get-UncPath {
    param([string]$Target,[string]$Share,[string]$RelativePath)
    $CleanRelative = $RelativePath.Replace('/','\').TrimStart('\')
    return "\\$Target\$Share\$CleanRelative"
}
function Read-BoundedBytes {
    param([string]$Path,[int]$MaximumBytes)

    $Stream = $null
    try {
        $Stream = New-Object IO.FileStream(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite
        )
        $OriginalLength = [int64]$Stream.Length
        $BytesToRead = [int][Math]::Min([int64]$MaximumBytes,$OriginalLength)
        $Buffer = New-Object byte[] $BytesToRead
        $TotalRead = 0
        while ($TotalRead -lt $BytesToRead) {
            $Read = $Stream.Read($Buffer,$TotalRead,$BytesToRead-$TotalRead)
            if ($Read -le 0) { break }
            $TotalRead += $Read
        }
        if ($TotalRead -lt $Buffer.Length) {
            $Trimmed = New-Object byte[] $TotalRead
            [Array]::Copy($Buffer,$Trimmed,$TotalRead)
            $Buffer = $Trimmed
        }
        return [pscustomobject][ordered]@{
            Bytes=$Buffer;BytesRead=$TotalRead;OriginalLength=$OriginalLength
            Truncated=($OriginalLength -gt $TotalRead)
        }
    } finally {
        if ($null -ne $Stream) { $Stream.Dispose() }
    }
}
function Convert-BytesToSafeText {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    $Encoding = New-Object Text.UTF8Encoding($false,$false)
    $Text = $Encoding.GetString($Bytes)
    if ($Text -match "`0") {
        try { $Text = [Text.Encoding]::Unicode.GetString($Bytes) } catch { }
    }
    return $Text
}
function Get-DetectionDefinitions {
    return [object[]]@(
        [pscustomobject]@{Class='GPPEncryptedPasswordAttribute';Pattern='(?i)\bcpassword\s*=';Sensitive=$true}
        [pscustomobject]@{Class='PasswordElementOrAttribute';Pattern='(?i)(<|\b)(password|passwd|pwd|administratorpassword|defaultpassword)(>|\s*=)';Sensitive=$true}
        [pscustomobject]@{Class='AutoLogonConfiguration';Pattern='(?i)(autologon|defaultusername|defaultdomainname)';Sensitive=$true}
        [pscustomobject]@{Class='DomainJoinCredentialContext';Pattern='(?i)(credentials|domainjoin|joindomain|joinworkgroup|machineobjectou)';Sensitive=$true}
        [pscustomobject]@{Class='ProductKeyElement';Pattern='(?i)(productkey|product-key)';Sensitive=$true}
        [pscustomobject]@{Class='RunAsOrTaskIdentity';Pattern='(?i)(runas|runasuser|accountname|username|usercontext|principal)';Sensitive=$true}
        [pscustomobject]@{Class='ConnectionStringOrSecretName';Pattern='(?i)(connectionstring|clientsecret|secretkey|apikey|accesskey|token)';Sensitive=$true}
        [pscustomobject]@{Class='PrivateKeyHeader';Pattern='-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----';Sensitive=$true}
        [pscustomobject]@{Class='CertificateHeader';Pattern='-----BEGIN CERTIFICATE-----';Sensitive=$false}
        [pscustomobject]@{Class='KeePassSignature';Pattern='(?i)KDBX';Sensitive=$true}
        [pscustomobject]@{Class='OpenVpnConfiguration';Pattern='(?im)^\s*(client|remote|auth-user-pass|pkcs12|secret)\b';Sensitive=$true}
    )
}
function Get-SafeDetections {
    param([string]$Text,[string]$Category)

    $Rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Definition in (Get-DetectionDefinitions)) {
        $Matches = [regex]::Matches($Text,[string]$Definition.Pattern)
        if ($Matches.Count -gt 0) {
            $Rows.Add([pscustomobject][ordered]@{
                DetectionClass=[string]$Definition.Class
                MatchCount=[int]$Matches.Count
                PotentiallySensitive=[bool]$Definition.Sensitive
                Value='<REDACTED>'
                CategoryContext=$Category
            })
        }
    }
    return [object[]]$Rows.ToArray()
}
function Get-FileSignatureClass {
    param([byte[]]$Bytes,[string]$Extension)

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return 'EmptyFile' }
    if ($Bytes.Length -ge 4) {
        $Hex = ($Bytes[0..3] | ForEach-Object { $_.ToString('X2') }) -join ''
        if ($Hex -eq '504B0304') { return 'ZipOrOfficeContainer' }
        if ($Hex -eq '3082' -or $Extension -in @('.pfx','.p12')) { return 'PossiblePkcs12OrDerContainer' }
        if ($Hex -eq '03D9A29A') { return 'KeePassKdbxContainer' }
    }
    if ($Extension -in @('.pem','.key','.ppk','.ovpn','.xml','.config','.ini','.json','.txt')) { return 'TextOrStructuredText' }
    return 'UnknownOrBinary'
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'P1-only bounded content validation with redacted structural evidence.' DarkGray

    if (-not (Test-Path -LiteralPath $LeadReductionDirectory -PathType Container)) {
        throw "LeadReductionDirectoryMissing: $LeadReductionDirectory"
    }

    $LogicalPath = Join-Path $LeadReductionDirectory 'logical-directory-services-leads.json'
    Require-File $LogicalPath 'Logical directory-services leads'

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $LeadReductionDirectory 'P1ContentValidation-v0.1.1'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $LogicalRows = [object[]]@(Get-Content -LiteralPath $LogicalPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    $P1Rows = [object[]]@(
        $LogicalRows |
            Where-Object { $_.Priority -eq 'P1' -and [bool]$_.ContentValidationEligible } |
            Sort-Object Category,NormalizedRelativePath |
            Select-Object -First $MaximumP1Files
    )
    if (@($P1Rows).Count -eq 0) { throw 'No P1 content-validation leads were found.' }

    $PlanList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Lead in $P1Rows) {
        $Sources = [object[]]@($Lead.SourceTargets | Sort-Object -Unique)
        $PreferredTarget = [string]$Sources[0]
        $AlternateTargets = [object[]]@($Sources | Select-Object -Skip 1)
        $PreferredUnc = Get-UncPath -Target $PreferredTarget -Share ([string]$Lead.Share) -RelativePath ([string]$Lead.RelativePath)
        $PlanList.Add([pscustomobject][ordered]@{
            LogicalLeadId=[string]$Lead.LogicalLeadId;Priority='P1';Category=[string]$Lead.Category
            Share=[string]$Lead.Share;RelativePath=[string]$Lead.RelativePath
            PreferredTarget=$PreferredTarget;AlternateTargets=$AlternateTargets
            PreferredUncPath=$PreferredUnc;MaximumBytes=$MaximumBytesPerFile
            DetectionMode='RedactedStructuralPatternValidation'
            ConsoleSecretOutput=$false;HtmlSecretOutput=$false;CompleteContentSaved=$false;RemoteChange=$false
        })
    }
    $PlanRows = [object[]]$PlanList.ToArray()

    Write-Step 'NETWORK' 'Planned live network operations follow.' Magenta
    Write-Step 'SCOPE' "Files=$(@($PlanRows).Count); Protocol=SMB; Port=TCP/445; maximumBytesPerFile=$MaximumBytesPerFile; P1 only." DarkCyan
    foreach ($Plan in $PlanRows) {
        Write-Step 'TARGET' "$($Plan.PreferredTarget) TCP/445 $($Plan.PreferredUncPath): read-only bounded content; alternateDCs=$(@($Plan.AlternateTargets).Count); values=REDACTED; write=False" DarkCyan
    }
    Write-Step 'CHANGES' 'Remote file changes=None; credential decryption=None; credential validation=None; relay=None; remote execution=None.' DarkCyan

    $ResultList = New-Object 'System.Collections.Generic.List[object]'
    $DetectionList = New-Object 'System.Collections.Generic.List[object]'
    $Position = 0

    foreach ($Plan in $PlanRows) {
        $Position++
        $CandidateTargets = [object[]]@($Plan.PreferredTarget) + [object[]]@($Plan.AlternateTargets)
        $RemoteReadSucceeded = $false
        $LocalAnalysisSucceeded = $false
        $Attempts = 0
        $FinalError = $null
        $ReadTarget = $null
        $ReadUncPath = $null
        $ReadResult = $null

        foreach ($TargetName in $CandidateTargets) {
            if ($RemoteReadSucceeded) { break }
            $Attempts++
            $UncPath = Get-UncPath -Target ([string]$TargetName) -Share ([string]$Plan.Share) -RelativePath ([string]$Plan.RelativePath)
            Write-Step 'READ' "$Position/$(@($PlanRows).Count) attempt=$Attempts target=$TargetName path=$UncPath maxBytes=$MaximumBytesPerFile" Yellow

            try {
                $ReadResult = Read-BoundedBytes -Path $UncPath -MaximumBytes $MaximumBytesPerFile
                $RemoteReadSucceeded = $true
                $ReadTarget = [string]$TargetName
                $ReadUncPath = $UncPath
            }
            catch {
                $FinalError = $_.Exception.Message
                Add-OperationalError -LeadId ([string]$Plan.LogicalLeadId) -Target ([string]$TargetName) -UncPath $UncPath -Stage 'BoundedContentRead' -ErrorText $FinalError
            }
        }

        if (-not $RemoteReadSucceeded) {
            $ResultList.Add([pscustomobject][ordered]@{
                LogicalLeadId=[string]$Plan.LogicalLeadId;Priority='P1';Category=[string]$Plan.Category
                Target=$null;Share=[string]$Plan.Share;RelativePath=[string]$Plan.RelativePath;UncPath=$null
                Attempts=$Attempts;RemoteReadSucceeded=$false;LocalAnalysisSucceeded=$false
                BytesRequested=$MaximumBytesPerFile;BytesRead=0;OriginalLength=$null
                ContentTruncated=$false;FileSignatureClass=$null;DetectionClassCount=0;SensitiveDetectionClassCount=0
                DetectedClasses=@();RedactionApplied=$true;CompleteContentSaved=$false;ContentHashCalculated=$false
                Disposition='FileUnavailable';RemoteChange=$false;Error=$FinalError
            })
            continue
        }

        try {
            $Extension = [IO.Path]::GetExtension([string]$Plan.RelativePath).ToLowerInvariant()
            $SignatureClass = Get-FileSignatureClass -Bytes ([byte[]]$ReadResult.Bytes) -Extension $Extension
            $Text = Convert-BytesToSafeText -Bytes ([byte[]]$ReadResult.Bytes)
            $Detections = [object[]]@(Get-SafeDetections -Text $Text -Category ([string]$Plan.Category))
            $DetectionCount = [int]@($Detections).Count
            $SensitiveDetections = [object[]]@($Detections | Where-Object { [bool]$_.PotentiallySensitive })
            $SensitiveDetectionCount = [int]@($SensitiveDetections).Count
            $DetectedClasses = [object[]]@(
                $Detections |
                    ForEach-Object { [string]$_.DetectionClass } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Sort-Object -Unique
            )

            foreach ($Detection in $Detections) {
                $DetectionList.Add([pscustomobject][ordered]@{
                    LogicalLeadId=[string]$Plan.LogicalLeadId
                    Target=$ReadTarget;Share=[string]$Plan.Share;RelativePath=[string]$Plan.RelativePath
                    DetectionClass=[string]$Detection.DetectionClass;MatchCount=[int]$Detection.MatchCount
                    PotentiallySensitive=[bool]$Detection.PotentiallySensitive;Value='<REDACTED>'
                })
            }

            $Disposition = 'SensitivePatternNotDetected'
            if ($SignatureClass -in @('PossiblePkcs12OrDerContainer','KeePassKdbxContainer')) {
                $Disposition = 'EncryptedOrProtectedContainerDetected'
            }
            elseif ($SensitiveDetectionCount -gt 0) {
                $Disposition = 'SensitiveConfigurationPatternConfirmed'
            }
            elseif ($SignatureClass -eq 'UnknownOrBinary') {
                $Disposition = 'UnsupportedBinaryFormat'
            }
            elseif ([bool]$ReadResult.Truncated) {
                $Disposition = 'ContentTruncatedNoSensitivePatternDetectedInReadWindow'
            }

            $ResultList.Add([pscustomobject][ordered]@{
                LogicalLeadId=[string]$Plan.LogicalLeadId;Priority='P1';Category=[string]$Plan.Category
                Target=$ReadTarget;Share=[string]$Plan.Share;RelativePath=[string]$Plan.RelativePath;UncPath=$ReadUncPath
                Attempts=$Attempts;RemoteReadSucceeded=$true;LocalAnalysisSucceeded=$true
                BytesRequested=$MaximumBytesPerFile;BytesRead=[int]$ReadResult.BytesRead
                OriginalLength=[int64]$ReadResult.OriginalLength;ContentTruncated=[bool]$ReadResult.Truncated
                FileSignatureClass=$SignatureClass;DetectionClassCount=$DetectionCount
                SensitiveDetectionClassCount=$SensitiveDetectionCount;DetectedClasses=$DetectedClasses
                RedactionApplied=$true;CompleteContentSaved=$false;ContentHashCalculated=$false
                Disposition=$Disposition;RemoteChange=$false;Error=$null
            })
            $LocalAnalysisSucceeded = $true
        }
        catch {
            $FinalError = $_.Exception.Message
            Add-OperationalError -LeadId ([string]$Plan.LogicalLeadId) -Target $ReadTarget -UncPath $ReadUncPath -Stage 'LocalContentAnalysis' -ErrorText $FinalError
            $ResultList.Add([pscustomobject][ordered]@{
                LogicalLeadId=[string]$Plan.LogicalLeadId;Priority='P1';Category=[string]$Plan.Category
                Target=$ReadTarget;Share=[string]$Plan.Share;RelativePath=[string]$Plan.RelativePath;UncPath=$ReadUncPath
                Attempts=$Attempts;RemoteReadSucceeded=$true;LocalAnalysisSucceeded=$false
                BytesRequested=$MaximumBytesPerFile;BytesRead=[int]$ReadResult.BytesRead
                OriginalLength=[int64]$ReadResult.OriginalLength;ContentTruncated=[bool]$ReadResult.Truncated
                FileSignatureClass=$null;DetectionClassCount=0;SensitiveDetectionClassCount=0;DetectedClasses=@()
                RedactionApplied=$true;CompleteContentSaved=$false;ContentHashCalculated=$false
                Disposition='LocalAnalysisFailed';RemoteChange=$false;Error=$FinalError
            })
        }
    }

    $ResultRows = [object[]]$ResultList.ToArray()
    $DetectionRows = [object[]]$DetectionList.ToArray()
    $ErrorRows = [object[]]$OperationalErrors.ToArray()

    $RemoteReadSuccessCount = [int]@($ResultRows | Where-Object { [bool]$_.RemoteReadSucceeded }).Count
    $ValidatedCount = [int]@($ResultRows | Where-Object { [bool]$_.LocalAnalysisSucceeded }).Count
    $UnavailableCount = [int]@($ResultRows | Where-Object { $_.Disposition -eq 'FileUnavailable' }).Count
    $LocalAnalysisFailureCount = [int]@($ResultRows | Where-Object { $_.Disposition -eq 'LocalAnalysisFailed' }).Count
    $SensitivePatternCount = [int]@($ResultRows | Where-Object { $_.Disposition -eq 'SensitiveConfigurationPatternConfirmed' }).Count
    $ContainerCount = [int]@($ResultRows | Where-Object { $_.Disposition -eq 'EncryptedOrProtectedContainerDetected' }).Count
    $NoPatternCount = [int]@($ResultRows | Where-Object { $_.Disposition -like '*SensitivePatternNotDetected*' }).Count

    $OverallDisposition = 'NoSensitivePatternDetected'
    if ($SensitivePatternCount -gt 0) { $OverallDisposition='SensitiveConfigurationPatternDetected' }
    elseif ($ContainerCount -gt 0) { $OverallDisposition='ProtectedCredentialContainerDetected' }
    elseif ($ValidatedCount -eq 0) { $OverallDisposition='ContentValidationInconclusive' }

    $PlanJson=Join-Path $OutputDirectory 'p1-content-validation-plan.json'
    $PlanCsv=Join-Path $OutputDirectory 'p1-content-validation-plan.csv'
    $ResultsJson=Join-Path $OutputDirectory 'p1-content-validation-results.json'
    $ResultsCsv=Join-Path $OutputDirectory 'p1-content-validation-results.csv'
    $DetectionsJson=Join-Path $OutputDirectory 'p1-redacted-detections.json'
    $DetectionsCsv=Join-Path $OutputDirectory 'p1-redacted-detections.csv'
    $ErrorsJson=Join-Path $OutputDirectory 'operational-errors.json'

    Write-JsonArray $PlanRows $PlanJson;$PlanRows|Export-Csv -LiteralPath $PlanCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ResultRows $ResultsJson;$ResultRows|Export-Csv -LiteralPath $ResultsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $DetectionRows $DetectionsJson;$DetectionRows|Export-Csv -LiteralPath $DetectionsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ErrorRows $ErrorsJson

    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status=if(@($ErrorRows).Count -gt 0){'CompletedWithErrors'}else{'Completed'}
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        SourceLeadReductionDirectory=$LeadReductionDirectory;OverallDisposition=$OverallDisposition
        Counts=[pscustomobject]@{P1FilesSelected=@($PlanRows).Count;RemoteReadSuccesses=$RemoteReadSuccessCount;FilesValidated=$ValidatedCount;FilesUnavailable=$UnavailableCount;LocalAnalysisFailures=$LocalAnalysisFailureCount;SensitiveConfigurationPatternFiles=$SensitivePatternCount;ProtectedContainerFiles=$ContainerCount;NoSensitivePatternFiles=$NoPatternCount;RedactedDetectionRows=@($DetectionRows).Count;OperationalErrors=@($ErrorRows).Count}
        InterpretationBoundary=@('Sensitive pattern detection proves only that a relevant structural indicator was present.','No secret value was emitted or saved.','No credential was decrypted, validated, or used.','A vulnerability requires current applicability and reproducible security impact.','Complete file contents were not retained.')
        Safety=[pscustomobject]@{MaximumBytesPerFile=$MaximumBytesPerFile;CompleteContentSaved=$false;ConsoleSecretOutput=$false;HtmlSecretOutput=$false;CredentialDecryption='None';CredentialValidation='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'p1-content-validation-summary.json';Write-JsonDocument $Summary $SummaryPath

    $ResultHtml=($ResultRows|ForEach-Object{
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (Convert-HtmlText $_.LogicalLeadId),(Convert-HtmlText $_.Category),(Convert-HtmlText $_.RelativePath),(Convert-HtmlText $_.BytesRead),(Convert-HtmlText $_.DetectedClasses),(Convert-HtmlText $_.Disposition)
    })-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-SMB-P1-Content-Validation.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT SMB P1 Content Validation</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT SMB P1 Redacted Content Validation</h1><div class="card"><b>Disposition:</b> $(Convert-HtmlText $OverallDisposition)<br><b>P1 files selected:</b> $(@($PlanRows).Count)<br><b>Remote reads succeeded:</b> $RemoteReadSuccessCount<br><b>Files validated:</b> $ValidatedCount<br><b>Unavailable:</b> $UnavailableCount<br><b>Local analysis failures:</b> $LocalAnalysisFailureCount<br><b>Sensitive-pattern files:</b> $SensitivePatternCount<br><b>Protected containers:</b> $ContainerCount<br><b>Maximum bytes per file:</b> $MaximumBytesPerFile<br><b>Complete contents saved:</b> No<br><b>Secret values emitted:</b> No<br><b>Remote changes:</b> None</div><h2>Validation Results</h2><table><tr><th>Lead</th><th>Category</th><th>Relative path</th><th>Bytes read</th><th>Detection classes</th><th>Disposition</th></tr>$ResultHtml</table><h2>Evidence</h2><ul><li><a href="p1-content-validation-plan.csv">Validation plan</a></li><li><a href="p1-content-validation-results.csv">Validation results</a></li><li><a href="p1-redacted-detections.csv">Redacted detections</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="p1-content-validation-summary.json">Summary</a></li></ul><p class="note">Secret values are always represented as &lt;REDACTED&gt;. Structural detections are leads until current applicability and impact are reproduced.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name -ne 'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=[object[]]@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "P1 validation complete: selected=$(@($PlanRows).Count), remote-read=$RemoteReadSuccessCount, validated=$ValidatedCount, unavailable=$UnavailableCount, local-analysis-failed=$LocalAnalysisFailureCount, sensitive-pattern=$SensitivePatternCount, containers=$ContainerCount, disposition=$OverallDisposition." Green
    [pscustomobject][ordered]@{
        Status=if(@($ErrorRows).Count -gt 0){'PassedWithErrors'}else{'Passed'}
        PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;OverallDisposition=$OverallDisposition
        P1FileCount=@($PlanRows).Count;RemoteReadSuccessCount=$RemoteReadSuccessCount;ValidatedFileCount=$ValidatedCount;UnavailableFileCount=$UnavailableCount;LocalAnalysisFailureCount=$LocalAnalysisFailureCount
        SensitiveConfigurationPatternFileCount=$SensitivePatternCount;ProtectedContainerFileCount=$ContainerCount
        NoSensitivePatternFileCount=$NoPatternCount;RedactedDetectionCount=@($DetectionRows).Count
        OperationalErrorCount=@($ErrorRows).Count;OutputDirectory=$OutputDirectory
        HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        MaximumBytesPerFile=$MaximumBytesPerFile;CompleteContentSaved='No';SecretValuesEmitted='No'
        CredentialDecryption='None';CredentialValidation='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
