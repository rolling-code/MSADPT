<#
.SYNOPSIS
Reduces MSADPT SYSVOL and NETLOGON metadata leads into a deduplicated content-validation queue.

.DESCRIPTION
Consumes completed SMB Directory Services follow-up evidence. Normalizes replicated SYSVOL and
NETLOGON paths across domain controllers, removes duplicate observations, classifies artifacts by
security relevance, correlates metadata errors, and creates a bounded content-validation queue.

This stage is local only. It performs no Active Directory query, DNS lookup, network connection,
SMB authentication, share access, file-content read, hashing, remote write, relay, or execution.

.NOTES
Version: 0.1.0
Package identity: MSADPT-SMB-DIRECTORY-SERVICES-LEAD-REDUCTION
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FollowUpDirectory,

    [string]$OutputDirectory,

    [ValidateRange(1,500)]
    [int]$MaximumValidationQueue = 50,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageIdentity = 'MSADPT-SMB-DIRECTORY-SERVICES-LEAD-REDUCTION'
$PackageVersion = '0.1.0'

function Write-Step {
    param(
        [string]$Status,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($Quiet) {
        return
    }

    $Text = '[{0,-12}] {1}' -f $Status, $Message
    if ($NoColor) {
        Write-Host $Text
    }
    else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Require-File {
    param(
        [string]$Path,
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "RequiredFileMissing [$Label]: $Path"
    }

    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "RequiredFileEmpty [$Label]: $Path"
    }
}

function Read-JsonArray {
    param(
        [string]$Path,
        [string]$Label
    )

    Require-File -Path $Path -Label $Label
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
}

function Write-JsonArray {
    param(
        [object[]]$Rows,
        [string]$Path,
        [int]$Depth = 18
    )

    $Array = [object[]]@($Rows)
    if (@($Array).Count -eq 0) {
        [IO.File]::WriteAllText(
            $Path,
            "[]`r`n",
            (New-Object Text.UTF8Encoding($false))
        )
    }
    else {
        $Array |
            ConvertTo-Json -Depth $Depth |
            Set-Content -LiteralPath $Path -Encoding UTF8
    }

    $RoundTrip = [object[]]@(
        Get-Content -LiteralPath $Path -Raw |
            ConvertFrom-Json -ErrorAction Stop
    )

    if (@($RoundTrip).Count -ne @($Array).Count) {
        throw "JsonArrayRoundTripMismatch: $Path"
    }
}

function Write-JsonDocument {
    param(
        [object]$Document,
        [string]$Path,
        [int]$Depth = 18
    )

    $Document |
        ConvertTo-Json -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8

    $null = Get-Content -LiteralPath $Path -Raw |
        ConvertFrom-Json -ErrorAction Stop
}

function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Normalize-RelativePath {
    param([object]$Value)

    $Text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $Normalized = $Text.Replace('/', '\').Trim().TrimStart('\')
    while ($Normalized.Contains('\\')) {
        $Normalized = $Normalized.Replace('\\', '\')
    }

    return $Normalized.ToLowerInvariant()
}

function Get-LogicalPathKey {
    param(
        [string]$Share,
        [string]$RelativePath
    )

    return ('{0}|{1}' -f $Share.ToUpperInvariant(), (Normalize-RelativePath -Value $RelativePath))
}

function Get-ArtifactClassification {
    param(
        [string]$Share,
        [string]$RelativePath,
        [string]$Extension,
        [string]$EntryType
    )

    if ($EntryType -ne 'File') {
        return [pscustomobject]@{
            Priority = 'Informational'
            Category = 'Directory'
            Reason = 'Directory metadata only'
            ContentValidationEligible = $false
        }
    }

    $FileName = [IO.Path]::GetFileName($RelativePath)
    $LowerName = $FileName.ToLowerInvariant()
    $LowerPath = $RelativePath.ToLowerInvariant()
    $LowerExtension = $Extension.ToLowerInvariant()

    $ExactGppNames = @(
        'groups.xml',
        'services.xml',
        'scheduledtasks.xml',
        'registry.xml',
        'drives.xml',
        'printers.xml',
        'datasources.xml'
    )

    if ($LowerName -in $ExactGppNames) {
        return [pscustomobject]@{
            Priority = 'P1'
            Category = 'ExactGroupPolicyPreferencesArtifact'
            Reason = 'Exact Group Policy Preferences filename requiring bounded content validation'
            ContentValidationEligible = $true
        }
    }

    if ($LowerName -like 'unattend*.xml' -or $LowerName -like 'unattended*.xml') {
        return [pscustomobject]@{
            Priority = 'P1'
            Category = 'UnattendedInstallationArtifact'
            Reason = 'Unattended installation files may contain deployment credentials or sensitive configuration'
            ContentValidationEligible = $true
        }
    }

    if ($LowerExtension -in @('.pfx','.p12','.ppk','.pem','.key','.kdbx','.ovpn')) {
        return [pscustomobject]@{
            Priority = 'P1'
            Category = 'CredentialOrPrivateKeyContainer'
            Reason = 'Credential, private-key, password-database, or VPN artifact'
            ContentValidationEligible = $true
        }
    }

    if ($LowerName -in @('web.config') -or $LowerName -like 'appsettings*.json') {
        return [pscustomobject]@{
            Priority = 'P2'
            Category = 'ApplicationConfiguration'
            Reason = 'Application configuration may contain connection strings, service identities, or secrets'
            ContentValidationEligible = $true
        }
    }

    if ($LowerExtension -in @('.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.js','.wsf')) {
        return [pscustomobject]@{
            Priority = 'P2'
            Category = 'ExecutableOrDeploymentScript'
            Reason = 'Script may reveal credentials, privileged execution paths, deployment behavior, or pivot targets'
            ContentValidationEligible = $true
        }
    }

    if ($LowerExtension -in @('.bak','.old','.orig','.save')) {
        return [pscustomobject]@{
            Priority = 'P2'
            Category = 'BackupOrHistoricalArtifact'
            Reason = 'Backup or historical file may contain stale credentials or superseded sensitive configuration'
            ContentValidationEligible = $true
        }
    }

    if ($LowerExtension -in @('.config','.ini','.yml','.yaml','.sql','.rdp')) {
        return [pscustomobject]@{
            Priority = 'P3'
            Category = 'ConfigurationOrConnectionArtifact'
            Reason = 'Configuration or connection artifact requires context before content validation'
            ContentValidationEligible = $true
        }
    }

    if ($LowerExtension -in @('.xml','.json','.txt')) {
        $Category = 'GenericConfigurationOrText'
        $Reason = 'Broad metadata match; deprioritized unless path context suggests deployment or preferences data'
        $Eligible = $false

        if ($LowerPath -match '(?i)\\preferences\\|\\scripts\\|\\machine\\scripts\\|\\user\\scripts\\') {
            $Category = 'PolicyPreferenceOrScriptContext'
            $Reason = 'Generic configuration or text file located in a policy preference or script context'
            $Eligible = $true
        }

        return [pscustomobject]@{
            Priority = if ($Eligible) { 'P3' } else { 'Informational' }
            Category = $Category
            Reason = $Reason
            ContentValidationEligible = $Eligible
        }
    }

    return [pscustomobject]@{
        Priority = 'Informational'
        Category = 'Other'
        Reason = 'No content-validation rule matched'
        ContentValidationEligible = $false
    }
}

function Get-ErrorCategory {
    param([string]$ErrorText)

    if ($ErrorText -match '(?i)access is denied|unauthorized|status\s*5\b') {
        return 'AccessDenied'
    }
    if ($ErrorText -match '(?i)cannot find path|path does not exist|could not find a part of the path|status\s*3\b') {
        return 'PathUnavailable'
    }
    if ($ErrorText -match '(?i)network path was not found|status\s*53\b') {
        return 'NetworkPathNotFound'
    }
    if ($ErrorText -match '(?i)specified network name is no longer available|status\s*64\b') {
        return 'NetworkNameUnavailable'
    }
    if ($ErrorText -match '(?i)path too long|longer than the system-defined maximum') {
        return 'PathTooLong'
    }
    if ($ErrorText -match '(?i)used by another process|sharing violation') {
        return 'SharingViolation'
    }
    if ($ErrorText -match '(?i)timeout|timed out|semaphore timeout') {
        return 'Timeout'
    }

    return 'Other'
}

try {
    Write-Step -Status 'START' -Message "$PackageIdentity v$PackageVersion" -Color Cyan
    Write-Step -Status 'INFO' -Message 'Local-only deduplication, classification, error correlation, and queue generation.' -Color DarkGray

    if (-not (Test-Path -LiteralPath $FollowUpDirectory -PathType Container)) {
        throw "FollowUpDirectoryMissing: $FollowUpDirectory"
    }

    $MetadataPath = Join-Path $FollowUpDirectory 'directory-services-file-metadata.json'
    $LeadPath = Join-Path $FollowUpDirectory 'directory-services-interesting-name-leads.json'
    $ShareResultsPath = Join-Path $FollowUpDirectory 'directory-services-share-results.json'
    $ErrorsPath = Join-Path $FollowUpDirectory 'operational-errors.json'

    Require-File -Path $MetadataPath -Label 'Directory-services metadata'
    Require-File -Path $LeadPath -Label 'Interesting-name leads'
    Require-File -Path $ShareResultsPath -Label 'Directory-services share results'
    Require-File -Path $ErrorsPath -Label 'Operational errors'

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $FollowUpDirectory 'LeadReduction-v0.1.0'
    }

    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step -Status 'LOAD' -Message 'Loading preserved metadata, leads, share results, and operational errors.' -Color Yellow

    $MetadataRows = [object[]]@(Read-JsonArray -Path $MetadataPath -Label 'Directory-services metadata')
    $RawLeadRows = [object[]]@(Read-JsonArray -Path $LeadPath -Label 'Interesting-name leads')
    $ShareResults = [object[]]@(Read-JsonArray -Path $ShareResultsPath -Label 'Directory-services share results')
    $ErrorRows = [object[]]@(Read-JsonArray -Path $ErrorsPath -Label 'Operational errors')

    $MetadataCount = [int]@($MetadataRows).Count
    $RawLeadCount = [int]@($RawLeadRows).Count
    $ErrorCount = [int]@($ErrorRows).Count

    Write-Step -Status 'OK' -Message "Loaded metadata=$MetadataCount, broad-leads=$RawLeadCount, share-results=$(@($ShareResults).Count), errors=$ErrorCount." -Color Green

    $GroupedLeads = @(
        $RawLeadRows |
            Group-Object {
                Get-LogicalPathKey -Share ([string]$_.Share) -RelativePath ([string]$_.RelativePath)
            }
    )

    $LogicalList = New-Object 'System.Collections.Generic.List[object]'
    $LogicalIndex = 0

    foreach ($Group in $GroupedLeads) {
        $LogicalIndex++
        $Observations = [object[]]@($Group.Group)
        $First = $Observations[0]
        $Classification = Get-ArtifactClassification `
            -Share ([string]$First.Share) `
            -RelativePath ([string]$First.RelativePath) `
            -Extension ([string]$First.Extension) `
            -EntryType ([string]$First.EntryType)

        $SourceTargets = [object[]]@(
            $Observations.Target |
                Sort-Object -Unique
        )
        $SourceUncPaths = [object[]]@(
            $Observations.UncPath |
                Sort-Object -Unique
        )

        $LogicalList.Add([pscustomobject][ordered]@{
            LogicalLeadId = 'DSLEAD-{0:D4}' -f $LogicalIndex
            LogicalPathKey = [string]$Group.Name
            Share = [string]$First.Share
            RelativePath = [string]$First.RelativePath
            NormalizedRelativePath = Normalize-RelativePath -Value $First.RelativePath
            EntryType = [string]$First.EntryType
            Extension = [string]$First.Extension
            Size = $First.Size
            LastWriteTimeUtc = [string]$First.LastWriteTimeUtc
            ObservationCount = @($Observations).Count
            SourceTargetCount = @($SourceTargets).Count
            SourceTargets = $SourceTargets
            SourceUncPaths = $SourceUncPaths
            ReplicatedDuplicate = (@($SourceTargets).Count -gt 1)
            Priority = [string]$Classification.Priority
            Category = [string]$Classification.Category
            ClassificationReason = [string]$Classification.Reason
            ContentValidationEligible = [bool]$Classification.ContentValidationEligible
            ContentRead = $false
            SecurityImpact = 'NotEstablished'
        })
    }

    $LogicalRows = [object[]]$LogicalList.ToArray()
    $LogicalCount = [int]@($LogicalRows).Count
    $DuplicatesRemoved = $RawLeadCount - $LogicalCount

    $P1Rows = [object[]]@($LogicalRows | Where-Object { $_.Priority -eq 'P1' })
    $P2Rows = [object[]]@($LogicalRows | Where-Object { $_.Priority -eq 'P2' })
    $P3Rows = [object[]]@($LogicalRows | Where-Object { $_.Priority -eq 'P3' })
    $InformationalRows = [object[]]@($LogicalRows | Where-Object { $_.Priority -eq 'Informational' })

    $QueueRows = [object[]]@(
        $LogicalRows |
            Where-Object { [bool]$_.ContentValidationEligible } |
            Sort-Object `
                @{Expression={switch ($_.Priority) {'P1'{1};'P2'{2};'P3'{3};default{9}}}},
                Category,
                Share,
                NormalizedRelativePath |
            Select-Object -First $MaximumValidationQueue
    )

    $QueueList = New-Object 'System.Collections.Generic.List[object]'
    $QueueIndex = 0
    foreach ($Lead in $QueueRows) {
        $QueueIndex++
        $QueueList.Add([pscustomobject][ordered]@{
            QueueId = 'DSCONTENT-{0:D3}' -f $QueueIndex
            LogicalLeadId = [string]$Lead.LogicalLeadId
            Priority = [string]$Lead.Priority
            Category = [string]$Lead.Category
            Share = [string]$Lead.Share
            RelativePath = [string]$Lead.RelativePath
            SourceTargets = [object[]]@($Lead.SourceTargets)
            PreferredTarget = [string](@($Lead.SourceTargets | Sort-Object | Select-Object -First 1)[0])
            MaximumBytesToRead = 1048576
            SearchMode = 'RedactedSensitivePatternValidation'
            ConsoleSecretOutput = $false
            HtmlSecretOutput = $false
            RemoteChange = $false
            RequiredBeforeExecution = 'Display exact target, UNC path, byte limit, detection classes, and redaction behavior'
            EvidenceState = 'Metadata lead only; content not yet read'
        })
    }
    $ValidationQueue = [object[]]$QueueList.ToArray()

    $ClassifiedErrorRows = [object[]]@(
        foreach ($ErrorRow in $ErrorRows) {
            [pscustomobject][ordered]@{
                Stage = [string]$ErrorRow.Stage
                Target = [string]$ErrorRow.Target
                Share = [string]$ErrorRow.Share
                RelativePath = [string]$ErrorRow.RelativePath
                Category = Get-ErrorCategory -ErrorText ([string]$ErrorRow.Error)
                Error = [string]$ErrorRow.Error
                AffectsRoot = [string]::IsNullOrWhiteSpace([string]$ErrorRow.RelativePath)
            }
        }
    )

    $ErrorDistribution = [object[]]@(
        $ClassifiedErrorRows |
            Group-Object Category |
            Sort-Object Count -Descending |
            ForEach-Object {
                [pscustomobject]@{
                    Category = [string]$_.Name
                    Count = [int]$_.Count
                }
            }
    )

    $RootErrorCount = [int]@($ClassifiedErrorRows | Where-Object { [bool]$_.AffectsRoot }).Count
    $ChildPathErrorCount = $ErrorCount - $RootErrorCount

    $PriorityDistribution = [object[]]@(
        @(
            [pscustomobject]@{Priority='P1';Count=@($P1Rows).Count}
            [pscustomobject]@{Priority='P2';Count=@($P2Rows).Count}
            [pscustomobject]@{Priority='P3';Count=@($P3Rows).Count}
            [pscustomobject]@{Priority='Informational';Count=@($InformationalRows).Count}
        )
    )

    $CategoryDistribution = [object[]]@(
        $LogicalRows |
            Group-Object Category |
            Sort-Object Count -Descending |
            ForEach-Object {
                [pscustomobject]@{
                    Category = [string]$_.Name
                    Count = [int]$_.Count
                }
            }
    )

    $Disposition = 'NoContentValidationCandidateDetected'
    if (@($P1Rows).Count -gt 0) {
        $Disposition = 'HighPriorityMetadataCandidatesDetected'
    }
    elseif (@($ValidationQueue).Count -gt 0) {
        $Disposition = 'BoundedContentValidationQueueCreated'
    }

    $LogicalJson = Join-Path $OutputDirectory 'logical-directory-services-leads.json'
    $LogicalCsv = Join-Path $OutputDirectory 'logical-directory-services-leads.csv'
    $QueueJson = Join-Path $OutputDirectory 'content-validation-queue.json'
    $QueueCsv = Join-Path $OutputDirectory 'content-validation-queue.csv'
    $ErrorsJson = Join-Path $OutputDirectory 'classified-metadata-errors.json'
    $ErrorsCsv = Join-Path $OutputDirectory 'classified-metadata-errors.csv'
    $ErrorDistributionJson = Join-Path $OutputDirectory 'metadata-error-distribution.json'
    $ErrorDistributionCsv = Join-Path $OutputDirectory 'metadata-error-distribution.csv'
    $PriorityJson = Join-Path $OutputDirectory 'lead-priority-distribution.json'
    $PriorityCsv = Join-Path $OutputDirectory 'lead-priority-distribution.csv'
    $CategoryJson = Join-Path $OutputDirectory 'lead-category-distribution.json'
    $CategoryCsv = Join-Path $OutputDirectory 'lead-category-distribution.csv'

    Write-JsonArray -Rows $LogicalRows -Path $LogicalJson
    $LogicalRows | Export-Csv -LiteralPath $LogicalCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ValidationQueue -Path $QueueJson
    $ValidationQueue | Export-Csv -LiteralPath $QueueCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ClassifiedErrorRows -Path $ErrorsJson
    $ClassifiedErrorRows | Export-Csv -LiteralPath $ErrorsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ErrorDistribution -Path $ErrorDistributionJson
    $ErrorDistribution | Export-Csv -LiteralPath $ErrorDistributionCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $PriorityDistribution -Path $PriorityJson
    $PriorityDistribution | Export-Csv -LiteralPath $PriorityCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $CategoryDistribution -Path $CategoryJson
    $CategoryDistribution | Export-Csv -LiteralPath $CategoryCsv -NoTypeInformation -Encoding UTF8

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        Status = 'Completed'
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        SourceFollowUpDirectory = $FollowUpDirectory
        Disposition = $Disposition
        Counts = [pscustomobject][ordered]@{
            MetadataEntries = $MetadataCount
            RawInterestingNameLeads = $RawLeadCount
            LogicalUniqueLeads = $LogicalCount
            ReplicatedDuplicateObservationsRemoved = $DuplicatesRemoved
            P1Leads = @($P1Rows).Count
            P2Leads = @($P2Rows).Count
            P3Leads = @($P3Rows).Count
            InformationalLeads = @($InformationalRows).Count
            ContentValidationQueue = @($ValidationQueue).Count
            MetadataErrors = $ErrorCount
            RootLevelErrors = $RootErrorCount
            ChildPathErrors = $ChildPathErrorCount
        }
        PriorityDistribution = $PriorityDistribution
        CategoryDistribution = $CategoryDistribution
        ErrorDistribution = $ErrorDistribution
        InterpretationBoundary = @(
            'Deduplication treats the same share and relative path across domain controllers as one logical artifact.',
            'Priority is a content-validation routing decision, not vulnerability severity.',
            'No file content was read in this stage.',
            'A filename or path match does not prove sensitive content or security impact.',
            'A later content validator must redact secrets and read only evidence-selected files within a fixed byte limit.'
        )
        Safety = [pscustomobject][ordered]@{
            NetworkActivity = 'None'
            ActiveDirectoryQueries = 'None'
            SmbAuthentication = 'None'
            ShareAccess = 'None'
            ContentReads = 'None'
            Hashes = 'None'
            RemoteFileChanges = 'None'
            RelayAttempts = 'None'
            RemoteExecution = 'None'
            OllamaActivity = 'None'
        }
    }

    $SummaryPath = Join-Path $OutputDirectory 'directory-services-lead-reduction-summary.json'
    Write-JsonDocument -Document $Summary -Path $SummaryPath

    $PriorityHtml = ($PriorityDistribution | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td></tr>' -f
            (Convert-HtmlText $_.Priority),
            (Convert-HtmlText $_.Count)
    }) -join "`n"

    $QueueHtml = ($ValidationQueue | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f
            (Convert-HtmlText $_.QueueId),
            (Convert-HtmlText $_.Priority),
            (Convert-HtmlText $_.Category),
            (Convert-HtmlText $_.Share),
            (Convert-HtmlText $_.RelativePath)
    }) -join "`n"

    $ReportPath = Join-Path $OutputDirectory 'MSADPT-SMB-Directory-Services-Lead-Reduction.html'
    $Html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MSADPT SMB Directory Services Lead Reduction</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#17202a}
h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}
th{background:#eaf2f8}.note{color:#5d6d7e}
</style>
</head>
<body>
<h1>MSADPT SMB Directory Services Lead Reduction</h1>
<div class="card">
<b>Disposition:</b> $(Convert-HtmlText $Disposition)<br>
<b>Raw filename leads:</b> $RawLeadCount<br>
<b>Logical unique leads:</b> $LogicalCount<br>
<b>Replicated duplicates removed:</b> $DuplicatesRemoved<br>
<b>Content-validation queue:</b> $(@($ValidationQueue).Count)<br>
<b>Metadata errors:</b> $ErrorCount<br>
<b>Root-level errors:</b> $RootErrorCount<br>
<b>Network activity:</b> None<br>
<b>Content read:</b> None
</div>
<h2>Priority Distribution</h2>
<table><tr><th>Priority</th><th>Count</th></tr>$PriorityHtml</table>
<h2>Bounded Content-Validation Queue</h2>
<table><tr><th>Queue ID</th><th>Priority</th><th>Category</th><th>Share</th><th>Relative path</th></tr>$QueueHtml</table>
<h2>Evidence</h2>
<ul>
<li><a href="logical-directory-services-leads.csv">Logical lead inventory</a></li>
<li><a href="content-validation-queue.csv">Content-validation queue</a></li>
<li><a href="lead-priority-distribution.csv">Priority distribution</a></li>
<li><a href="lead-category-distribution.csv">Category distribution</a></li>
<li><a href="classified-metadata-errors.csv">Classified metadata errors</a></li>
<li><a href="metadata-error-distribution.csv">Error distribution</a></li>
<li><a href="directory-services-lead-reduction-summary.json">Structured summary</a></li>
</ul>
<p class="note">Priorities route validation work and are not vulnerability severities. No file content was read.</p>
</body>
</html>
"@

    [IO.File]::WriteAllText(
        $ReportPath,
        $Html,
        (New-Object Text.UTF8Encoding($false))
    )

    $Files = @(
        Get-ChildItem -LiteralPath $OutputDirectory -File |
            Where-Object { $_.Name -ne 'evidence-manifest.json' } |
            Sort-Object Name
    )
    $ManifestRows = [object[]]@(
        foreach ($File in $Files) {
            [pscustomobject]@{
                Name = $File.Name
                Size = [int64]$File.Length
                SHA256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
            }
        }
    )
    $ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument -Document ([pscustomobject]@{
        SchemaVersion = '1.0'
        Status = 'Completed'
        FileCount = @($ManifestRows).Count
        Files = $ManifestRows
    }) -Path $ManifestPath

    Write-Step -Status 'DONE' -Message "Lead reduction complete: raw=$RawLeadCount, logical=$LogicalCount, duplicates=$DuplicatesRemoved, P1=$(@($P1Rows).Count), P2=$(@($P2Rows).Count), P3=$(@($P3Rows).Count), queue=$(@($ValidationQueue).Count), disposition=$Disposition." -Color Green

    [pscustomobject][ordered]@{
        Status = 'Passed'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        Disposition = $Disposition
        MetadataEntryCount = $MetadataCount
        RawInterestingNameLeadCount = $RawLeadCount
        LogicalUniqueLeadCount = $LogicalCount
        ReplicatedDuplicateObservationCount = $DuplicatesRemoved
        P1LeadCount = @($P1Rows).Count
        P2LeadCount = @($P2Rows).Count
        P3LeadCount = @($P3Rows).Count
        InformationalLeadCount = @($InformationalRows).Count
        ContentValidationQueueCount = @($ValidationQueue).Count
        MetadataErrorCount = $ErrorCount
        RootLevelErrorCount = $RootErrorCount
        ChildPathErrorCount = $ChildPathErrorCount
        OutputDirectory = $OutputDirectory
        HtmlReportPath = $ReportPath
        SummaryPath = $SummaryPath
        ManifestPath = $ManifestPath
        NetworkActivity = 'None'
        ActiveDirectoryQueries = 'None'
        SmbAuthentication = 'None'
        ShareAccess = 'None'
        ContentReads = 'None'
        Hashes = 'None'
        RemoteFileChanges = 'None'
        RelayAttempts = 'None'
        RemoteExecution = 'None'
        OllamaActivity = 'None'
    }
}
catch {
    Write-Step -Status 'FAIL' -Message $_.Exception.Message -Color Red
    throw
}
