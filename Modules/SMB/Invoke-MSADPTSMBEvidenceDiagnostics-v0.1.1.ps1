<#
.SYNOPSIS
Diagnoses an existing MSADPT SMB baseline and generates a minimal continuation plan.

.DESCRIPTION
Consumes evidence from a completed MSADPT SMB Share and Pivot Surface assessment. Classifies
operational errors, correlates TCP/445 reachability with signing and share-enumeration evidence,
checks evidence consistency, and selects no more than three hosts for method validation.

This script is local-only. It performs no Active Directory queries, DNS lookups, network connections,
Nmap execution, SMB authentication, share enumeration, file access, file writes, relay, credential
capture, or remote execution.

.NOTES
Version: 0.1.1
Package identity: MSADPT-SMB-EVIDENCE-DIAGNOSTICS
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceDirectory,

    [string]$OutputDirectory,

    [ValidateRange(1,10)]
    [int]$MaximumValidationTargets = 3,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageIdentity = 'MSADPT-SMB-EVIDENCE-DIAGNOSTICS'
$PackageVersion = '0.1.1'

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

function Read-JsonDocument {
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

function Get-ErrorCategory {
    param(
        [string]$Stage,
        [string]$ErrorText
    )

    $Text = [string]$ErrorText

    if ($Stage -eq 'ShareEnumeration') {
        if ($Text -match '(?i)status\s*5\b|access is denied|access denied') {
            return 'ShareEnumerationAccessDenied'
        }
        if ($Text -match '(?i)status\s*53\b|network path was not found') {
            return 'ShareEnumerationNetworkPathNotFound'
        }
        if ($Text -match '(?i)status\s*1722\b|RPC server is unavailable') {
            return 'ShareEnumerationRpcUnavailable'
        }
        if ($Text -match '(?i)status\s*2114\b|server service is not started') {
            return 'ShareEnumerationServerServiceUnavailable'
        }
        if ($Text -match '(?i)status\s*124\b|invalid level') {
            return 'ShareEnumerationApiLevelInvalid'
        }
        return 'ShareEnumerationOther'
    }

    if ($Stage -eq 'NmapSMB') {
        return 'NmapFailure'
    }

    if ($Stage -eq 'Tcp445') {
        return 'Tcp445Failure'
    }

    if ($Stage -eq 'ShareMetadata') {
        if ($Text -match '(?i)access is denied|access denied') {
            return 'ShareMetadataAccessDenied'
        }
        return 'ShareMetadataOther'
    }

    return 'Other'
}

function Get-TargetRole {
    param([object]$TargetRecord)

    $OperatingSystem = [string]$TargetRecord.OperatingSystem
    $HostName = [string]$TargetRecord.HostName

    if ($HostName -match '(?i)DC\d*$' -or $OperatingSystem -match '(?i)Domain Controller') {
        return 'ProbableDomainController'
    }

    if ($OperatingSystem -match '(?i)Server') {
        return 'MemberServer'
    }

    return 'Unknown'
}

try {
    Write-Step -Status 'START' -Message "$PackageIdentity v$PackageVersion" -Color Cyan
    Write-Step -Status 'INFO' -Message 'Local evidence diagnostics only. No network activity will occur.' -Color DarkGray

    if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
        throw "EvidenceDirectoryMissing: $EvidenceDirectory"
    }

    $TargetsPath = Join-Path $EvidenceDirectory 'smb-targets.json'
    $TcpPath = Join-Path $EvidenceDirectory 'smb-tcp-reachability.json'
    $SigningPath = Join-Path $EvidenceDirectory 'smb-signing-observations.json'
    $SharesPath = Join-Path $EvidenceDirectory 'smb-share-inventory.json'
    $MetadataPath = Join-Path $EvidenceDirectory 'smb-file-metadata.json'
    $ErrorsPath = Join-Path $EvidenceDirectory 'operational-errors.json'
    $SourceSummaryPath = Join-Path $EvidenceDirectory 'smb-share-pivot-summary.json'

    Require-File -Path $TargetsPath -Label 'SMB target inventory'
    Require-File -Path $TcpPath -Label 'SMB TCP reachability'
    Require-File -Path $SigningPath -Label 'SMB signing observations'
    Require-File -Path $SharesPath -Label 'SMB share inventory'
    Require-File -Path $MetadataPath -Label 'SMB file metadata'
    Require-File -Path $ErrorsPath -Label 'Operational errors'
    Require-File -Path $SourceSummaryPath -Label 'Source summary'

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $EvidenceDirectory 'EvidenceDiagnostics-v0.1.1'
    }

    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step -Status 'LOAD' -Message 'Loading completed SMB baseline evidence.' -Color Yellow

    $Targets = [object[]]@(Read-JsonArray -Path $TargetsPath -Label 'SMB target inventory')
    $TcpRows = [object[]]@(Read-JsonArray -Path $TcpPath -Label 'SMB TCP reachability')
    $SigningRows = [object[]]@(Read-JsonArray -Path $SigningPath -Label 'SMB signing observations')
    $ShareRows = [object[]]@(Read-JsonArray -Path $SharesPath -Label 'SMB share inventory')
    $MetadataRows = [object[]]@(Read-JsonArray -Path $MetadataPath -Label 'SMB file metadata')
    $ErrorRows = [object[]]@(Read-JsonArray -Path $ErrorsPath -Label 'Operational errors')
    $SourceSummary = Read-JsonDocument -Path $SourceSummaryPath -Label 'Source summary'

    $TargetCount = [int]@($Targets).Count
    $TcpCount = [int]@($TcpRows).Count
    $SigningCount = [int]@($SigningRows).Count
    $ShareCount = [int]@($ShareRows).Count
    $MetadataCount = [int]@($MetadataRows).Count
    $ErrorCount = [int]@($ErrorRows).Count

    Write-Step -Status 'OK' -Message "Loaded targets=$TargetCount, TCP=$TcpCount, signing=$SigningCount, shares=$ShareCount, metadata=$MetadataCount, errors=$ErrorCount." -Color Green

    $TargetByName = @{}
    foreach ($Target in $Targets) {
        $Key = ([string]$Target.HostName).ToLowerInvariant()
        $TargetByName[$Key] = $Target
    }

    $ReachableRows = [object[]]@(
        $TcpRows |
            Where-Object { [bool]$_.Connected }
    )
    $ReachableCount = [int]@($ReachableRows).Count

    $ClassifiedErrorList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ErrorRow in $ErrorRows) {
        $Category = Get-ErrorCategory -Stage ([string]$ErrorRow.Stage) -ErrorText ([string]$ErrorRow.Error)
        $ClassifiedErrorList.Add([pscustomobject][ordered]@{
            Stage = [string]$ErrorRow.Stage
            Target = [string]$ErrorRow.Target
            Protocol = [string]$ErrorRow.Protocol
            Port = $ErrorRow.Port
            Category = $Category
            Error = [string]$ErrorRow.Error
        })
    }
    $ClassifiedErrors = [object[]]$ClassifiedErrorList.ToArray()

    $ErrorDistribution = [object[]]@(
        $ClassifiedErrors |
            Group-Object Category |
            Sort-Object Count -Descending |
            ForEach-Object {
                [pscustomobject]@{
                    Category = [string]$_.Name
                    Count = [int]$_.Count
                }
            }
    )

    $ShareEnumerationErrors = [object[]]@(
        $ClassifiedErrors |
            Where-Object { $_.Stage -eq 'ShareEnumeration' }
    )
    $ShareEnumerationErrorCount = [int]@($ShareEnumerationErrors).Count

    $SigningLeadRows = [object[]]@(
        $SigningRows |
            Where-Object {
                $_.SigningState -in @('EnabledNotRequired','Disabled')
            } |
            Sort-Object SigningState, Target
    )
    $SigningLeadCount = [int]@($SigningLeadRows).Count

    $SmbV1Rows = [object[]]@(
        $SigningRows |
            Where-Object { [bool]$_.SmbV1Detected }
    )
    $SmbV1Count = [int]@($SmbV1Rows).Count

    $ReachableWithoutSigning = [object[]]@(
        foreach ($Reachable in $ReachableRows) {
            $TargetHostName = [string]$Reachable.Target
            if (@($SigningRows | Where-Object { [string]$_.Target -eq $TargetHostName }).Count -eq 0) {
                [pscustomobject]@{
                    Target = $TargetHostName
                    Reason = 'No signing observation in completed baseline'
                }
            }
        }
    )

    $ShareEnumerationTargetSet = @{}
    foreach ($ErrorRow in $ShareEnumerationErrors) {
        $ShareEnumerationTargetSet[([string]$ErrorRow.Target).ToLowerInvariant()] = $true
    }

    $ReachableShareStatusList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Reachable in $ReachableRows) {
        $TargetHostName = [string]$Reachable.Target
        $Key = $TargetHostName.ToLowerInvariant()
        $TargetRecord = $null
        if ($TargetByName.ContainsKey($Key)) {
            $TargetRecord = $TargetByName[$Key]
        }

        $Signing = @($SigningRows | Where-Object { [string]$_.Target -eq $TargetHostName } | Select-Object -First 1)
        $HostShares = @($ShareRows | Where-Object { [string]$_.Target -eq $TargetHostName })
        $HostErrors = @($ShareEnumerationErrors | Where-Object { [string]$_.Target -eq $TargetHostName })

        $ShareState = 'NoShareRowsAndNoEnumerationError'
        if ($HostShares.Count -gt 0) {
            $ShareState = 'ShareRowsPresent'
        }
        elseif ($HostErrors.Count -gt 0) {
            $ShareState = 'ShareEnumerationFailed'
        }

        $ReachableShareStatusList.Add([pscustomobject][ordered]@{
            Target = $TargetHostName
            OperatingSystem = if ($null -ne $TargetRecord) { [string]$TargetRecord.OperatingSystem } else { $null }
            TargetRole = if ($null -ne $TargetRecord) { Get-TargetRole -TargetRecord $TargetRecord } else { 'Unknown' }
            Tcp445Reachable = $true
            SigningState = if ($Signing.Count -gt 0) { [string]$Signing[0].SigningState } else { 'NotCollected' }
            SmbV1Detected = if ($Signing.Count -gt 0) { [bool]$Signing[0].SmbV1Detected } else { $false }
            ShareState = $ShareState
            ShareRowCount = $HostShares.Count
            EnumerationErrorCount = $HostErrors.Count
            EnumerationErrorCategory = if ($HostErrors.Count -gt 0) { [string]$HostErrors[0].Category } else { $null }
        })
    }
    $ReachableShareStatus = [object[]]$ReachableShareStatusList.ToArray()

    $ConsistencyList = New-Object 'System.Collections.Generic.List[object]'
    $ConsistencyList.Add([pscustomobject]@{
        Check = 'Target count equals TCP observation count'
        Passed = ($TargetCount -eq $TcpCount)
        Expected = $TargetCount
        Actual = $TcpCount
    })
    $ConsistencyList.Add([pscustomobject]@{
        Check = 'Source summary target count equals target inventory'
        Passed = ([int]$SourceSummary.Counts.Targets -eq $TargetCount)
        Expected = [int]$SourceSummary.Counts.Targets
        Actual = $TargetCount
    })
    $ConsistencyList.Add([pscustomobject]@{
        Check = 'Source summary reachable count equals derived reachability'
        Passed = ([int]$SourceSummary.Counts.Tcp445Reachable -eq $ReachableCount)
        Expected = [int]$SourceSummary.Counts.Tcp445Reachable
        Actual = $ReachableCount
    })
    $ConsistencyList.Add([pscustomobject]@{
        Check = 'Source summary share count equals share evidence'
        Passed = ([int]$SourceSummary.Counts.Shares -eq $ShareCount)
        Expected = [int]$SourceSummary.Counts.Shares
        Actual = $ShareCount
    })
    $ConsistencyList.Add([pscustomobject]@{
        Check = 'Source summary operational error count equals error evidence'
        Passed = ([int]$SourceSummary.Counts.OperationalErrors -eq $ErrorCount)
        Expected = [int]$SourceSummary.Counts.OperationalErrors
        Actual = $ErrorCount
    })
    $ConsistencyRows = [object[]]$ConsistencyList.ToArray()
    $FailedConsistencyCount = [int]@($ConsistencyRows | Where-Object { -not [bool]$_.Passed }).Count

    $ValidationList = New-Object 'System.Collections.Generic.List[object]'
    $SelectedTargets = @{}

    function Add-ValidationTarget {
        param(
            [string]$Target,
            [string]$SelectionReason,
            [string]$SigningState,
            [string]$TargetRole,
            [string]$EnumerationErrorCategory
        )

        if ([string]::IsNullOrWhiteSpace($Target)) {
            return
        }
        if ($ValidationList.Count -ge $MaximumValidationTargets) {
            return
        }
        $Key = $Target.ToLowerInvariant()
        if ($SelectedTargets.ContainsKey($Key)) {
            return
        }

        $SelectedTargets[$Key] = $true
        $ValidationList.Add([pscustomobject][ordered]@{
            Target = $Target
            SelectionReason = $SelectionReason
            SigningState = $SigningState
            TargetRole = $TargetRole
            PriorEnumerationErrorCategory = $EnumerationErrorCategory
            PlannedNetworkOperation = 'TCP/445 SMB share-enumeration method validation only'
            RepeatTcpProbe = $false
            RepeatNmap = $false
            ShareWriteTest = $false
            ContentRead = $false
        })
    }

    $OptionalCandidates = @(
        $ReachableShareStatus |
            Where-Object { $_.SigningState -in @('EnabledNotRequired','Disabled') } |
            Sort-Object Target
    )
    foreach ($Candidate in $OptionalCandidates) {
        Add-ValidationTarget -Target $Candidate.Target -SelectionReason 'Reachable host with optional or disabled SMB signing' -SigningState $Candidate.SigningState -TargetRole $Candidate.TargetRole -EnumerationErrorCategory $Candidate.EnumerationErrorCategory
    }

    $DcCandidates = @(
        $ReachableShareStatus |
            Where-Object { $_.TargetRole -eq 'ProbableDomainController' } |
            Sort-Object Target
    )
    foreach ($Candidate in $DcCandidates) {
        Add-ValidationTarget -Target $Candidate.Target -SelectionReason 'Reachable probable domain controller control target' -SigningState $Candidate.SigningState -TargetRole $Candidate.TargetRole -EnumerationErrorCategory $Candidate.EnumerationErrorCategory
    }

    $MemberCandidates = @(
        $ReachableShareStatus |
            Where-Object { $_.TargetRole -eq 'MemberServer' } |
            Sort-Object Target
    )
    foreach ($Candidate in $MemberCandidates) {
        Add-ValidationTarget -Target $Candidate.Target -SelectionReason 'Reachable member server control target' -SigningState $Candidate.SigningState -TargetRole $Candidate.TargetRole -EnumerationErrorCategory $Candidate.EnumerationErrorCategory
    }

    $ValidationTargets = [object[]]$ValidationList.ToArray()
    $ValidationTargetCount = [int]@($ValidationTargets).Count

    $PrimaryEnumerationCategory = $null
    if (@($ErrorDistribution | Where-Object { $_.Category -like 'ShareEnumeration*' }).Count -gt 0) {
        $PrimaryEnumerationCategory = [string](
            $ErrorDistribution |
                Where-Object { $_.Category -like 'ShareEnumeration*' } |
                Sort-Object Count -Descending |
                Select-Object -First 1 -ExpandProperty Category
        )
    }

    $EnumerationDisposition = 'Inconclusive'
    if ($ShareCount -gt 0) {
        $EnumerationDisposition = 'ShareEnumerationSucceededOnAtLeastOneHost'
    }
    elseif ($ShareEnumerationErrorCount -eq $ReachableCount -and $ReachableCount -gt 0) {
        $EnumerationDisposition = 'SystematicShareEnumerationFailure'
    }
    elseif ($ShareEnumerationErrorCount -gt 0) {
        $EnumerationDisposition = 'PartialShareEnumerationFailure'
    }
    elseif ($ReachableCount -gt 0) {
        $EnumerationDisposition = 'NoShareRowsAndNoRecordedEnumerationFailure'
    }

    $ContinuationPlan = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        Status = 'Completed'
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        SourceEvidenceDirectory = $EvidenceDirectory
        BaselineReuse = [pscustomobject][ordered]@{
            ReuseTargetInventory = $true
            ReuseTcpReachability = $true
            ReuseSigningEvidence = $true
            RepeatUnreachableTargets = $false
            RepeatFullTargetDiscovery = $false
            RepeatNmap = $false
        }
        Counts = [pscustomobject][ordered]@{
            OriginalTargets = $TargetCount
            ReachableTargets = $ReachableCount
            UnreachableTargetsSkipped = ($TargetCount - $ReachableCount)
            ShareEnumerationErrors = $ShareEnumerationErrorCount
            SigningLeads = $SigningLeadCount
            SmbV1Leads = $SmbV1Count
            ValidationTargets = $ValidationTargetCount
            EvidenceConsistencyFailures = $FailedConsistencyCount
        }
        EnumerationDisposition = $EnumerationDisposition
        PrimaryEnumerationErrorCategory = $PrimaryEnumerationCategory
        ValidationTargets = $ValidationTargets
        InterpretationBoundary = @(
            'The continuation plan does not perform network activity.',
            'No share rows does not prove the absence of shares when enumeration failed.',
            'The validation target list is limited to method validation, not a broad rescan.',
            'Existing TCP and Nmap evidence must be reused.'
        )
        Safety = [pscustomobject][ordered]@{
            NetworkActivity = 'None'
            ActiveDirectoryQueries = 'None'
            SmbAuthentication = 'None'
            ShareEnumeration = 'None'
            RemoteFileChanges = 'None'
            ContentReads = 'None'
            RelayAttempts = 'None'
            RemoteExecution = 'None'
            OllamaActivity = 'None'
        }
    }

    $ClassifiedErrorsJson = Join-Path $OutputDirectory 'classified-operational-errors.json'
    $ClassifiedErrorsCsv = Join-Path $OutputDirectory 'classified-operational-errors.csv'
    $ErrorDistributionJson = Join-Path $OutputDirectory 'error-distribution.json'
    $ErrorDistributionCsv = Join-Path $OutputDirectory 'error-distribution.csv'
    $ReachableStatusJson = Join-Path $OutputDirectory 'reachable-host-share-status.json'
    $ReachableStatusCsv = Join-Path $OutputDirectory 'reachable-host-share-status.csv'
    $SigningLeadsJson = Join-Path $OutputDirectory 'smb-signing-leads.json'
    $SigningLeadsCsv = Join-Path $OutputDirectory 'smb-signing-leads.csv'
    $ConsistencyJson = Join-Path $OutputDirectory 'evidence-consistency-checks.json'
    $ConsistencyCsv = Join-Path $OutputDirectory 'evidence-consistency-checks.csv'
    $ValidationTargetsJson = Join-Path $OutputDirectory 'minimal-validation-targets.json'
    $ValidationTargetsCsv = Join-Path $OutputDirectory 'minimal-validation-targets.csv'
    $PlanPath = Join-Path $OutputDirectory 'smb-continuation-plan.json'

    Write-JsonArray -Rows $ClassifiedErrors -Path $ClassifiedErrorsJson
    $ClassifiedErrors | Export-Csv -LiteralPath $ClassifiedErrorsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ErrorDistribution -Path $ErrorDistributionJson
    $ErrorDistribution | Export-Csv -LiteralPath $ErrorDistributionCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ReachableShareStatus -Path $ReachableStatusJson
    $ReachableShareStatus | Export-Csv -LiteralPath $ReachableStatusCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $SigningLeadRows -Path $SigningLeadsJson
    $SigningLeadRows | Export-Csv -LiteralPath $SigningLeadsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ConsistencyRows -Path $ConsistencyJson
    $ConsistencyRows | Export-Csv -LiteralPath $ConsistencyCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ValidationTargets -Path $ValidationTargetsJson
    $ValidationTargets | Export-Csv -LiteralPath $ValidationTargetsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonDocument -Document $ContinuationPlan -Path $PlanPath

    $ErrorHtml = ($ErrorDistribution | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td></tr>' -f
            (Convert-HtmlText $_.Category),
            (Convert-HtmlText $_.Count)
    }) -join "`n"

    $SigningHtml = ($SigningLeadRows | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f
            (Convert-HtmlText $_.Target),
            (Convert-HtmlText $_.SigningState),
            (Convert-HtmlText $_.SmbV1Detected)
    }) -join "`n"

    $ValidationHtml = ($ValidationTargets | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
            (Convert-HtmlText $_.Target),
            (Convert-HtmlText $_.SelectionReason),
            (Convert-HtmlText $_.SigningState),
            (Convert-HtmlText $_.PriorEnumerationErrorCategory)
    }) -join "`n"

    $ReportPath = Join-Path $OutputDirectory 'MSADPT-SMB-Evidence-Diagnostics.html'
    $Html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MSADPT SMB Evidence Diagnostics</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#17202a}
h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}
th{background:#eaf2f8}.note{color:#5d6d7e}
</style>
</head>
<body>
<h1>MSADPT SMB Evidence Diagnostics and Continuation Plan</h1>
<div class="card">
<b>Original targets:</b> $TargetCount<br>
<b>Reachable targets retained:</b> $ReachableCount<br>
<b>Unreachable targets skipped:</b> $($TargetCount-$ReachableCount)<br>
<b>Share-enumeration errors:</b> $ShareEnumerationErrorCount<br>
<b>Signing leads:</b> $SigningLeadCount<br>
<b>SMBv1 leads:</b> $SmbV1Count<br>
<b>Minimal validation targets:</b> $ValidationTargetCount<br>
<b>Enumeration disposition:</b> $(Convert-HtmlText $EnumerationDisposition)<br>
<b>Network activity:</b> None
</div>
<h2>Error Distribution</h2>
<table><tr><th>Category</th><th>Count</th></tr>$ErrorHtml</table>
<h2>SMB Signing Leads</h2>
<table><tr><th>Target</th><th>Signing state</th><th>SMBv1 detected</th></tr>$SigningHtml</table>
<h2>Minimal Method-Validation Targets</h2>
<table><tr><th>Target</th><th>Selection reason</th><th>Signing state</th><th>Prior error</th></tr>$ValidationHtml</table>
<h2>Evidence</h2>
<ul>
<li><a href="error-distribution.csv">Error distribution</a></li>
<li><a href="classified-operational-errors.csv">Classified errors</a></li>
<li><a href="reachable-host-share-status.csv">Reachable-host status</a></li>
<li><a href="smb-signing-leads.csv">Signing leads</a></li>
<li><a href="evidence-consistency-checks.csv">Consistency checks</a></li>
<li><a href="minimal-validation-targets.csv">Minimal validation targets</a></li>
<li><a href="smb-continuation-plan.json">Continuation plan</a></li>
</ul>
<p class="note">This is a local diagnostic stage. Completed TCP and Nmap evidence must be reused; the 412-host scan must not be repeated.</p>
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

    Write-Step -Status 'DONE' -Message "Diagnostics complete: reachable=$ReachableCount, share-errors=$ShareEnumerationErrorCount, signing-leads=$SigningLeadCount, validation-targets=$ValidationTargetCount, disposition=$EnumerationDisposition." -Color Green

    [pscustomobject][ordered]@{
        Status = 'Passed'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        OriginalTargetCount = $TargetCount
        ReachableTargetCount = $ReachableCount
        UnreachableTargetCount = ($TargetCount - $ReachableCount)
        ShareEnumerationErrorCount = $ShareEnumerationErrorCount
        PrimaryEnumerationErrorCategory = $PrimaryEnumerationCategory
        SigningLeadCount = $SigningLeadCount
        SmbV1LeadCount = $SmbV1Count
        ShareEvidenceCount = $ShareCount
        MinimalValidationTargetCount = $ValidationTargetCount
        MinimalValidationTargets = @($ValidationTargets.Target)
        EnumerationDisposition = $EnumerationDisposition
        EvidenceConsistencyFailureCount = $FailedConsistencyCount
        OutputDirectory = $OutputDirectory
        HtmlReportPath = $ReportPath
        ContinuationPlanPath = $PlanPath
        ManifestPath = $ManifestPath
        NetworkActivity = 'None'
        ActiveDirectoryQueries = 'None'
        SmbAuthentication = 'None'
        ShareEnumeration = 'None'
        RemoteFileChanges = 'None'
        ContentReads = 'None'
        RelayAttempts = 'None'
        RemoteExecution = 'None'
        OllamaActivity = 'None'
    }
}
catch {
    Write-Step -Status 'FAIL' -Message $_.Exception.Message -Color Red
    throw
}
