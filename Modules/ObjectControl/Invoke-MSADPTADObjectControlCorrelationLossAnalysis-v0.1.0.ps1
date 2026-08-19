<#
.SYNOPSIS
Analyzes nonroutine first-hop ACE matches that were removed during MSADPT semantic correlation.

.DESCRIPTION
Consumes starting-trustee-raw-ace-matches.json from the completed first-hop integrity audit.
Selects only nonroutine ACEs, resolves known high-impact property and control-access GUIDs,
reconstructs the semantic mapping decision, explains the likely correlation-loss reason,
and selects a bounded next validator when justified.

This stage is local only. It performs no Active Directory query, network operation, directory
write, password reset, membership change, SPN write, RBCD write, key-credential write,
owner change, DACL change, ticket operation, or Ollama call.

.NOTES
Version: 0.1.0
Package identity: MSADPT-AD-OBJECT-CONTROL-CORRELATION-LOSS-ANALYSIS
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FirstHopIntegrityAuditDirectory,

    [string]$OutputDirectory,

    [switch]$Quiet,

    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageIdentity = 'MSADPT-AD-OBJECT-CONTROL-CORRELATION-LOSS-ANALYSIS'
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

function Normalize-GuidText {
    param([object]$Value)

    $Text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return '00000000-0000-0000-0000-000000000000'
    }

    return $Text.Trim().Trim('{', '}').ToLowerInvariant()
}

function Get-GuidSemantic {
    param([string]$Guid)

    $Map = @{
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'WriteGroupMembership'
        'bf967a7f-0de6-11d0-a285-00aa003049e2' = 'WriteServicePrincipalName'
        '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'WriteRBCD'
        '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'WriteKeyCredentialLink'
        '00299570-246d-11d0-a768-00aa006e0529' = 'ResetPassword'
        'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'ChangePassword'
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'ReplicatingDirectoryChanges'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'ReplicatingDirectoryChangesAll'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'ReplicatingDirectoryChangesFilteredSet'
        'bf9679e8-0de6-11d0-a285-00aa003049e2' = 'WriteUserAccountControl'
    }

    if ($Map.ContainsKey($Guid)) {
        return [string]$Map[$Guid]
    }

    return $null
}

function Get-BroadCapability {
    param(
        [string]$Rights,
        [string]$TargetObjectType
    )

    if ($Rights -match 'GenericAll') {
        return 'GenericAll'
    }
    if ($Rights -match 'WriteDacl') {
        return 'WriteDacl'
    }
    if ($Rights -match 'WriteOwner') {
        return 'WriteOwner'
    }
    if ($Rights -match 'GenericWrite') {
        return 'GenericWrite'
    }

    if ($Rights -match 'WriteProperty') {
        switch ($TargetObjectType) {
            'Group' { return 'BroadGroupControl' }
            'Computer' { return 'BroadComputerControl' }
            'User' { return 'BroadUserControl' }
            'Domain' { return 'BroadDomainControl' }
            'OrganizationalUnit' { return 'BroadOuControl' }
            default { return 'UnresolvedWriteProperty' }
        }
    }

    if ($Rights -match 'ExtendedRight') {
        return 'UnresolvedExtendedRight'
    }

    if ($Rights -match 'Self') {
        return 'UnresolvedValidatedWrite'
    }

    return $null
}

function Get-Validator {
    param([string]$Capability)

    switch ($Capability) {
        'WriteGroupMembership' { return 'GroupMembershipBehavioralValidation' }
        'WriteServicePrincipalName' { return 'SpnWriteBehavioralValidation' }
        'WriteRBCD' { return 'RbcdWriteBehavioralValidation' }
        'WriteKeyCredentialLink' { return 'KeyCredentialWriteBehavioralValidation' }
        'ResetPassword' { return 'PasswordResetRightBehavioralValidation' }
        'WriteUserAccountControl' { return 'UserAccountControlBehavioralValidation' }
        'WriteDacl' { return 'DaclControlBehavioralValidation' }
        'WriteOwner' { return 'OwnershipControlBehavioralValidation' }
        'GenericAll' { return 'GenericObjectControlBehavioralValidation' }
        'GenericWrite' { return 'GenericObjectControlBehavioralValidation' }
        'ReplicatingDirectoryChanges' { return 'ReplicationRightsValidation' }
        'ReplicatingDirectoryChangesAll' { return 'ReplicationRightsValidation' }
        'ReplicatingDirectoryChangesFilteredSet' { return 'ReplicationRightsValidation' }
        default { return 'SemanticRefinementRequired' }
    }
}

function Get-SafetyState {
    param([string]$Capability)

    switch ($Capability) {
        'WriteGroupMembership' { return 'ReversibleIfDedicatedTestMemberAvailable' }
        'WriteServicePrincipalName' { return 'ReversibleIfOriginalSpnSetCaptured' }
        'WriteRBCD' { return 'ReversibleIfOriginalDescriptorCaptured' }
        'WriteKeyCredentialLink' { return 'HighImpactRequiresDedicatedTestIdentity' }
        'ResetPassword' { return 'NotSafeWithoutDedicatedTestIdentity' }
        'WriteUserAccountControl' { return 'HighImpactRequiresExactOriginalValue' }
        'WriteDacl' { return 'HighImpactRequiresExactDaclBackupAndRestore' }
        'WriteOwner' { return 'HighImpactRequiresExactOwnerRestore' }
        'GenericAll' { return 'SemanticOperationAndRollbackRequired' }
        'GenericWrite' { return 'SemanticOperationAndRollbackRequired' }
        'ReplicatingDirectoryChanges' { return 'ReadOnlyEffectiveRightsValidationFirst' }
        'ReplicatingDirectoryChangesAll' { return 'ReadOnlyEffectiveRightsValidationFirst' }
        'ReplicatingDirectoryChangesFilteredSet' { return 'ReadOnlyEffectiveRightsValidationFirst' }
        default { return 'LocalSemanticRefinementOnly' }
    }
}

try {
    Write-Step -Status 'START' -Message "$PackageIdentity v$PackageVersion" -Color Cyan
    Write-Step -Status 'INFO' -Message 'Local analysis of preserved first-hop matches only. No AD or network operations.' -Color DarkGray

    if (-not (Test-Path -LiteralPath $FirstHopIntegrityAuditDirectory -PathType Container)) {
        throw "FirstHopIntegrityAuditDirectoryMissing: $FirstHopIntegrityAuditDirectory"
    }

    $SourcePath = Join-Path $FirstHopIntegrityAuditDirectory 'starting-trustee-raw-ace-matches.json'
    Require-File -Path $SourcePath -Label 'Starting trustee raw ACE matches'

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $FirstHopIntegrityAuditDirectory 'CorrelationLossAnalysis-v0.1.0'
    }

    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step -Status 'LOAD' -Message 'Loading preserved first-hop raw ACE matches.' -Color Yellow
    $AllMatches = [object[]]@(
        Read-JsonArray -Path $SourcePath -Label 'Starting trustee raw ACE matches'
    )

    $AllMatchCount = [int]@($AllMatches).Count
    $NonRoutineMatches = [object[]]@(
        $AllMatches |
            Where-Object {
                -not [bool]$_.RoutineAdministrative
            }
    )
    $NonRoutineCount = [int]@($NonRoutineMatches).Count

    Write-Step -Status 'OK' -Message "Loaded $AllMatchCount total matches and isolated $NonRoutineCount nonroutine match(es)." -Color Green

    $AnalysisList = New-Object 'System.Collections.Generic.List[object]'
    $Index = 0

    foreach ($Ace in $NonRoutineMatches) {
        $Index++
        Write-Step -Status 'ANALYZE' -Message "$Index/$NonRoutineCount trustee=$($Ace.Trustee) target=$($Ace.TargetName)" -Color DarkCyan

        $Rights = [string]$Ace.ActiveDirectoryRights
        $TargetObjectType = [string]$Ace.TargetObjectType
        $Guid = Normalize-GuidText -Value $Ace.ObjectTypeGuid
        $GuidSemantic = Get-GuidSemantic -Guid $Guid
        $BroadCapability = Get-BroadCapability -Rights $Rights -TargetObjectType $TargetObjectType

        $Capability = $GuidSemantic
        $MappingSource = 'KnownObjectTypeGuid'
        if ([string]::IsNullOrWhiteSpace($Capability)) {
            $Capability = $BroadCapability
            $MappingSource = 'BroadRightsFallback'
        }
        if ([string]::IsNullOrWhiteSpace($Capability)) {
            $Capability = 'Unmapped'
            $MappingSource = 'NoSemanticMapping'
        }

        $LikelyLossReason = 'UnknownCorrelationLoss'
        if ($Capability -eq 'Unmapped') {
            $LikelyLossReason = 'NoSemanticCapabilityProduced'
        }
        elseif ($Capability -in @(
            'UnresolvedWriteProperty',
            'UnresolvedExtendedRight',
            'UnresolvedValidatedWrite',
            'BroadUserControl',
            'BroadComputerControl',
            'BroadGroupControl',
            'BroadDomainControl',
            'BroadOuControl'
        )) {
            $LikelyLossReason = 'SemanticRefinementRequired'
        }
        elseif (-not [bool]$Ace.TrusteeResolved) {
            $LikelyLossReason = 'TrusteeUnresolved'
        }
        elseif ($Ace.TrusteeEnabled -eq $false) {
            $LikelyLossReason = 'TrusteeDisabled'
        }
        elseif ([bool]$Ace.IsInherited) {
            $LikelyLossReason = 'MappedCapabilityLikelyLostByCorrelationOrInheritanceHandling'
        }
        else {
            $LikelyLossReason = 'MappedDirectCapabilityUnexpectedlyAbsentFromCorrelation'
        }

        $Validator = Get-Validator -Capability $Capability
        $SafetyState = Get-SafetyState -Capability $Capability
        $NeedsFollowUp = $Validator -ne 'SemanticRefinementRequired'

        $ExclusionAssessment = 'PotentiallyCorrectPendingSemanticRefinement'
        if ($LikelyLossReason -in @(
            'MappedDirectCapabilityUnexpectedlyAbsentFromCorrelation',
            'MappedCapabilityLikelyLostByCorrelationOrInheritanceHandling'
        )) {
            $ExclusionAssessment = 'RequiresCorrelationDefectReview'
        }
        elseif ($LikelyLossReason -in @('TrusteeUnresolved', 'TrusteeDisabled')) {
            $ExclusionAssessment = 'LikelyCorrectExclusion'
        }

        $AnalysisList.Add([pscustomobject][ordered]@{
            RecordId = 'LOSS-{0:D3}' -f $Index
            Trustee = [string]$Ace.Trustee
            TrusteeSamAccountName = [string]$Ace.TrusteeSamAccountName
            MatchingAliases = [object[]]@($Ace.MatchingAliases)
            TrusteeResolved = $Ace.TrusteeResolved
            TrusteeEnabled = $Ace.TrusteeEnabled
            TargetObjectType = $TargetObjectType
            TargetName = [string]$Ace.TargetName
            TargetDistinguishedName = [string]$Ace.TargetDistinguishedName
            ActiveDirectoryRights = $Rights
            RiskRights = [object[]]@($Ace.RiskRights)
            ObjectTypeGuid = $Guid
            IsInherited = [bool]$Ace.IsInherited
            RoutineAdministrative = [bool]$Ace.RoutineAdministrative
            SemanticCapability = $Capability
            SemanticMappingSource = $MappingSource
            LikelyCorrelationLossReason = $LikelyLossReason
            ExclusionAssessment = $ExclusionAssessment
            NeedsFollowUp = $NeedsFollowUp
            ProposedValidator = $Validator
            SafetyState = $SafetyState
            EvidenceState = 'Raw nonroutine starting-principal ACE match; semantic reconciliation completed locally'
            Interpretation = 'This record is an ACL lead. Effective access, target applicability, and security impact remain unproven.'
        })
    }

    $AnalysisRows = [object[]]$AnalysisList.ToArray()
    $AnalysisCount = [int]@($AnalysisRows).Count
    $DefectReviewRows = [object[]]@(
        $AnalysisRows |
            Where-Object {
                $_.ExclusionAssessment -eq 'RequiresCorrelationDefectReview'
            }
    )
    $DefectReviewCount = [int]@($DefectReviewRows).Count
    $ValidatorRows = [object[]]@(
        $AnalysisRows |
            Where-Object {
                [bool]$_.NeedsFollowUp
            }
    )
    $ValidatorCount = [int]@($ValidatorRows).Count

    $CapabilityDistribution = [object[]]@(
        $AnalysisRows |
            Group-Object SemanticCapability |
            Sort-Object Count -Descending |
            ForEach-Object {
                [pscustomobject]@{
                    Capability = [string]$_.Name
                    Count = [int]$_.Count
                }
            }
    )

    $LossReasonDistribution = [object[]]@(
        $AnalysisRows |
            Group-Object LikelyCorrelationLossReason |
            Sort-Object Count -Descending |
            ForEach-Object {
                [pscustomobject]@{
                    Reason = [string]$_.Name
                    Count = [int]$_.Count
                }
            }
    )

    $AuthoritativeDisposition = 'Inconclusive'
    if ($AnalysisCount -eq 0) {
        $AuthoritativeDisposition = 'NotDetected'
    }
    elseif ($DefectReviewCount -eq 0 -and $ValidatorCount -eq 0) {
        $AuthoritativeDisposition = 'NoActionableCapabilityResolved'
    }

    $AnalysisJson = Join-Path $OutputDirectory 'correlation-loss-analysis.json'
    $AnalysisCsv = Join-Path $OutputDirectory 'correlation-loss-analysis.csv'
    $DefectJson = Join-Path $OutputDirectory 'correlation-defect-review-queue.json'
    $DefectCsv = Join-Path $OutputDirectory 'correlation-defect-review-queue.csv'
    $ValidatorJson = Join-Path $OutputDirectory 'proposed-validator-queue.json'
    $ValidatorCsv = Join-Path $OutputDirectory 'proposed-validator-queue.csv'

    Write-JsonArray -Rows $AnalysisRows -Path $AnalysisJson
    $AnalysisRows | Export-Csv -LiteralPath $AnalysisCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $DefectReviewRows -Path $DefectJson
    $DefectReviewRows | Export-Csv -LiteralPath $DefectCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ValidatorRows -Path $ValidatorJson
    $ValidatorRows | Export-Csv -LiteralPath $ValidatorCsv -NoTypeInformation -Encoding UTF8

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        Status = 'Completed'
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        SourceDirectory = $FirstHopIntegrityAuditDirectory
        Counts = [pscustomobject][ordered]@{
            TotalStartingTrusteeRawAceMatches = $AllMatchCount
            NonRoutineMatches = $NonRoutineCount
            AnalyzedMatches = $AnalysisCount
            CorrelationDefectReviewRows = $DefectReviewCount
            ProposedValidatorRows = $ValidatorCount
        }
        AuthoritativeDisposition = $AuthoritativeDisposition
        CapabilityDistribution = $CapabilityDistribution
        LossReasonDistribution = $LossReasonDistribution
        InterpretationBoundary = @(
            'This local analysis does not prove effective access.',
            'A semantic mapping does not establish exploitability.',
            'No candidate becomes a vulnerability without real tool reproduction and captured impact.',
            'No directory write is selected until target safety, original value, inverse operation, and cleanup verification are deterministic.'
        )
        Safety = [pscustomobject][ordered]@{
            NetworkActivity = 'None'
            DirectoryQueries = 'None'
            DirectoryChanges = 'None'
            OllamaActivity = 'None'
        }
    }

    $SummaryPath = Join-Path $OutputDirectory 'correlation-loss-analysis-summary.json'
    Write-JsonDocument -Document $Summary -Path $SummaryPath

    $RowsHtml = ($AnalysisRows | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f
            (Convert-HtmlText $_.RecordId),
            (Convert-HtmlText $_.Trustee),
            (Convert-HtmlText $_.TargetName),
            (Convert-HtmlText $_.SemanticCapability),
            (Convert-HtmlText $_.LikelyCorrelationLossReason),
            (Convert-HtmlText $_.ExclusionAssessment),
            (Convert-HtmlText $_.ProposedValidator)
    }) -join "`n"

    $ReportPath = Join-Path $OutputDirectory 'MSADPT-AD-Object-Control-Correlation-Loss-Analysis.html'
    $Html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MSADPT AD Object-Control Correlation-Loss Analysis</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#17202a}
h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}
th{background:#eaf2f8}.note{color:#5d6d7e}
</style>
</head>
<body>
<h1>MSADPT AD Object-Control Correlation-Loss Analysis</h1>
<div class="card">
<b>Total first-hop raw matches:</b> $AllMatchCount<br>
<b>Nonroutine matches analyzed:</b> $AnalysisCount<br>
<b>Correlation-defect review rows:</b> $DefectReviewCount<br>
<b>Proposed validator rows:</b> $ValidatorCount<br>
<b>Disposition:</b> $(Convert-HtmlText $AuthoritativeDisposition)<br>
<b>Network activity:</b> None<br>
<b>Directory changes:</b> None
</div>
<h2>Record Analysis</h2>
<table>
<tr><th>ID</th><th>Trustee</th><th>Target</th><th>Capability</th><th>Loss reason</th><th>Exclusion assessment</th><th>Proposed validator</th></tr>
$RowsHtml
</table>
<h2>Evidence</h2>
<ul>
<li><a href="correlation-loss-analysis.csv">Complete analysis</a></li>
<li><a href="correlation-defect-review-queue.csv">Correlation-defect review queue</a></li>
<li><a href="proposed-validator-queue.csv">Proposed validator queue</a></li>
<li><a href="correlation-loss-analysis-summary.json">Structured summary</a></li>
</ul>
<p class="note">These records are leads, not vulnerabilities. Effective access and real reversible impact remain unproven.</p>
</body>
</html>
"@

    [IO.File]::WriteAllText(
        $ReportPath,
        $Html,
        (New-Object Text.UTF8Encoding($false))
    )

    $Files = @(Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object { $_.Name -ne 'evidence-manifest.json' } | Sort-Object Name)
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

    Write-Step -Status 'DONE' -Message "Correlation-loss analysis complete: analyzed=$AnalysisCount, defect-review=$DefectReviewCount, validators=$ValidatorCount, disposition=$AuthoritativeDisposition." -Color Green

    [pscustomobject][ordered]@{
        Status = 'Passed'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        TotalRawMatchCount = $AllMatchCount
        NonRoutineMatchCount = $NonRoutineCount
        AnalyzedMatchCount = $AnalysisCount
        CorrelationDefectReviewCount = $DefectReviewCount
        ProposedValidatorCount = $ValidatorCount
        AuthoritativeDisposition = $AuthoritativeDisposition
        OutputDirectory = $OutputDirectory
        HtmlReportPath = $ReportPath
        SummaryPath = $SummaryPath
        ManifestPath = $ManifestPath
        NetworkActivity = 'None'
        DirectoryQueries = 'None'
        DirectoryChanges = 'None'
        OllamaActivity = 'None'
    }
}
catch {
    Write-Step -Status 'FAIL' -Message $_.Exception.Message -Color Red
    throw
}
