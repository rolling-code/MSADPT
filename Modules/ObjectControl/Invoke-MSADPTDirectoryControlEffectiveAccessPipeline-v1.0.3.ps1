<#
.SYNOPSIS
Selectively reprocesses MSADPT Directory Control token, schema, effective-access, and reporting stages.

.DESCRIPTION
Reuses existing Directory Control ACL inventory and candidate-reduction evidence. The pipeline runs
only SID-safe token collection, schema class mapping, offline effective-access evaluation, state
serialization, and HTML regeneration. It does not recollect ACLs or rerun candidate reduction.

.NOTES
Version: 1.0.3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EngagementDirectory,

    [string]$Server,

    [PSCredential]$Credential,

    [ValidateRange(1, 64)]
    [int]$MaximumTokenDepth = 16,

    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PipelineVersion = '1.0.3'
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Write-MSADPTStep {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $Text = '[{0,-12}] {1}' -f $State, $Message
    if ($NoColor) {
        Write-Host $Text
    }
    else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}

function ConvertTo-HtmlText {
    param([object]$Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

$EngagementDirectory = [System.IO.Path]::GetFullPath($EngagementDirectory)
$DirectoryControlDirectory = Join-Path $EngagementDirectory 'evidence\DirectoryControl'
$ReductionDirectory = Join-Path $EngagementDirectory 'analysis\DirectoryControlReduction'
$TokenDirectory = Join-Path $EngagementDirectory 'evidence\DirectoryControlToken'
$SchemaDirectory = Join-Path $EngagementDirectory 'evidence\DirectoryControlSchema'
$EffectiveAccessDirectory = Join-Path $EngagementDirectory 'analysis\DirectoryControlEffectiveAccess'
$ReportDirectory = Join-Path $EngagementDirectory 'reports'
$StageDirectory = Join-Path $EngagementDirectory 'state\stages'

$AceInventoryPath = Join-Path $DirectoryControlDirectory 'directory-control-ace-inventory.csv'
$CandidatePath = Join-Path $ReductionDirectory 'directory-control-prioritized-target-details.csv'

foreach ($RequiredPath in @($AceInventoryPath, $CandidatePath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "ReusableEvidenceMissing: $RequiredPath"
    }
}

$TokenRunner = Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlTokenEvidence-v1.0.1.ps1'
$SchemaRunner = Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlSchemaClassMap-v1.0.1.ps1'
$EvaluatorRunner = Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccess-v1.0.2.ps1'

foreach ($ComponentPath in @($TokenRunner, $SchemaRunner, $EvaluatorRunner)) {
    if (-not (Test-Path -LiteralPath $ComponentPath -PathType Leaf)) {
        throw "PipelineComponentMissing: $ComponentPath"
    }
}

Write-MSADPTStep -State 'START' -Message "Selective effective-access reprocessing v$PipelineVersion" -Color Cyan
Write-MSADPTStep -State 'REUSE' -Message 'Existing Directory Control ACL evidence. No ACL recollection.' -Color DarkGreen
Write-MSADPTStep -State 'REUSE' -Message 'Existing candidate-reduction evidence. No candidate reduction.' -Color DarkGreen
Write-MSADPTStep -State 'SAFETY' -Message 'Read-only token and schema queries; offline evaluation; directory changes=None; impact reproduction=None.' -Color Yellow

$Target = 'current domain'
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $Target = $Server
}

$RunToken = [guid]::NewGuid().ToString('N')
$TemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "MSADPT-EffectiveAccess-$RunToken"
$TemporaryTokenDirectory = Join-Path $TemporaryRoot 'DirectoryControlToken'
$TemporarySchemaDirectory = Join-Path $TemporaryRoot 'DirectoryControlSchema'
$TemporaryEffectiveDirectory = Join-Path $TemporaryRoot 'DirectoryControlEffectiveAccess'

New-Item -ItemType Directory -Path $TemporaryTokenDirectory, $TemporarySchemaDirectory, $TemporaryEffectiveDirectory -Force | Out-Null

try {
    Write-MSADPTStep -State 'EXECUTE' -Message "Trustee token collection through $Target over ADWS/LDAP. Read-only; changes=None." -Color Magenta

    $TokenParameters = @{
        CandidateEvidencePath = $CandidatePath
        OutputDirectory = $TemporaryTokenDirectory
        MaximumDepth = $MaximumTokenDepth
        NoColor = [bool]$NoColor
    }
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $TokenParameters.Server = $Server
    }
    if ($null -ne $Credential) {
        $TokenParameters.Credential = $Credential
    }

    $TokenOutput = @(& $TokenRunner @TokenParameters)
    $TokenTerminal = @($TokenOutput | Where-Object { $_.PSObject.Properties['ModuleId'] } | Select-Object -Last 1)
    if ($null -eq $TokenTerminal -or $TokenTerminal.Status -ne 'Passed') {
        throw 'TokenEvidenceTerminalResultMissingOrFailed'
    }

    Write-MSADPTStep -State 'EXECUTE' -Message "Schema class GUID collection through $Target over ADWS/LDAP. Read-only; changes=None." -Color Magenta

    $SchemaParameters = @{
        OutputDirectory = $TemporarySchemaDirectory
        NoColor = [bool]$NoColor
    }
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $SchemaParameters.Server = $Server
    }
    if ($null -ne $Credential) {
        $SchemaParameters.Credential = $Credential
    }

    $SchemaOutput = @(& $SchemaRunner @SchemaParameters)
    $SchemaTerminal = @($SchemaOutput | Where-Object { $_.PSObject.Properties['ModuleId'] } | Select-Object -Last 1)
    if ($null -eq $SchemaTerminal -or $SchemaTerminal.Status -ne 'Passed') {
        throw 'SchemaClassMapTerminalResultMissingOrFailed'
    }

    Write-MSADPTStep -State 'EXECUTE' -Message 'Offline token-wide effective-access evaluation.' -Color Cyan

    $EvaluatorOutput = @(
        & $EvaluatorRunner `
            -DirectoryControlEvidenceDirectory $DirectoryControlDirectory `
            -CandidateReductionDirectory $ReductionDirectory `
            -OutputDirectory $TemporaryEffectiveDirectory `
            -TokenEvidencePath (Join-Path $TemporaryTokenDirectory 'directory-control-token-evidence.csv') `
            -SchemaClassMapPath (Join-Path $TemporarySchemaDirectory 'directory-control-schema-class-map.csv') `
            -NoColor:$NoColor
    )

    $EvaluatorTerminal = @($EvaluatorOutput | Where-Object { $_.PSObject.Properties['ModuleId'] } | Select-Object -Last 1)
    if ($null -eq $EvaluatorTerminal -or $EvaluatorTerminal.Status -ne 'Passed') {
        throw 'EffectiveAccessTerminalResultMissingOrFailed'
    }

    $TokenSummary = Read-JsonFile -Path (Join-Path $TemporaryTokenDirectory 'directory-control-token-summary.json')
    $SchemaSummary = Read-JsonFile -Path (Join-Path $TemporarySchemaDirectory 'directory-control-schema-class-summary.json')
    $EffectiveSummary = Read-JsonFile -Path (Join-Path $TemporaryEffectiveDirectory 'directory-control-effective-access-summary.json')
    $Evaluations = @(Import-Csv -LiteralPath (Join-Path $TemporaryEffectiveDirectory 'directory-control-effective-access-evaluations.csv'))

    $Confirmed = @($Evaluations | Where-Object Disposition -eq 'EffectiveControlConfirmed')
    $NotEstablished = @($Evaluations | Where-Object Disposition -eq 'EffectiveControlNotEstablished')
    $NotApplicable = @($Evaluations | Where-Object Disposition -eq 'NotApplicable')
    $Inconclusive = @($Evaluations | Where-Object Disposition -eq 'Inconclusive')

    $ReasonRows = @(
        $Evaluations |
            Group-Object Reason |
            Sort-Object Count -Descending |
            ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-HtmlText $_.Name), $_.Count
            }
    ) -join ''

    $ConfirmedRows = @(
        $Confirmed |
            Select-Object -First 50 |
            ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f `
                    (ConvertTo-HtmlText $_.ValidationPriority), `
                    (ConvertTo-HtmlText $_.Trustee), `
                    (ConvertTo-HtmlText $_.Capability), `
                    (ConvertTo-HtmlText $_.TargetName), `
                    (ConvertTo-HtmlText $_.Reason)
            }
    ) -join ''

    $Html = @"
<!doctype html>
<html><head><meta charset="utf-8"><title>MSADPT Directory Control Effective Access</title>
<style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}.warn{border-left:5px solid #d68910}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left}th{background:#eaf2f8}</style></head>
<body><h1>Directory Control Effective Access</h1>
<div class="card"><b>Reused:</b> ACL inventory and candidate reduction<br>
<b>Token principals:</b> $($TokenSummary.PrincipalCount)<br>
<b>Resolved principals:</b> $($TokenSummary.ResolvedPrincipalCount)<br>
<b>Unresolved principals:</b> $($TokenSummary.UnresolvedPrincipalCount)<br>
<b>Complete tokens:</b> $($TokenSummary.CompletePrincipalCount)<br>
<b>Schema classes:</b> $($SchemaSummary.ClassCount)<br>
<b>Evaluations:</b> $($Evaluations.Count)<br>
<b>Effective control confirmed:</b> $($Confirmed.Count)<br>
<b>Effective control not established:</b> $($NotEstablished.Count)<br>
<b>Not applicable:</b> $($NotApplicable.Count)<br>
<b>Inconclusive:</b> $($Inconclusive.Count)</div>
<div class="card warn"><b>Interpretation boundary:</b> Effective control confirms only applicable directory permission for collected token evidence. Impact was not reproduced, and no vulnerability is automatically confirmed.</div>
<h2>Disposition Reasons</h2><table><tr><th>Reason</th><th>Count</th></tr>$ReasonRows</table>
<h2>Confirmed Permission Candidates</h2><table><tr><th>Validation Priority</th><th>Trustee</th><th>Capability</th><th>Target</th><th>Reason</th></tr>$ConfirmedRows</table>
<h2>Evidence</h2><ul>
<li><a href="../analysis/DirectoryControlEffectiveAccess/directory-control-effective-access-evaluations.csv">Evaluations</a></li>
<li><a href="../analysis/DirectoryControlEffectiveAccess/directory-control-effective-access-ace-trace.csv">ACE trace</a></li>
<li><a href="../evidence/DirectoryControlToken/directory-control-token-evidence.csv">Token evidence</a></li>
<li><a href="../evidence/DirectoryControlSchema/directory-control-schema-class-map.csv">Schema class map</a></li>
</ul></body></html>
"@

    New-Item -ItemType Directory -Path $ReportDirectory, $StageDirectory -Force | Out-Null
    $ReportPath = Join-Path $ReportDirectory 'MSADPT-Directory-Control-Effective-Access.html'
    [System.IO.File]::WriteAllText($ReportPath, $Html, (New-Object System.Text.UTF8Encoding($false)))

    $StageObject = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Stage = 'DirectoryControlEffectiveAccess'
        Status = 'Completed'
        Disposition = [string]$EffectiveSummary.Disposition
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        ReusedAclEvidence = $true
        ReusedReductionEvidence = $true
        TokenPrincipalCount = [int]$TokenSummary.PrincipalCount
        ResolvedPrincipalCount = [int]$TokenSummary.ResolvedPrincipalCount
        CompleteTokenCount = [int]$TokenSummary.CompletePrincipalCount
        SchemaClassCount = [int]$SchemaSummary.ClassCount
        EvaluationCount = $Evaluations.Count
        EffectiveControlConfirmedCount = $Confirmed.Count
        EffectiveControlNotEstablishedCount = $NotEstablished.Count
        NotApplicableCount = $NotApplicable.Count
        InconclusiveCount = $Inconclusive.Count
        ImpactReproduced = $false
        VulnerabilityConfirmed = $false
        ReportPath = $ReportPath
    }
    $StageObject | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $StageDirectory 'directory-control-effective-access.json') -Encoding UTF8

    foreach ($Promotion in @(
        [pscustomobject]@{ Source = $TemporaryTokenDirectory; Destination = $TokenDirectory },
        [pscustomobject]@{ Source = $TemporarySchemaDirectory; Destination = $SchemaDirectory },
        [pscustomobject]@{ Source = $TemporaryEffectiveDirectory; Destination = $EffectiveAccessDirectory }
    )) {
        $BackupPath = "$($Promotion.Destination).previous"
        Remove-Item -LiteralPath $BackupPath -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $Promotion.Destination -PathType Container) {
            Move-Item -LiteralPath $Promotion.Destination -Destination $BackupPath -Force
        }
        Move-Item -LiteralPath $Promotion.Source -Destination $Promotion.Destination -Force
        Remove-Item -LiteralPath $BackupPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-MSADPTStep -State 'REPORT' -Message $ReportPath -Color Cyan
    Write-MSADPTStep -State 'DONE' -Message "Resolved=$($TokenSummary.ResolvedPrincipalCount)/$($TokenSummary.PrincipalCount); classes=$($SchemaSummary.ClassCount); confirmed=$($Confirmed.Count); inconclusive=$($Inconclusive.Count)." -Color Green

    [pscustomobject][ordered]@{
        Status = 'Passed'
        PipelineVersion = $PipelineVersion
        EngagementDirectory = $EngagementDirectory
        ReusedAclEvidence = $true
        ReusedReductionEvidence = $true
        ResolvedPrincipalCount = [int]$TokenSummary.ResolvedPrincipalCount
        CompleteTokenCount = [int]$TokenSummary.CompletePrincipalCount
        SchemaClassCount = [int]$SchemaSummary.ClassCount
        EvaluationCount = $Evaluations.Count
        EffectiveControlConfirmedCount = $Confirmed.Count
        EffectiveControlNotEstablishedCount = $NotEstablished.Count
        NotApplicableCount = $NotApplicable.Count
        InconclusiveCount = $Inconclusive.Count
        ImpactReproduced = $false
        VulnerabilityConfirmed = $false
        HtmlReportPath = $ReportPath
        NetworkActivity = 'ReadOnlyADQueries'
        RemoteChanges = 'None'
    }
}
finally {
    Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
