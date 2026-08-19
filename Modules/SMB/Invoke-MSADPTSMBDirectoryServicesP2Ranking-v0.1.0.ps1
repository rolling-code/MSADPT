<#
.SYNOPSIS
Ranks P2 SYSVOL and NETLOGON artifacts for bounded content validation.

.DESCRIPTION
Consumes logical-directory-services-leads.json from MSADPT lead reduction. Selects only P2
artifacts, deduplicates equivalent SYSVOL scripts and NETLOGON paths, scores execution, deployment,
backup, certificate-import, CyberArk, remote-management, and recency indicators, and produces a
bounded content-validation queue.

This stage is local only. It performs no network connection, SMB access, file-content read,
remote hash, credential operation, relay, execution, or remote change. P3 artifacts are excluded.

.NOTES
Version: 0.1.0
Package identity: MSADPT-SMB-DIRECTORY-SERVICES-P2-RANKING
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$LeadReductionDirectory,

    [string]$OutputDirectory,

    [ValidateRange(1,50)]
    [int]$MaximumValidationQueue = 15,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-SMB-DIRECTORY-SERVICES-P2-RANKING'
$PackageVersion = '0.1.0'

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
function Get-AliasKey {
    param([string]$Share,[string]$RelativePath)
    $PathText = $RelativePath.Replace('/','\').TrimStart('\').ToLowerInvariant()
    if ($Share -eq 'SYSVOL') {
        $Marker = '\scripts\'
        $Index = $PathText.IndexOf($Marker)
        if ($Index -ge 0) { return $PathText.Substring($Index + $Marker.Length) }
    }
    if ($Share -eq 'NETLOGON') { return $PathText }
    return ('{0}|{1}' -f $Share.ToUpperInvariant(),$PathText)
}
function Get-ScoreResult {
    param([object]$Lead)

    $PathText = ([string]$Lead.RelativePath).ToLowerInvariant()
    $Extension = ([string]$Lead.Extension).ToLowerInvariant()
    $Category = [string]$Lead.Category
    $Score = 0
    $Reasons = New-Object 'System.Collections.Generic.List[string]'

    if ([string]$Lead.Share -eq 'NETLOGON') { $Score += 30; $Reasons.Add('NETLOGON execution or deployment context') }
    if ($PathText -match '(?i)cyberark|psm|vault') { $Score += 35; $Reasons.Add('CyberArk or privileged-access deployment context') }
    if ($PathText -match '(?i)software[_ -]?push|deploy|install|package|startup|logon|scripts') { $Score += 25; $Reasons.Add('Software deployment or logon/startup context') }
    if ($PathText -match '(?i)cert|pfx|pkcs|client[_ -]?auth') { $Score += 20; $Reasons.Add('Certificate or authentication context') }
    if ($PathText -match '(?i)password|credential|secret|token|apikey|api[_ -]?key') { $Score += 40; $Reasons.Add('Credential-related path indicator') }
    if ($PathText -match '(?i)psexec|winrm|invoke-command|scheduled|task|service|sc\.exe|schtasks') { $Score += 30; $Reasons.Add('Remote-management, service, or scheduled-task context') }
    if ($Extension -eq '.ps1') { $Score += 30; $Reasons.Add('PowerShell script') }
    elseif ($Extension -in @('.bat','.cmd','.vbs','.wsf','.js')) { $Score += 25; $Reasons.Add('Executable script') }
    elseif ($Extension -in @('.bak','.old','.orig','.save')) { $Score += 20; $Reasons.Add('Backup or historical artifact') }
    elseif ($Extension -in @('.config','.json')) { $Score += 15; $Reasons.Add('Application configuration') }

    if ($Category -eq 'BackupOrHistoricalArtifact') { $Score += 15; $Reasons.Add('Historical copy may expose stale sensitive configuration') }
    if ([bool]$Lead.ReplicatedDuplicate) { $Score += 2; $Reasons.Add('Replicated domain artifact') }

    $AgeDays = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$Lead.LastWriteTimeUtc)) {
        try {
            $AgeDays = [int]((Get-Date).ToUniversalTime() - [datetime]$Lead.LastWriteTimeUtc).TotalDays
            if ($AgeDays -le 90) { $Score += 15; $Reasons.Add('Modified within 90 days') }
            elseif ($AgeDays -le 365) { $Score += 8; $Reasons.Add('Modified within one year') }
        } catch { }
    }

    return [pscustomobject][ordered]@{
        Score = $Score
        Reasons = [object[]]$Reasons.ToArray()
        AgeDays = $AgeDays
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local-only P2 ranking. P3 excluded. No network or content access.' DarkGray

    if (-not (Test-Path -LiteralPath $LeadReductionDirectory -PathType Container)) {
        throw "LeadReductionDirectoryMissing: $LeadReductionDirectory"
    }
    $LogicalPath = Join-Path $LeadReductionDirectory 'logical-directory-services-leads.json'
    Require-File $LogicalPath 'Logical directory-services leads'

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $LeadReductionDirectory 'P2Ranking-v0.1.0'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $LogicalRows = [object[]]@(Get-Content -LiteralPath $LogicalPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    $P2Rows = [object[]]@($LogicalRows | Where-Object { $_.Priority -eq 'P2' -and [bool]$_.ContentValidationEligible })
    Write-Step 'LOAD' "Loaded logical=$(@($LogicalRows).Count), P2=$(@($P2Rows).Count), P3 intentionally excluded." Yellow

    $AliasGroups = @($P2Rows | Group-Object { Get-AliasKey -Share ([string]$_.Share) -RelativePath ([string]$_.RelativePath) })
    $RankedList = New-Object 'System.Collections.Generic.List[object]'
    $RankIndex = 0

    foreach ($Group in $AliasGroups) {
        $Observations = [object[]]@($Group.Group)
        $Preferred = @(
            $Observations |
                Sort-Object @{Expression={if ($_.Share -eq 'NETLOGON') {0} else {1}}},NormalizedRelativePath |
                Select-Object -First 1
        )[0]
        $ScoreResult = Get-ScoreResult -Lead $Preferred
        $RankIndex++
        $RankedList.Add([pscustomobject][ordered]@{
            RankCandidateId = 'P2RANK-{0:D3}' -f $RankIndex
            AliasKey = [string]$Group.Name
            Score = [int]$ScoreResult.Score
            ScoreReasons = [object[]]$ScoreResult.Reasons
            AgeDays = $ScoreResult.AgeDays
            LogicalLeadId = [string]$Preferred.LogicalLeadId
            Category = [string]$Preferred.Category
            Share = [string]$Preferred.Share
            RelativePath = [string]$Preferred.RelativePath
            Extension = [string]$Preferred.Extension
            Size = $Preferred.Size
            LastWriteTimeUtc = [string]$Preferred.LastWriteTimeUtc
            ObservationCount = @($Observations).Count
            SourceTargets = [object[]]@($Observations.SourceTargets | ForEach-Object { $_ } | Sort-Object -Unique)
            PreferredTarget = [string](@($Preferred.SourceTargets | Sort-Object | Select-Object -First 1)[0])
            P3Included = $false
            ContentRead = $false
            RemoteChange = $false
        })
    }

    $RankedRows = [object[]]@($RankedList.ToArray() | Sort-Object @{Expression='Score';Descending=$true},Category,RelativePath)
    $QueueSource = [object[]]@($RankedRows | Select-Object -First $MaximumValidationQueue)
    $QueueList = New-Object 'System.Collections.Generic.List[object]'
    $QueueIndex = 0
    foreach ($Lead in $QueueSource) {
        $QueueIndex++
        $QueueList.Add([pscustomobject][ordered]@{
            QueueId = 'P2CONTENT-{0:D3}' -f $QueueIndex
            Rank = $QueueIndex
            Score = [int]$Lead.Score
            ScoreReasons = [object[]]$Lead.ScoreReasons
            AliasKey = [string]$Lead.AliasKey
            Category = [string]$Lead.Category
            Share = [string]$Lead.Share
            RelativePath = [string]$Lead.RelativePath
            Extension = [string]$Lead.Extension
            Size = $Lead.Size
            LastWriteTimeUtc = [string]$Lead.LastWriteTimeUtc
            PreferredTarget = [string]$Lead.PreferredTarget
            SourceTargets = [object[]]$Lead.SourceTargets
            MaximumBytesToRead = 1048576
            ValidationMode = 'RedactedScriptAndConfigurationPatternAnalysis'
            ExecuteScript = $false
            SecretOutput = $false
            CompleteContentSaved = $false
            RemoteChange = $false
        })
    }
    $QueueRows = [object[]]$QueueList.ToArray()

    $CategoryDistribution = [object[]]@($RankedRows | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {[pscustomobject]@{Category=[string]$_.Name;Count=[int]$_.Count}})
    $ExtensionDistribution = [object[]]@($RankedRows | Group-Object Extension | Sort-Object Count -Descending | ForEach-Object {[pscustomobject]@{Extension=[string]$_.Name;Count=[int]$_.Count}})

    $RankedJson=Join-Path $OutputDirectory 'ranked-p2-leads.json'
    $RankedCsv=Join-Path $OutputDirectory 'ranked-p2-leads.csv'
    $QueueJson=Join-Path $OutputDirectory 'p2-content-validation-queue.json'
    $QueueCsv=Join-Path $OutputDirectory 'p2-content-validation-queue.csv'
    $CategoryJson=Join-Path $OutputDirectory 'p2-category-distribution.json'
    $CategoryCsv=Join-Path $OutputDirectory 'p2-category-distribution.csv'
    $ExtensionJson=Join-Path $OutputDirectory 'p2-extension-distribution.json'
    $ExtensionCsv=Join-Path $OutputDirectory 'p2-extension-distribution.csv'

    Write-JsonArray $RankedRows $RankedJson;$RankedRows|Export-Csv -LiteralPath $RankedCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $QueueRows $QueueJson;$QueueRows|Export-Csv -LiteralPath $QueueCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $CategoryDistribution $CategoryJson;$CategoryDistribution|Export-Csv -LiteralPath $CategoryCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ExtensionDistribution $ExtensionJson;$ExtensionDistribution|Export-Csv -LiteralPath $ExtensionCsv -NoTypeInformation -Encoding UTF8

    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status='Completed';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        SourceLeadReductionDirectory=$LeadReductionDirectory
        Counts=[pscustomobject]@{LogicalLeads=@($LogicalRows).Count;P2InputLeads=@($P2Rows).Count;AliasDeduplicatedP2Leads=@($RankedRows).Count;Queue=@($QueueRows).Count;P3Included=0}
        InterpretationBoundary=@('P2 is a validation-routing priority, not vulnerability severity.','P3 artifacts are intentionally excluded.','No content was read in this stage.','Ranking scores path context, extension, category, recency, and deployment relevance.','A queued artifact remains a lead until bounded content analysis confirms a meaningful condition.')
        Safety=[pscustomobject]@{NetworkActivity='None';ShareAccess='None';ContentReads='None';ScriptExecution='None';SecretOutput='None';CompleteContentSaved=$false;RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'p2-ranking-summary.json';Write-JsonDocument $Summary $SummaryPath

    $QueueHtml=($QueueRows|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (Convert-HtmlText $_.Rank),(Convert-HtmlText $_.Score),(Convert-HtmlText $_.Category),(Convert-HtmlText $_.Share),(Convert-HtmlText $_.RelativePath),(Convert-HtmlText $_.ScoreReasons)})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-SMB-Directory-Services-P2-Ranking.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT SMB P2 Ranking</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT SMB Directory Services P2 Ranking</h1><div class="card"><b>P2 input leads:</b> $(@($P2Rows).Count)<br><b>Alias-deduplicated P2 leads:</b> $(@($RankedRows).Count)<br><b>Validation queue:</b> $(@($QueueRows).Count)<br><b>P3 included:</b> 0<br><b>Network activity:</b> None<br><b>Content read:</b> None</div><h2>Ranked Validation Queue</h2><table><tr><th>Rank</th><th>Score</th><th>Category</th><th>Share</th><th>Relative path</th><th>Reasons</th></tr>$QueueHtml</table><h2>Evidence</h2><ul><li><a href="ranked-p2-leads.csv">All ranked P2 leads</a></li><li><a href="p2-content-validation-queue.csv">Bounded queue</a></li><li><a href="p2-category-distribution.csv">Category distribution</a></li><li><a href="p2-extension-distribution.csv">Extension distribution</a></li><li><a href="p2-ranking-summary.json">Summary</a></li></ul><p class="note">P2 routes content validation and is not a vulnerability severity. P3 is excluded.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name -ne 'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=[object[]]@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "P2 ranking complete: input=$(@($P2Rows).Count), alias-deduplicated=$(@($RankedRows).Count), queue=$(@($QueueRows).Count), P3=0." Green
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        P2InputLeadCount=@($P2Rows).Count;AliasDeduplicatedP2LeadCount=@($RankedRows).Count
        ContentValidationQueueCount=@($QueueRows).Count;P3IncludedCount=0
        OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        NetworkActivity='None';ShareAccess='None';ContentReads='None';ScriptExecution='None';SecretOutput='None';CompleteContentSaved='No';RemoteFileChanges='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
