<#
.SYNOPSIS
Audits first-hop trustee matching and graph-index integrity for MSADPT AD object-control evidence.
.DESCRIPTION
Consumes existing deduplicated candidates, raw dangerous ACE inventory, token-group evidence, and the
transitive graph output. Compares starting nodes against trustees using exact domain-qualified names,
unqualified names, SamAccountName aliases, and SID text where available. Reports raw matches, semantic
matches, graph-eligible matches, exclusion reasons, and whether alias normalization changes the zero-hop result.

This stage is local only. It performs no network operations, Active Directory queries, directory writes,
password resets, membership changes, SPN writes, RBCD writes, key-credential writes, DACL changes, owner
changes, ticket operations, or Ollama calls.
.NOTES
Version: 0.1.5
Package identity: MSADPT-AD-OBJECT-CONTROL-FIRST-HOP-INTEGRITY-AUDIT
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$BaselineDirectory,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CorrelationDirectory,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$TransitiveGraphDirectory,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$StartingIdentity,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$StartingIdentityGroupsPath,
    [string]$OutputDirectory,
    [ValidateRange(1,5000)][int]$MaximumReportedEdges = 250,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-AD-OBJECT-CONTROL-FIRST-HOP-INTEGRITY-AUDIT'
$PackageVersion = '0.1.5'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-10}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}
function Require-File {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) { throw "RequiredFileEmpty [$Label]: $Path" }
}
function Read-JsonArray {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
}
function Read-JsonDocument {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
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
function Normalize-Text {
    param([object]$Value)
    $Text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return $Text.Trim().ToLowerInvariant()
}
function Get-UnqualifiedName {
    param([object]$Value)
    $Text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $Text = $Text.Trim()
    if ($Text -match '\\') { return ($Text -split '\\')[-1].ToLowerInvariant() }
    return $Text.ToLowerInvariant()
}
function Get-IdentityAliases {
    param([object[]]$Values)
    $Aliases = @{}
    foreach ($Value in @($Values)) {
        $Exact = Normalize-Text $Value
        if ($null -ne $Exact) { $Aliases[$Exact] = 'ExactOrQualified' }
        $Short = Get-UnqualifiedName $Value
        if ($null -ne $Short) { $Aliases[$Short] = 'UnqualifiedAlias' }
    }
    return $Aliases
}
function Test-SemanticEligibility {
    param([object]$Candidate)
    $Reasons = New-Object 'System.Collections.Generic.List[string]'
    if (-not [bool]$Candidate.TrusteeResolved) { $Reasons.Add('TrusteeUnresolved') }
    if ($Candidate.TrusteeEnabled -eq $false) { $Reasons.Add('TrusteeDisabled') }
    if (-not [bool]$Candidate.BehavioralValidationReady) { $Reasons.Add('SemanticRefinementRequired') }
    if ([string]$Candidate.Priority -notin @('P1','P2')) { $Reasons.Add('PriorityBelowP2') }
    return [object[]]@($Reasons.ToArray() | Sort-Object -Unique)
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local first-hop integrity audit only. No network or directory operations.' DarkGray

    foreach ($Directory in @($BaselineDirectory,$CorrelationDirectory,$TransitiveGraphDirectory)) {
        if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { throw "RequiredDirectoryMissing: $Directory" }
    }
    Require-File $StartingIdentityGroupsPath 'Starting identity token evidence'

    $RawAcePath = Join-Path $BaselineDirectory 'dangerous-ace-inventory.json'
    $CandidatePath = Join-Path $CorrelationDirectory 'deduplicated-control-candidates.json'
    $CorrelationSummaryPath = Join-Path $CorrelationDirectory 'ad-object-control-correlation-summary.json'
    $GraphSummaryPath = Join-Path $TransitiveGraphDirectory 'ad-object-control-transitive-graph-summary.json'
    Require-File $RawAcePath 'Raw dangerous ACE inventory'
    Require-File $CandidatePath 'Deduplicated control candidates'

    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $OutputDirectory = Join-Path $TransitiveGraphDirectory 'FirstHopIntegrityAudit-v0.1.5'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) { throw "OutputDirectoryNotEmpty: $OutputDirectory" }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $SeedNames = New-Object 'System.Collections.Generic.List[string]'
    $SeedNames.Add($StartingIdentity)
    $TokenText = Get-Content -LiteralPath $StartingIdentityGroupsPath -Raw
    foreach ($Line in ($TokenText -split "`r?`n")) {
        if ($Line -match '^\s*([^\s].*?\\[^\s].*?)\s{2,}') { $SeedNames.Add($Matches[1].Trim()) }
    }
    $SeedNamesArray = [object[]]@($SeedNames.ToArray() | Sort-Object -Unique)
    $SeedAliases = Get-IdentityAliases $SeedNamesArray
    Write-Step 'OK' "Prepared $(@($SeedNamesArray).Count) starting names and $($SeedAliases.Keys.Count) normalized aliases." Green

    Write-Step 'LOAD' 'Loading deduplicated candidates.' Yellow
    $Candidates = [object[]]@(Read-JsonArray $CandidatePath 'Deduplicated control candidates')
    $CandidateCount = [int]@($Candidates).Count
    Write-Step 'OK' "Loaded $CandidateCount deduplicated candidate(s)." Green

    $CandidateMatches = New-Object 'System.Collections.Generic.List[object]'
    $IndexedTrusteeAliases = @{}
    $Index = 0
    foreach ($Candidate in $Candidates) {
        $Index++
        if ($Index -eq 1 -or $Index % 50000 -eq 0 -or $Index -eq $CandidateCount) {
            $Percent = [int](($Index/[double]$CandidateCount)*100)
            Write-Step 'PROCESS' "Candidate alias audit $Index/$CandidateCount ($Percent%)." DarkCyan
        }
        $TrusteeValues = @($Candidate.Trustee,$Candidate.TrusteeSamAccountName)
        $TrusteeAliases = Get-IdentityAliases $TrusteeValues
        foreach ($Alias in $TrusteeAliases.Keys) { $IndexedTrusteeAliases[$Alias] = $true }
        $MatchingAliases = [object[]]@($TrusteeAliases.Keys | Where-Object { $SeedAliases.ContainsKey($_) } | Sort-Object -Unique)
        if (@($MatchingAliases).Count -eq 0) { continue }
        $Reasons = [object[]]@(Test-SemanticEligibility $Candidate)
        $CandidateMatches.Add([pscustomobject][ordered]@{
            Trustee=$Candidate.Trustee;TrusteeSamAccountName=$Candidate.TrusteeSamAccountName
            MatchingAliases=$MatchingAliases;Priority=$Candidate.Priority;Capability=$Candidate.Capability
            TargetObjectType=$Candidate.TargetObjectType;TargetName=$Candidate.TargetName
            TargetDistinguishedName=$Candidate.TargetDistinguishedName
            TrusteeResolved=$Candidate.TrusteeResolved;TrusteeEnabled=$Candidate.TrusteeEnabled
            BehavioralValidationReady=$Candidate.BehavioralValidationReady
            SemanticEligibility=(@($Reasons).Count -eq 0);ExclusionReasons=$Reasons
            DirectAceCount=$Candidate.DirectAceCount;InheritedAceCount=$Candidate.InheritedAceCount
            NextValidator=$Candidate.NextValidator
        })
    }

    Write-Step 'LOAD' 'Streaming raw ACE trustees for starting-node matches.' Yellow
    $RawAces = [object[]]@(Read-JsonArray $RawAcePath 'Raw dangerous ACE inventory')
    $RawAceCount = [int]@($RawAces).Count
    $RawMatches = New-Object 'System.Collections.Generic.List[object]'
    $RawIndex = 0
    foreach ($Ace in $RawAces) {
        $RawIndex++
        if ($RawIndex -eq 1 -or $RawIndex % 100000 -eq 0 -or $RawIndex -eq $RawAceCount) {
            $Percent = [int](($RawIndex/[double]$RawAceCount)*100)
            Write-Step 'PROCESS' "Raw trustee audit $RawIndex/$RawAceCount ($Percent%)." DarkCyan
        }
        $Aliases = Get-IdentityAliases @($Ace.Trustee,$Ace.TrusteeSamAccountName)
        $MatchingAliases = [object[]]@($Aliases.Keys | Where-Object { $SeedAliases.ContainsKey($_) } | Sort-Object -Unique)
        if (@($MatchingAliases).Count -eq 0) { continue }
        $RawMatches.Add([pscustomobject][ordered]@{
            Trustee=$Ace.Trustee;TrusteeSamAccountName=$Ace.TrusteeSamAccountName
            MatchingAliases=$MatchingAliases;TargetObjectType=$Ace.TargetObjectType
            TargetName=$Ace.TargetName;TargetDistinguishedName=$Ace.TargetDistinguishedName
            ActiveDirectoryRights=$Ace.ActiveDirectoryRights;RiskRights=$Ace.RiskRights
            ObjectTypeGuid=$Ace.ObjectTypeGuid;IsInherited=$Ace.IsInherited
            RoutineAdministrative=$Ace.RoutineAdministrative;TrusteeResolved=$Ace.TrusteeResolved
            TrusteeEnabled=$Ace.TrusteeEnabled
        })
    }

    # PowerShell 7 can throw 'Argument types do not match' when a generic
    # List[object] is converted through @(). Materialize through ToArray().
    $CandidateMatchArray = [object[]]$CandidateMatches.ToArray()
    $RawMatchArray = [object[]]$RawMatches.ToArray()

    $ExactCandidateMatches = [object[]]@(
        $CandidateMatchArray |
        Where-Object {
            $_.MatchingAliases -contains (Normalize-Text $_.Trustee)
        }
    )
    $AliasCandidateMatches = $CandidateMatchArray
    $EligibleAliasMatches = [object[]]@(
        $CandidateMatchArray |
        Where-Object {
            [bool]$_.SemanticEligibility
        }
    )
    $RawNonRoutineMatches = [object[]]@(
        $RawMatchArray |
        Where-Object {
            -not [bool]$_.RoutineAdministrative
        }
    )

    $CandidateMatchCount = [int]@($AliasCandidateMatches).Count
    $ExactCandidateMatchCount = [int]@($ExactCandidateMatches).Count
    $EligibleFirstHopCount = [int]@($EligibleAliasMatches).Count
    $RawMatchCount = [int]@($RawMatchArray).Count
    $RawNonRoutineMatchCount = [int]@($RawNonRoutineMatches).Count

    $FindingState = 'ZeroFirstHopConfirmedUnderCurrentModel'
    $Interpretation = 'No exact or alias-normalized starting trustee produced a graph-eligible first-hop relationship.'
    if ($EligibleFirstHopCount -gt 0) {
        $FindingState = 'AliasNormalizationChangesResult'
        $Interpretation = 'One or more starting trustees match graph-eligible relationships after alias normalization. The v0.1.0 graph key model requires correction.'
    }
    elseif ($CandidateMatchCount -gt 0) {
        $FindingState = 'MatchesExistButExcludedBeforeGraphIndex'
        $Interpretation = 'Starting trustees exist in correlated evidence, but all matching relationships were excluded by semantic, resolution, enabled-state, or priority gates.'
    }
    elseif ($RawMatchCount -gt 0) {
        $FindingState = 'RawMatchesRemovedDuringSemanticCorrelation'
        $Interpretation = 'Starting trustees appear in raw ACE evidence but not in the deduplicated semantic candidate set.'
    }

    $ExclusionDistribution = [object[]]@(
        $CandidateMatchArray | ForEach-Object { $_.ExclusionReasons } | Where-Object { $null -ne $_ } |
        Group-Object | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{Reason=$_.Name;Count=[int]$_.Count} }
    )
    $SeedCoverage = [object[]]@(
        foreach ($Seed in $SeedNamesArray) {
            $Aliases = Get-IdentityAliases @($Seed)
            $CandidateHit = @($Aliases.Keys | Where-Object { $IndexedTrusteeAliases.ContainsKey($_) }).Count -gt 0
            $RawHit = @($RawMatchArray | Where-Object { @($_.MatchingAliases | Where-Object { $Aliases.ContainsKey($_) }).Count -gt 0 }).Count -gt 0
            [pscustomobject]@{SeedIdentity=$Seed;CandidateTrusteeMatch=$CandidateHit;RawAceTrusteeMatch=$RawHit}
        }
    )

    $CandidateMatchesPath=Join-Path $OutputDirectory 'starting-trustee-candidate-matches.json';$CandidateMatchesCsv=Join-Path $OutputDirectory 'starting-trustee-candidate-matches.csv'
    $RawMatchesPath=Join-Path $OutputDirectory 'starting-trustee-raw-ace-matches.json';$RawMatchesCsv=Join-Path $OutputDirectory 'starting-trustee-raw-ace-matches.csv'
    $EligiblePath=Join-Path $OutputDirectory 'eligible-first-hop-edges.json';$EligibleCsv=Join-Path $OutputDirectory 'eligible-first-hop-edges.csv'
    $SeedPath=Join-Path $OutputDirectory 'starting-node-coverage.json';$SeedCsv=Join-Path $OutputDirectory 'starting-node-coverage.csv'
    Write-JsonArray $CandidateMatchArray $CandidateMatchesPath;$CandidateMatchArray|Export-Csv $CandidateMatchesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $RawMatchArray $RawMatchesPath;$RawMatchArray|Export-Csv $RawMatchesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $EligibleAliasMatches $EligiblePath;$EligibleAliasMatches|Export-Csv $EligibleCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $SeedCoverage $SeedPath;$SeedCoverage|Export-Csv $SeedCsv -NoTypeInformation -Encoding UTF8

    $CorrelationSummary = Read-JsonDocument $CorrelationSummaryPath 'Correlation summary'
    $GraphSummary = Read-JsonDocument $GraphSummaryPath 'Graph summary'
    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status='Completed';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Domain=[string]$CorrelationSummary.Domain;StartingIdentity=$StartingIdentity
        FindingState=$FindingState;Interpretation=$Interpretation
        Counts=[pscustomobject]@{
            StartingNodes=@($SeedNamesArray).Count;StartingAliases=$SeedAliases.Keys.Count
            RawAceRows=$RawAceCount;RawAceMatches=$RawMatchCount;RawNonRoutineMatches=$RawNonRoutineMatchCount
            DeduplicatedCandidates=$CandidateCount;ExactCandidateMatches=$ExactCandidateMatchCount
            AliasCandidateMatches=$CandidateMatchCount;EligibleAliasMatches=$EligibleFirstHopCount
            PriorGraphPaths=[int]$GraphSummary.Counts.GraphPaths
        }
        ExclusionDistribution=$ExclusionDistribution
        InterpretationBoundary=@(
            'Alias matching uses domain-qualified and unqualified names plus TrusteeSamAccountName where available.',
            'SID comparison is textual only when SID values appear in the supplied evidence.',
            'Nested group expansion is outside this local audit.',
            'An eligible first-hop edge remains a lead until effective access and real reversible impact are reproduced.'
        )
        Safety=[pscustomobject]@{NetworkActivity='None';DirectoryQueries='None';DirectoryChanges='None';OllamaActivity='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'first-hop-integrity-audit-summary.json';Write-JsonDocument $Summary $SummaryPath

    $EligibleHtml=($EligibleAliasMatches|Select-Object -First 100|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>'-f(Convert-HtmlText $_.Trustee),(Convert-HtmlText $_.Capability),(Convert-HtmlText $_.TargetName),(Convert-HtmlText $_.Priority),(Convert-HtmlText $_.NextValidator)})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-AD-Object-Control-First-Hop-Integrity-Audit.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT First-Hop Integrity Audit</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT AD Object-Control First-Hop Integrity Audit</h1><div class="card"><b>Domain:</b> $(Convert-HtmlText $Summary.Domain)<br><b>Finding state:</b> $(Convert-HtmlText $FindingState)<br><b>Starting nodes:</b> $(@($SeedNamesArray).Count)<br><b>Raw ACE matches:</b> $($RawMatchCount)<br><b>Candidate alias matches:</b> $($CandidateMatchCount)<br><b>Eligible first-hop edges:</b> $($EligibleFirstHopCount)<br><b>Network activity:</b> None</div><h2>Interpretation</h2><p>$(Convert-HtmlText $Interpretation)</p><h2>Eligible First-Hop Edges</h2><table><tr><th>Trustee</th><th>Capability</th><th>Target</th><th>Priority</th><th>Validator</th></tr>$EligibleHtml</table><h2>Evidence</h2><ul><li><a href="starting-node-coverage.csv">Starting-node coverage</a></li><li><a href="starting-trustee-raw-ace-matches.csv">Raw ACE matches</a></li><li><a href="starting-trustee-candidate-matches.csv">Candidate matches</a></li><li><a href="eligible-first-hop-edges.csv">Eligible first-hop edges</a></li><li><a href="first-hop-integrity-audit-summary.json">Structured summary</a></li><li><a href="../MSADPT-AD-Object-Control-Transitive-Graph.html">Prior graph report</a></li></ul><p class="note">This integrity audit performs no directory operation and produces no vulnerability finding.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name-ne'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=[object[]]@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Integrity audit complete: raw matches=$($RawMatchCount), candidate matches=$($CandidateMatchCount), eligible first hops=$($EligibleFirstHopCount), state=$FindingState." Green
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Domain=$Summary.Domain;FindingState=$FindingState;StartingNodeCount=@($SeedNamesArray).Count
        RawAceMatchCount=$RawMatchCount;RawNonRoutineMatchCount=$RawNonRoutineMatchCount
        ExactCandidateMatchCount=$ExactCandidateMatchCount;AliasCandidateMatchCount=$CandidateMatchCount
        EligibleFirstHopCount=$EligibleFirstHopCount;PriorGraphPathCount=[int]$GraphSummary.Counts.GraphPaths
        OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        NetworkActivity='None';DirectoryQueries='None';DirectoryChanges='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
