<#
.SYNOPSIS
Builds bounded transitive AD object-control paths from existing MSADPT correlation evidence.
.DESCRIPTION
Consumes deduplicated-control-candidates.json and starting-token evidence. Performs a local breadth-first
reachability analysis to a configurable depth. Only capabilities that can plausibly establish control of
a user, computer, or security group create new reachable-principal nodes. Terminal capabilities such as
SPN write, RBCD write, replication rights, and broad OU control remain path findings but do not automatically
create new principal-control nodes.

No network activity, AD query, directory write, password reset, membership change, SPN write, RBCD write,
key-credential write, ownership change, DACL change, ticket operation, or Ollama call occurs.
.NOTES
Version: 0.1.0
Package identity: MSADPT-AD-OBJECT-CONTROL-TRANSITIVE-GRAPH
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$CorrelationDirectory,

    [string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$StartingIdentity,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$StartingIdentityGroupsPath,
    [ValidateRange(1,8)][int]$MaximumDepth = 4,
    [ValidateRange(1,5000)][int]$MaximumReportedPaths = 250,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-AD-OBJECT-CONTROL-TRANSITIVE-GRAPH'
$PackageVersion = '0.1.0'

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
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=20)
    $Array = [object[]]@($Rows)
    if (@($Array).Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    }
    else {
        $Array | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $Check = [object[]]@(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    if (@($Check).Count -ne @($Array).Count) { throw "JsonArrayRoundTripMismatch: $Path" }
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=20)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}
function Normalize-Identity {
    param([object]$Value)
    $Text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return $Text.Trim().ToLowerInvariant()
}
function Get-TargetPrincipalKeys {
    param([object]$Candidate)
    $Keys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Value in @($Candidate.TargetSamAccountName,$Candidate.TargetName,$Candidate.TargetDistinguishedName)) {
        $Normalized = Normalize-Identity $Value
        if ($null -ne $Normalized) { $Keys.Add($Normalized) }
    }
    return [object[]]@($Keys.ToArray() | Sort-Object -Unique)
}
function Test-CapabilityCreatesControl {
    param([string]$Capability,[string]$TargetObjectType)
    if ($TargetObjectType -notin @('User','Computer','Group')) { return $false }
    return $Capability -in @(
        'GenericAll','WriteDacl','WriteOwner','ResetPassword',
        'WriteGroupMembership','BroadGroupControl','BroadComputerControl','BroadUserControl'
    )
}
function Test-CapabilityIsTerminalImpact {
    param([string]$Capability,[object]$Candidate)
    if ($Candidate.TargetAdminCount -eq 1) { return $true }
    if ([string]$Candidate.TargetObjectType -eq 'Domain') { return $true }
    return $Capability -in @(
        'ReplicatingDirectoryChanges','ReplicatingDirectoryChangesAll',
        'ReplicatingDirectoryChangesFilteredSet','WriteRBCD','WriteKeyCredentialLink',
        'ResetPassword','WriteGroupMembership','WriteServicePrincipalName',
        'WriteDacl','WriteOwner','GenericAll'
    )
}
function Get-PathSafetyState {
    param([string]$Capability)
    switch ($Capability) {
        'WriteGroupMembership' { return 'ReversibleIfDedicatedTestMemberAvailable' }
        'WriteServicePrincipalName' { return 'ReversibleIfOriginalSpnSetCaptured' }
        'WriteRBCD' { return 'ReversibleIfOriginalDescriptorCaptured' }
        'WriteKeyCredentialLink' { return 'HighImpactRequiresDedicatedTestIdentity' }
        'ResetPassword' { return 'NotSafeWithoutDedicatedTestIdentity' }
        'WriteDacl' { return 'HighImpactRequiresExactDaclBackupAndRestore' }
        'WriteOwner' { return 'HighImpactRequiresExactOwnerRestore' }
        'GenericAll' { return 'SemanticOperationAndRollbackRequired' }
        'ReplicatingDirectoryChanges' { return 'ReadOnlyEffectiveRightsValidationFirst' }
        'ReplicatingDirectoryChangesAll' { return 'ReadOnlyEffectiveRightsValidationFirst' }
        'ReplicatingDirectoryChangesFilteredSet' { return 'ReadOnlyEffectiveRightsValidationFirst' }
        default { return 'SemanticRefinementOrReadOnlyValidationFirst' }
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local transitive graph analysis only. No network or directory operations.' DarkGray

    if (-not (Test-Path -LiteralPath $CorrelationDirectory -PathType Container)) {
        throw "CorrelationDirectoryMissing: $CorrelationDirectory"
    }
    $CandidatePath = Join-Path $CorrelationDirectory 'deduplicated-control-candidates.json'
    Require-File $CandidatePath 'Deduplicated control candidates'
    Require-File $StartingIdentityGroupsPath 'Starting identity token evidence'

    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $OutputDirectory = Join-Path $CorrelationDirectory 'TransitiveGraph-v0.1.0'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step 'LOAD' 'Loading deduplicated ACL candidates.' Yellow
    $Candidates = [object[]]@(Read-JsonArray $CandidatePath 'Deduplicated control candidates')
    $CandidateCount = [int]@($Candidates).Count
    Write-Step 'OK' "Loaded $CandidateCount candidate relationship(s)." Green

    $Reachable = @{}
    $ReachableOrder = New-Object 'System.Collections.Generic.List[object]'
    $Queue = New-Object 'System.Collections.Generic.Queue[object]'

    $StartKey = Normalize-Identity $StartingIdentity
    $Reachable[$StartKey] = [pscustomobject]@{Identity=$StartingIdentity;Depth=0;Source='StartingIdentity';PredecessorPathId=$null}
    $Queue.Enqueue([pscustomobject]@{Key=$StartKey;Identity=$StartingIdentity;Depth=0;PredecessorPathId=$null})
    $ReachableOrder.Add($Reachable[$StartKey])

    $GroupText = Get-Content -LiteralPath $StartingIdentityGroupsPath -Raw
    foreach ($Line in ($GroupText -split "`r?`n")) {
        if ($Line -match '^\s*([^\s].*?\\[^\s].*?)\s{2,}') {
            $Identity = $Matches[1].Trim()
            $Key = Normalize-Identity $Identity
            if ($null -ne $Key -and -not $Reachable.ContainsKey($Key)) {
                $Node = [pscustomobject]@{Identity=$Identity;Depth=0;Source='TokenGroup';PredecessorPathId=$null}
                $Reachable[$Key] = $Node
                $Queue.Enqueue([pscustomobject]@{Key=$Key;Identity=$Identity;Depth=0;PredecessorPathId=$null})
                $ReachableOrder.Add($Node)
            }
        }
    }
    Write-Step 'OK' "Seeded $($Reachable.Keys.Count) starting identity and token-group node(s)." Green

    $EdgesByTrustee = @{}
    $Index = 0
    foreach ($Candidate in $Candidates) {
        $Index++
        if ($Index -eq 1 -or $Index % 50000 -eq 0 -or $Index -eq $CandidateCount) {
            $Percent = [int](($Index/[double]$CandidateCount)*100)
            Write-Step 'INDEX' "Indexing candidate edges $Index/$CandidateCount ($Percent%)." DarkCyan
        }
        if (-not [bool]$Candidate.TrusteeResolved) { continue }
        if ($Candidate.TrusteeEnabled -eq $false) { continue }
        if (-not [bool]$Candidate.BehavioralValidationReady) { continue }
        $TrusteeKey = Normalize-Identity $Candidate.Trustee
        if ($null -eq $TrusteeKey) { continue }
        if (-not $EdgesByTrustee.ContainsKey($TrusteeKey)) {
            $EdgesByTrustee[$TrusteeKey] = New-Object 'System.Collections.Generic.List[object]'
        }
        $EdgesByTrustee[$TrusteeKey].Add($Candidate)
    }

    $PathRows = New-Object 'System.Collections.Generic.List[object]'
    $ExpansionRows = New-Object 'System.Collections.Generic.List[object]'
    $SeenEdges = @{}

    while ($Queue.Count -gt 0) {
        $Node = $Queue.Dequeue()
        if ([int]$Node.Depth -ge $MaximumDepth) { continue }
        if (-not $EdgesByTrustee.ContainsKey([string]$Node.Key)) { continue }

        foreach ($Edge in $EdgesByTrustee[[string]$Node.Key]) {
            $EdgeKey = '{0}|{1}|{2}|{3}' -f $Node.Key,([string]$Edge.TargetDistinguishedName).ToLowerInvariant(),$Edge.Capability,$Node.Depth
            if ($SeenEdges.ContainsKey($EdgeKey)) { continue }
            $SeenEdges[$EdgeKey] = $true

            $PathId = 'TRANSITIVE-{0:D6}' -f $PathRows.Count
            $NextDepth = [int]$Node.Depth + 1
            $CreatesControl = Test-CapabilityCreatesControl ([string]$Edge.Capability) ([string]$Edge.TargetObjectType)
            $TerminalImpact = Test-CapabilityIsTerminalImpact ([string]$Edge.Capability) $Edge
            $PathRows.Add([pscustomobject][ordered]@{
                PathId=$PathId;Depth=$NextDepth;PredecessorPathId=$Node.PredecessorPathId
                SourcePrincipal=$Node.Identity;SourcePrincipalKey=$Node.Key
                Trustee=$Edge.Trustee;Capability=$Edge.Capability
                TargetObjectType=$Edge.TargetObjectType;TargetName=$Edge.TargetName
                TargetSamAccountName=$Edge.TargetSamAccountName;TargetDistinguishedName=$Edge.TargetDistinguishedName
                TargetAdminCount=$Edge.TargetAdminCount;TargetEnabled=$Edge.TargetEnabled
                CreatesNewControlNode=$CreatesControl;TerminalImpactLead=$TerminalImpact
                Priority=$Edge.Priority;NextValidator=$Edge.NextValidator
                SafetyState=(Get-PathSafetyState ([string]$Edge.Capability))
                DirectAceCount=$Edge.DirectAceCount;InheritedAceCount=$Edge.InheritedAceCount
                EvidenceState='Transitive graph lead; effective access and impact not reproduced'
            })

            if ($CreatesControl -and $NextDepth -lt $MaximumDepth) {
                foreach ($TargetKey in @(Get-TargetPrincipalKeys $Edge)) {
                    if ($null -eq $TargetKey) { continue }
                    if (-not $Reachable.ContainsKey($TargetKey)) {
                        $DisplayIdentity = [string]$Edge.TargetSamAccountName
                        if ([string]::IsNullOrWhiteSpace($DisplayIdentity)) { $DisplayIdentity = [string]$Edge.TargetName }
                        $ReachNode = [pscustomobject]@{Identity=$DisplayIdentity;Depth=$NextDepth;Source='TransitiveControl';PredecessorPathId=$PathId}
                        $Reachable[$TargetKey] = $ReachNode
                        $Queue.Enqueue([pscustomobject]@{Key=$TargetKey;Identity=$DisplayIdentity;Depth=$NextDepth;PredecessorPathId=$PathId})
                        $ReachableOrder.Add($ReachNode)
                        $ExpansionRows.Add([pscustomobject]@{NewReachableIdentity=$DisplayIdentity;Key=$TargetKey;Depth=$NextDepth;ViaPathId=$PathId;Capability=$Edge.Capability})
                    }
                }
            }
        }
    }

    $TerminalPaths = [object[]]@(
        $PathRows |
        Where-Object { $_.TerminalImpactLead } |
        Sort-Object Depth,Priority,TargetAdminCount,Capability,TargetName |
        Select-Object -First $MaximumReportedPaths
    )
    $TerminalCount = [int]@($TerminalPaths).Count

    $PathsJson=Join-Path $OutputDirectory 'transitive-control-paths.json';$PathsCsv=Join-Path $OutputDirectory 'transitive-control-paths.csv'
    $ReachJson=Join-Path $OutputDirectory 'reachable-principals.json';$ReachCsv=Join-Path $OutputDirectory 'reachable-principals.csv'
    $ExpansionJson=Join-Path $OutputDirectory 'graph-expansions.json';$ExpansionCsv=Join-Path $OutputDirectory 'graph-expansions.csv'
    $TerminalJson=Join-Path $OutputDirectory 'terminal-impact-paths.json';$TerminalCsv=Join-Path $OutputDirectory 'terminal-impact-paths.csv'
    Write-JsonArray $PathRows.ToArray() $PathsJson;$PathRows|Export-Csv $PathsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ReachableOrder.ToArray() $ReachJson;$ReachableOrder|Export-Csv $ReachCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ExpansionRows.ToArray() $ExpansionJson;$ExpansionRows|Export-Csv $ExpansionCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $TerminalPaths $TerminalJson;$TerminalPaths|Export-Csv $TerminalCsv -NoTypeInformation -Encoding UTF8

    $DepthCounts = [object[]]@($PathRows | Group-Object Depth | Sort-Object Name | ForEach-Object {[pscustomobject]@{Depth=[int]$_.Name;Count=[int]$_.Count}})
    $CapabilityCounts = [object[]]@($PathRows | Group-Object Capability | Sort-Object Count -Descending | ForEach-Object {[pscustomobject]@{Capability=$_.Name;Count=[int]$_.Count}})
    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status='Completed';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        CorrelationDirectory=$CorrelationDirectory;StartingIdentity=$StartingIdentity
        MaximumDepth=$MaximumDepth
        Counts=[pscustomobject]@{
            CandidateRelationships=$CandidateCount;SeedNodes=$ReachableOrder.Count
            IndexedTrustees=$EdgesByTrustee.Keys.Count;GraphPaths=$PathRows.Count
            NewReachablePrincipals=$ExpansionRows.Count;AllReachableNodes=$Reachable.Keys.Count
            TerminalImpactPathsBeforeLimit=@($PathRows|Where-Object{$_.TerminalImpactLead}).Count
            TerminalImpactPathsReturned=$TerminalCount
        }
        DepthCounts=$DepthCounts;CapabilityCounts=$CapabilityCounts
        InterpretationBoundary=@(
            'Graph edges represent plausible semantic control, not successful exploitation.',
            'Capability-to-control expansion is conservative but does not evaluate deny ACE precedence.',
            'Nested group membership beyond the supplied token is discovered only through WriteGroupMembership-style control edges.',
            'No path is a vulnerability until effective access and real reversible impact are reproduced.'
        )
        Safety=[pscustomobject]@{NetworkActivity='None';DirectoryQueries='None';DirectoryChanges='None';OllamaActivity='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'ad-object-control-transitive-graph-summary.json';Write-JsonDocument $Summary $SummaryPath

    $PathHtml=($TerminalPaths|Select-Object -First 100|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>'-f(Convert-HtmlText $_.Depth),(Convert-HtmlText $_.SourcePrincipal),(Convert-HtmlText $_.Capability),(Convert-HtmlText $_.TargetName),(Convert-HtmlText $_.NextValidator),(Convert-HtmlText $_.SafetyState)})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-AD-Object-Control-Transitive-Graph.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT AD Object-Control Transitive Graph</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT AD Object-Control Transitive Graph</h1><div class="card"><b>Starting identity:</b> $(Convert-HtmlText $StartingIdentity)<br><b>Maximum depth:</b> $MaximumDepth<br><b>Graph paths:</b> $($PathRows.Count)<br><b>New reachable principals:</b> $($ExpansionRows.Count)<br><b>Terminal impact paths:</b> $TerminalCount<br><b>Network activity:</b> None</div><h2>Terminal Impact Leads</h2><table><tr><th>Depth</th><th>Source</th><th>Capability</th><th>Target</th><th>Validator</th><th>Safety State</th></tr>$PathHtml</table><h2>Evidence</h2><ul><li><a href="transitive-control-paths.csv">All graph paths</a></li><li><a href="reachable-principals.csv">Reachable principals</a></li><li><a href="graph-expansions.csv">Graph expansions</a></li><li><a href="terminal-impact-paths.csv">Terminal impact paths</a></li><li><a href="ad-object-control-transitive-graph-summary.json">Structured summary</a></li><li><a href="../MSADPT-AD-Object-Control-Correlation.html">Correlation report</a></li></ul><p class="note">Graph paths are leads, not vulnerabilities. Effective rights and real reversible impact must be reproduced.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name-ne'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=[object[]]@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Transitive graph complete: paths=$($PathRows.Count), expansions=$($ExpansionRows.Count), terminal=$TerminalCount." Green
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        StartingIdentity=$StartingIdentity;MaximumDepth=$MaximumDepth;CandidateRelationshipCount=$CandidateCount
        SeedNodeCount=$ReachableOrder.Count;GraphPathCount=$PathRows.Count
        NewReachablePrincipalCount=$ExpansionRows.Count;AllReachableNodeCount=$Reachable.Keys.Count
        TerminalImpactPathCount=$TerminalCount;OutputDirectory=$OutputDirectory
        HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        NetworkActivity='None';DirectoryQueries='None';DirectoryChanges='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
