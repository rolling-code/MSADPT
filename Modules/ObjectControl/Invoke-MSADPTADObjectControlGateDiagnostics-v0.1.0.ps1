<#
.SYNOPSIS
Diagnoses MSADPT AD object-control selection gates and reduces correlated ACL evidence into attack-path leads.
.DESCRIPTION
Consumes deduplicated-control-candidates.json and behavioral-validation-candidates.json from the MSADPT
object-control semantic correlator. Produces a gate waterfall, trustee and target distributions, exclusion
reason evidence, starting-principal reachability using the current token evidence supplied by the operator
or an optional identity name, and a conservative final queue of distinct object-control paths.

This stage is local only by default. If -StartingIdentity is supplied without -StartingIdentityGroupsPath,
Active Directory group expansion is not attempted; the identity is used only for exact trustee matching.
No network operation, AD query, directory write, password reset, membership change, SPN write, RBCD write,
key-credential write, ownership change, DACL change, or Ollama call occurs.
.NOTES
Version: 0.1.0
Package identity: MSADPT-AD-OBJECT-CONTROL-GATE-DIAGNOSTICS
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$CorrelationDirectory,

    [string]$OutputDirectory,
    [string]$StartingIdentity,
    [string]$StartingIdentityGroupsPath,
    [ValidateRange(1,5000)][int]$MaximumFinalPaths = 250,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-AD-OBJECT-CONTROL-GATE-DIAGNOSTICS'
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
    return @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
}
function Read-JsonDocument {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=15)
    $Array = @($Rows)
    if ($Array.Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    } else {
        $Array | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $Check = @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($Check.Count -ne $Array.Count) { throw "JsonArrayRoundTripMismatch: $Path" }
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=15)
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
function Get-TrusteeClass {
    param([object]$Candidate)
    $Type = [string]$Candidate.TrusteeObjectType
    $Name = [string]$Candidate.Trustee
    if (-not [bool]$Candidate.TrusteeResolved) {
        if ($Name -match '^S-1-5-') { return 'UnresolvedSid' }
        return 'UnresolvedIdentity'
    }
    if ($Type -eq 'User') {
        if ($Candidate.TrusteeEnabled -eq $false) { return 'DisabledUser' }
        return 'EnabledUser'
    }
    if ($Type -eq 'Computer') {
        if ($Candidate.TrusteeEnabled -eq $false) { return 'DisabledComputer' }
        return 'EnabledComputer'
    }
    if ($Type -eq 'Group') { return 'SecurityGroup' }
    if ($Name -match '^(BUILTIN|NT AUTHORITY|Everyone|CREATOR OWNER)\\') { return 'WellKnownOrBuiltin' }
    return 'ResolvedOther'
}
function Get-TargetClass {
    param([object]$Candidate)
    if ($Candidate.TargetEnabled -eq $false) { return 'DisabledTarget' }
    if ($Candidate.TargetAdminCount -eq 1) { return 'ProtectedTarget' }
    if ([string]$Candidate.TargetObjectType -eq 'Domain') { return 'DomainRoot' }
    if ([string]$Candidate.TargetObjectType -eq 'OrganizationalUnit') { return 'OrganizationalUnit' }
    return 'ActiveStandardTarget'
}
function Get-ExclusionReasons {
    param([object]$Candidate,[hashtable]$ReachableTrustees)
    $Reasons = New-Object 'System.Collections.Generic.List[string]'
    $TrusteeClass = Get-TrusteeClass $Candidate
    if ($Candidate.Priority -notin @('P1','P2')) { $Reasons.Add('PriorityBelowP2') }
    if (-not [bool]$Candidate.BehavioralValidationReady) { $Reasons.Add('SemanticRefinementRequired') }
    if (-not [bool]$Candidate.TrusteeResolved) { $Reasons.Add('TrusteeUnresolved') }
    if ($TrusteeClass -in @('DisabledUser','DisabledComputer')) { $Reasons.Add('TrusteeDisabled') }
    if ($TrusteeClass -eq 'WellKnownOrBuiltin') { $Reasons.Add('BroadOrBuiltinTrustee') }
    if ($Candidate.TargetEnabled -eq $false) { $Reasons.Add('TargetDisabled') }
    if ([int]$Candidate.DirectAceCount -eq 0 -and [int]$Candidate.InheritedAceCount -gt 0) { $Reasons.Add('InheritedOnly') }
    $Normalized = Normalize-Identity $Candidate.Trustee
    if ($ReachableTrustees.Count -gt 0 -and -not $ReachableTrustees.ContainsKey($Normalized)) { $Reasons.Add('TrusteeNotReachableFromStartingPrincipal') }
    return @($Reasons.ToArray() | Sort-Object -Unique)
}
function Get-PathSafetyState {
    param([object]$Candidate)
    switch ([string]$Candidate.NextValidator) {
        'GroupMembershipBehavioralValidation' { return 'ReversibleIfDedicatedTestMemberAvailable' }
        'SpnWriteBehavioralValidation' { return 'ReversibleIfOriginalSpnSetCaptured' }
        'RbcdWriteBehavioralValidation' { return 'ReversibleIfOriginalDescriptorCaptured' }
        'KeyCredentialWriteBehavioralValidation' { return 'HighImpactRequiresDedicatedTestIdentity' }
        'PasswordResetRightBehavioralValidation' { return 'NotSafeWithoutDedicatedTestIdentity' }
        'DaclControlBehavioralValidation' { return 'HighImpactRequiresExactDaclBackupAndRestore' }
        'OwnershipControlBehavioralValidation' { return 'HighImpactRequiresExactOwnerRestore' }
        'ReplicationRightsValidation' { return 'ReadOnlyEffectiveRightsValidationFirst' }
        'GenericObjectControlBehavioralValidation' { return 'SemanticOperationSelectionRequired' }
        default { return 'SemanticRefinementRequired' }
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local gate diagnostics only. No network or directory operations.' DarkGray

    if (-not (Test-Path -LiteralPath $CorrelationDirectory -PathType Container)) {
        throw "CorrelationDirectoryMissing: $CorrelationDirectory"
    }
    $CandidatePath = Join-Path $CorrelationDirectory 'deduplicated-control-candidates.json'
    $PriorBehavioralPath = Join-Path $CorrelationDirectory 'behavioral-validation-candidates.json'
    $SourceSummaryPath = Join-Path $CorrelationDirectory 'ad-object-control-correlation-summary.json'
    $Candidates = Read-JsonArray $CandidatePath 'Deduplicated candidates'
    $PriorBehavioral = Read-JsonArray $PriorBehavioralPath 'Prior behavioral candidates'
    $SourceSummary = Read-JsonDocument $SourceSummaryPath 'Correlation summary'

    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $OutputDirectory = Join-Path $CorrelationDirectory 'GateDiagnostics-v0.1.0'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $ReachableTrustees = @{}
    if (-not [string]::IsNullOrWhiteSpace($StartingIdentity)) {
        $ReachableTrustees[(Normalize-Identity $StartingIdentity)] = 'ExactStartingIdentity'
    }
    if (-not [string]::IsNullOrWhiteSpace($StartingIdentityGroupsPath)) {
        Require-File $StartingIdentityGroupsPath 'Starting identity group evidence'
        $GroupEvidenceText = Get-Content -LiteralPath $StartingIdentityGroupsPath -Raw
        foreach ($Line in ($GroupEvidenceText -split "`r?`n")) {
            if ($Line -match '^\s*([^\s].*?\\[^\s].*?)\s{2,}') {
                $Identity = $Matches[1].Trim()
                $ReachableTrustees[(Normalize-Identity $Identity)] = 'TokenGroupEvidence'
            }
        }
    }
    Write-Step 'OK' "Loaded $($Candidates.Count) deduplicated candidate(s); reachable trustee evidence=$($ReachableTrustees.Count)." Green

    $DiagnosticRows = New-Object 'System.Collections.Generic.List[object]'
    $ExclusionRows = New-Object 'System.Collections.Generic.List[object]'
    $FinalPathRows = New-Object 'System.Collections.Generic.List[object]'
    $Processed = 0

    foreach ($Candidate in $Candidates) {
        $Processed++
        if ($Processed -eq 1 -or $Processed % 25000 -eq 0 -or $Processed -eq $Candidates.Count) {
            $Percent = [int](($Processed/[double]$Candidates.Count)*100)
            Write-Step 'PROCESS' "Gate evaluation $Processed/$($Candidates.Count) ($Percent%)." DarkCyan
        }

        $TrusteeClass = Get-TrusteeClass $Candidate
        $TargetClass = Get-TargetClass $Candidate
        $Reasons = @(Get-ExclusionReasons $Candidate $ReachableTrustees)
        $Eligible = ($Reasons.Count -eq 0)
        $ReachabilityState = if ($ReachableTrustees.Count -eq 0) {'NotEvaluated'}elseif($ReachableTrustees.ContainsKey((Normalize-Identity $Candidate.Trustee))){'DirectlyReachable'}else{'NotReachable'}

        $DiagnosticRows.Add([pscustomobject][ordered]@{
            CandidateId=$Candidate.CandidateId;Priority=$Candidate.Priority
            Trustee=$Candidate.Trustee;TrusteeClass=$TrusteeClass;TrusteeReachability=$ReachabilityState
            TargetObjectType=$Candidate.TargetObjectType;TargetName=$Candidate.TargetName
            TargetDistinguishedName=$Candidate.TargetDistinguishedName;TargetClass=$TargetClass
            Capability=$Candidate.Capability;NextValidator=$Candidate.NextValidator
            DirectAceCount=$Candidate.DirectAceCount;InheritedAceCount=$Candidate.InheritedAceCount
            BehavioralValidationReady=$Candidate.BehavioralValidationReady
            EligibleForFinalQueue=$Eligible;ExclusionReasons=$Reasons
        })

        foreach ($Reason in $Reasons) {
            $ExclusionRows.Add([pscustomobject]@{
                CandidateId=$Candidate.CandidateId;Reason=$Reason;Priority=$Candidate.Priority
                Trustee=$Candidate.Trustee;Target=$Candidate.TargetDistinguishedName;Capability=$Candidate.Capability
            })
        }

        if ($Eligible) {
            $FinalPathRows.Add([pscustomobject][ordered]@{
                PathId=('ADPATH-{0:D5}' -f $FinalPathRows.Count)
                Priority=$Candidate.Priority;StartingPrincipal=if($null-ne$StartingIdentity){$StartingIdentity}else{'Unspecified'}
                Trustee=$Candidate.Trustee;TrusteeClass=$TrusteeClass;TrusteeReachability=$ReachabilityState
                Capability=$Candidate.Capability;TargetObjectType=$Candidate.TargetObjectType
                TargetName=$Candidate.TargetName;TargetDistinguishedName=$Candidate.TargetDistinguishedName
                TargetClass=$TargetClass;DirectAceCount=$Candidate.DirectAceCount
                InheritedAceCount=$Candidate.InheritedAceCount;NextValidator=$Candidate.NextValidator
                SafetyState=(Get-PathSafetyState $Candidate)
                EvidenceState='Gate diagnostics passed; effective rights and reversible impact validation pending'
                Interpretation='The candidate passed the current local gates. No directory operation or impact has been reproduced.'
            })
        }
    }

    $FinalPaths = @($FinalPathRows | Sort-Object Priority,TargetClass,Capability,TargetName,Trustee | Select-Object -First $MaximumFinalPaths)

    $GateWaterfall = @(
        [pscustomobject]@{Gate='Deduplicated candidates';InputCount=$Candidates.Count;PassedCount=$Candidates.Count;RemovedCount=0}
        [pscustomobject]@{Gate='Priority P1 or P2';InputCount=$Candidates.Count;PassedCount=@($Candidates|Where-Object{$_.Priority-in@('P1','P2')}).Count;RemovedCount=@($Candidates|Where-Object{$_.Priority-notin@('P1','P2')}).Count}
        [pscustomobject]@{Gate='Semantic validator ready';InputCount=@($Candidates|Where-Object{$_.Priority-in@('P1','P2')}).Count;PassedCount=@($Candidates|Where-Object{$_.Priority-in@('P1','P2')-and$_.BehavioralValidationReady}).Count;RemovedCount=@($Candidates|Where-Object{$_.Priority-in@('P1','P2')-and-not$_.BehavioralValidationReady}).Count}
        [pscustomobject]@{Gate='Trustee resolved';InputCount=@($Candidates|Where-Object{$_.Priority-in@('P1','P2')-and$_.BehavioralValidationReady}).Count;PassedCount=@($Candidates|Where-Object{$_.Priority-in@('P1','P2')-and$_.BehavioralValidationReady-and$_.TrusteeResolved}).Count;RemovedCount=@($Candidates|Where-Object{$_.Priority-in@('P1','P2')-and$_.BehavioralValidationReady-and-not$_.TrusteeResolved}).Count}
        [pscustomobject]@{Gate='Active or group trustee';InputCount=@($DiagnosticRows|Where-Object{$_.Priority-in@('P1','P2')-and$_.BehavioralValidationReady-and$_.TrusteeClass-notin@('UnresolvedSid','UnresolvedIdentity')}).Count;PassedCount=@($DiagnosticRows|Where-Object{$_.Priority-in@('P1','P2')-and$_.BehavioralValidationReady-and$_.TrusteeClass-notin@('DisabledUser','DisabledComputer','UnresolvedSid','UnresolvedIdentity')}).Count;RemovedCount=@($DiagnosticRows|Where-Object{$_.Priority-in@('P1','P2')-and$_.BehavioralValidationReady-and$_.TrusteeClass-in@('DisabledUser','DisabledComputer')}).Count}
        [pscustomobject]@{Gate='Direct or mixed ACE';InputCount=$DiagnosticRows.Count;PassedCount=@($DiagnosticRows|Where-Object{$_.DirectAceCount-gt0}).Count;RemovedCount=@($DiagnosticRows|Where-Object{$_.DirectAceCount-eq0-and$_.InheritedAceCount-gt0}).Count}
        [pscustomobject]@{Gate='Starting-principal reachability';InputCount=@($DiagnosticRows|Where-Object{$_.ExclusionReasons.Count-eq0-or$_.ExclusionReasons-notcontains'TrusteeNotReachableFromStartingPrincipal'}).Count;PassedCount=if($ReachableTrustees.Count-eq0){0}else{@($DiagnosticRows|Where-Object{$_.TrusteeReachability-eq'DirectlyReachable'}).Count};RemovedCount=if($ReachableTrustees.Count-eq0){0}else{@($DiagnosticRows|Where-Object{$_.TrusteeReachability-eq'NotReachable'}).Count}}
        [pscustomobject]@{Gate='Final queue';InputCount=$DiagnosticRows.Count;PassedCount=$FinalPathRows.Count;RemovedCount=($DiagnosticRows.Count-$FinalPathRows.Count)}
    )

    $TrusteeDistribution = @($DiagnosticRows | Group-Object TrusteeClass | Sort-Object Count -Descending | ForEach-Object {[pscustomobject]@{TrusteeClass=$_.Name;Count=$_.Count}})
    $CapabilityDistribution = @($DiagnosticRows | Group-Object Capability | Sort-Object Count -Descending | ForEach-Object {[pscustomobject]@{Capability=$_.Name;Count=$_.Count}})
    $TargetDistribution = @($DiagnosticRows | Group-Object TargetClass | Sort-Object Count -Descending | ForEach-Object {[pscustomobject]@{TargetClass=$_.Name;Count=$_.Count}})
    $ExclusionDistribution = @($ExclusionRows | Group-Object Reason | Sort-Object Count -Descending | ForEach-Object {[pscustomobject]@{Reason=$_.Name;Count=$_.Count}})

    $DiagnosticsPath=Join-Path $OutputDirectory 'candidate-gate-diagnostics.json';$DiagnosticsCsv=Join-Path $OutputDirectory 'candidate-gate-diagnostics.csv'
    $ExclusionsPath=Join-Path $OutputDirectory 'candidate-exclusions.json';$ExclusionsCsv=Join-Path $OutputDirectory 'candidate-exclusions.csv'
    $FinalPath=Join-Path $OutputDirectory 'final-attack-path-queue.json';$FinalCsv=Join-Path $OutputDirectory 'final-attack-path-queue.csv'
    $WaterfallPath=Join-Path $OutputDirectory 'gate-waterfall.json';$WaterfallCsv=Join-Path $OutputDirectory 'gate-waterfall.csv'
    Write-JsonArray $DiagnosticRows.ToArray() $DiagnosticsPath;$DiagnosticRows|Export-Csv $DiagnosticsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ExclusionRows.ToArray() $ExclusionsPath;$ExclusionRows|Export-Csv $ExclusionsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $FinalPaths $FinalPath;$FinalPaths|Export-Csv $FinalCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $GateWaterfall $WaterfallPath;$GateWaterfall|Export-Csv $WaterfallCsv -NoTypeInformation -Encoding UTF8

    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status='Completed';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Domain=[string]$SourceSummary.Domain;CorrelationDirectory=$CorrelationDirectory
        StartingPrincipal=[pscustomobject]@{Identity=$StartingIdentity;GroupEvidencePath=$StartingIdentityGroupsPath;ReachableTrusteeCount=$ReachableTrustees.Count;ReachabilityMode=if($ReachableTrustees.Count-gt0){'Exact identity and token evidence'}else{'Not evaluated'}}
        Counts=[pscustomobject]@{DeduplicatedCandidates=$Candidates.Count;PriorBehavioralCandidates=$PriorBehavioral.Count;DiagnosticRows=$DiagnosticRows.Count;ExclusionRows=$ExclusionRows.Count;FinalPathsBeforeLimit=$FinalPathRows.Count;FinalPathsReturned=$FinalPaths.Count}
        GateWaterfall=$GateWaterfall;TrusteeDistribution=$TrusteeDistribution;CapabilityDistribution=$CapabilityDistribution;TargetDistribution=$TargetDistribution;ExclusionDistribution=$ExclusionDistribution
        InterpretationBoundary=@(
            'Reachability is exact-match only unless token-group evidence is supplied.',
            'Nested group expansion and graph reachability are not performed in this local-only version.',
            'A final queue entry is not a vulnerability finding.',
            'Effective access, deny precedence, protected-object behavior, and reversible impact remain to be validated.'
        )
        Safety=[pscustomobject]@{NetworkActivity='None';DirectoryQueries='None';DirectoryChanges='None';OllamaActivity='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'ad-object-control-gate-diagnostics-summary.json';Write-JsonDocument $Summary $SummaryPath

    $WaterfallHtml=($GateWaterfall|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>'-f(Convert-HtmlText $_.Gate),(Convert-HtmlText $_.InputCount),(Convert-HtmlText $_.PassedCount),(Convert-HtmlText $_.RemovedCount)})-join"`n"
    $PathHtml=($FinalPaths|Select-Object -First 100|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>'-f(Convert-HtmlText $_.Priority),(Convert-HtmlText $_.Trustee),(Convert-HtmlText $_.Capability),(Convert-HtmlText $_.TargetName),(Convert-HtmlText $_.NextValidator),(Convert-HtmlText $_.SafetyState)})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-AD-Object-Control-Gate-Diagnostics.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT AD Object-Control Gate Diagnostics</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT AD Object-Control Gate Diagnostics</h1><div class="card"><b>Domain:</b> $(Convert-HtmlText $Summary.Domain)<br><b>Deduplicated candidates:</b> $($Candidates.Count)<br><b>Prior behavioral queue:</b> $($PriorBehavioral.Count)<br><b>Final paths:</b> $($FinalPaths.Count)<br><b>Reachability mode:</b> $(Convert-HtmlText $Summary.StartingPrincipal.ReachabilityMode)<br><b>Network activity:</b> None</div><h2>Gate Waterfall</h2><table><tr><th>Gate</th><th>Input</th><th>Passed</th><th>Removed</th></tr>$WaterfallHtml</table><h2>Final Attack-Path Queue</h2><table><tr><th>Priority</th><th>Trustee</th><th>Capability</th><th>Target</th><th>Validator</th><th>Safety State</th></tr>$PathHtml</table><h2>Evidence</h2><ul><li><a href="gate-waterfall.csv">Gate waterfall</a></li><li><a href="candidate-gate-diagnostics.csv">Candidate diagnostics</a></li><li><a href="candidate-exclusions.csv">Exclusions</a></li><li><a href="final-attack-path-queue.csv">Final queue</a></li><li><a href="ad-object-control-gate-diagnostics-summary.json">Structured summary</a></li><li><a href="../MSADPT-AD-Object-Control-Correlation.html">Correlation report</a></li></ul><p class="note">Final queue entries are validation leads, not vulnerabilities. Real reversible impact must be reproduced.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name-ne'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Gate diagnostics complete: input=$($Candidates.Count), exclusions=$($ExclusionRows.Count), final paths=$($FinalPaths.Count)." Green
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Domain=$Summary.Domain
        DeduplicatedCandidateCount=$Candidates.Count;PriorBehavioralCandidateCount=$PriorBehavioral.Count
        ExclusionRecordCount=$ExclusionRows.Count;FinalPathCountBeforeLimit=$FinalPathRows.Count
        FinalPathCount=$FinalPaths.Count;ReachableTrusteeCount=$ReachableTrustees.Count
        ReachabilityMode=$Summary.StartingPrincipal.ReachabilityMode;OutputDirectory=$OutputDirectory
        HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        NetworkActivity='None';DirectoryQueries='None';DirectoryChanges='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
