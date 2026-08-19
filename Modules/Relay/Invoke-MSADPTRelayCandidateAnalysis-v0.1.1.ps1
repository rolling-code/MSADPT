<#
.SYNOPSIS
Analyzes an existing MSADPT relay-prerequisite baseline and selects defensible behavioral validators.
.DESCRIPTION
Consumes deterministic JSON and Nmap evidence from MSADPT-RELAY-PREREQUISITE-ASSESSMENT. Parses SMB
signing behavior per target, correlates LDAP, LDAPS, Global Catalog, TLS, MachineAccountQuota, and
coverage errors, creates neutral relay candidates, selects the next validation modules, and produces
one standalone HTML report linking all local evidence.

This analysis is local only. It performs no network operations, coercion, relay, authentication,
directory changes, ticket operations, or Ollama calls. A prerequisite candidate is not a vulnerability.
.NOTES
Version: 0.1.1
Package identity: MSADPT-RELAY-CANDIDATE-ANALYSIS
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$BaselineDirectory,

    [string]$OutputDirectory,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-RELAY-CANDIDATE-ANALYSIS'
$PackageVersion = '0.1.1'

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
function Get-SmbSigningState {
    param([object]$Observation)
    $Text = (([string]$Observation.SigningEvidence) + "`n" + ([string]$Observation.RawConsole))
    if ([string]$Observation.Status -eq 'Failed') { return 'Inconclusive' }
    if ($Text -match '(?i)message signing enabled and required|signing\s*:\s*required|message_signing\s*:\s*required') { return 'Required' }
    if ($Text -match '(?i)message signing enabled but not required|message signing enabled and not required|signing\s*:\s*enabled.*not required') { return 'EnabledNotRequired' }
    if ($Text -match '(?i)message signing disabled|signing\s*:\s*disabled') { return 'Disabled' }
    if ($Text -match '(?i)message signing enabled|required') { return 'RequiredProbable' }
    return 'Inconclusive'
}
function Get-LdapState {
    param([object[]]$Rows,[string]$Target,[int]$Port)
    $Match = @($Rows | Where-Object { [string]$_.Target -eq $Target -and [int]$_.Port -eq $Port } | Select-Object -First 1)
    if ($Match.Count -eq 0) { return 'NotCollected' }
    if ([string]$Match[0].Status -eq 'Bound') { return 'Bound' }
    return 'Failed'
}
function Get-TcpState {
    param([object[]]$Rows,[string]$Target,[int]$Port)
    $Match = @($Rows | Where-Object { [string]$_.Target -eq $Target -and [int]$_.Port -eq $Port } | Select-Object -First 1)
    if ($Match.Count -eq 0) { return 'NotCollected' }
    if ([bool]$Match[0].Connected) { return 'Open' }
    return [string]$Match[0].Status
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local analysis only. No network operations will occur.' DarkGray

    if (-not (Test-Path -LiteralPath $BaselineDirectory -PathType Container)) {
        throw "BaselineDirectoryMissing: $BaselineDirectory"
    }
    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $OutputDirectory = Join-Path $BaselineDirectory 'CandidateAnalysis-v0.1.1'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $SummaryPath = Join-Path $BaselineDirectory 'relay-prerequisite-summary.json'
    $DcPath = Join-Path $BaselineDirectory 'domain-controllers.json'
    $TcpPath = Join-Path $BaselineDirectory 'tcp-reachability.json'
    $LdapPath = Join-Path $BaselineDirectory 'ldap-session-observations.json'
    $TlsPath = Join-Path $BaselineDirectory 'tls-certificate-observations.json'
    $SmbPath = Join-Path $BaselineDirectory 'smb-signing-nmap.json'
    $ErrorsPath = Join-Path $BaselineDirectory 'operational-errors.json'

    $BaselineSummary = Read-JsonDocument $SummaryPath 'Baseline summary'
    $DomainControllers = Read-JsonArray $DcPath 'Domain controllers'
    $TcpRows = Read-JsonArray $TcpPath 'TCP observations'
    $LdapRows = Read-JsonArray $LdapPath 'LDAP observations'
    $TlsRows = Read-JsonArray $TlsPath 'TLS observations'
    $SmbRows = Read-JsonArray $SmbPath 'SMB signing observations'
    $Errors = Read-JsonArray $ErrorsPath 'Operational errors'

    $Targets = @($DomainControllers.HostName | Where-Object { $null -ne $_ } | Sort-Object -Unique)
    if ($Targets.Count -eq 0) { throw 'No domain-controller targets exist in the baseline evidence.' }
    Write-Step 'OK' "Loaded baseline: targets=$($Targets.Count), TCP=$($TcpRows.Count), LDAP=$($LdapRows.Count), SMB=$($SmbRows.Count), errors=$($Errors.Count)." Green

    $TargetRows = New-Object 'System.Collections.Generic.List[object]'
    $CandidateRows = New-Object 'System.Collections.Generic.List[object]'
    $SelectorRows = New-Object 'System.Collections.Generic.List[object]'

    foreach ($Target in $Targets) {
        $Dc = @($DomainControllers | Where-Object { [string]$_.HostName -eq $Target } | Select-Object -First 1)[0]
        $Smb = @($SmbRows | Where-Object { [string]$_.Target -eq $Target } | Select-Object -First 1)
        $SmbSigning = if ($Smb.Count -gt 0) { Get-SmbSigningState $Smb[0] } else { 'NotCollected' }
        $Ldap389 = Get-LdapState $LdapRows $Target 389
        $Ldaps636 = Get-LdapState $LdapRows $Target 636
        $Gc3268 = Get-LdapState $LdapRows $Target 3268
        $Gc3269 = Get-LdapState $LdapRows $Target 3269
        $Tls636 = @($TlsRows | Where-Object { [string]$_.Target -eq $Target -and [int]$_.Port -eq 636 -and [string]$_.Status -eq 'Negotiated' }).Count -gt 0
        $Tls3269 = @($TlsRows | Where-Object { [string]$_.Target -eq $Target -and [int]$_.Port -eq 3269 -and [string]$_.Status -eq 'Negotiated' }).Count -gt 0
        $TargetErrors = @($Errors | Where-Object { [string]$_.Target -eq $Target })

        $Row = [pscustomobject][ordered]@{
            Target=$Target;Site=[string]$Dc.Site;OperatingSystem=[string]$Dc.OperatingSystem
            IsGlobalCatalog=[bool]$Dc.IsGlobalCatalog;IsReadOnly=[bool]$Dc.IsReadOnly
            Rpc135=(Get-TcpState $TcpRows $Target 135);Ldap389Tcp=(Get-TcpState $TcpRows $Target 389)
            Smb445Tcp=(Get-TcpState $TcpRows $Target 445);Ldaps636Tcp=(Get-TcpState $TcpRows $Target 636)
            Gc3268Tcp=(Get-TcpState $TcpRows $Target 3268);Gc3269Tcp=(Get-TcpState $TcpRows $Target 3269)
            Ldap389Session=$Ldap389;Ldaps636Session=$Ldaps636;Gc3268Session=$Gc3268;Gc3269Session=$Gc3269
            Tls636Negotiated=$Tls636;Tls3269Negotiated=$Tls3269;SmbSigning=$SmbSigning
            OperationalErrorCount=$TargetErrors.Count
        }
        $TargetRows.Add($Row)

        if ($Row.Smb445Tcp -eq 'Open' -and $SmbSigning -in @('Disabled','EnabledNotRequired')) {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateId=('SMB-RELAY-{0}' -f $Target);Technique='SMBRelay';Target=$Target
                Priority='P1';State='BehavioralValidationRequired'
                Preconditions=@('TCP/445 reachable',('SMB signing state: {0}' -f $SmbSigning))
                BlockingControls=@();NextValidator='SMBRelayBehavioralValidation'
                Interpretation='SMB relay prerequisite survived deterministic screening. Real relay and impact remain unproven.'
            })
        } elseif ($SmbSigning -in @('Required','RequiredProbable')) {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateId=('SMB-RELAY-{0}' -f $Target);Technique='SMBRelay';Target=$Target
                Priority='P4';State='BlockedByObservedControl';Preconditions=@('TCP/445 reachable')
                BlockingControls=@('SMB signing required');NextValidator='None'
                Interpretation='Observed SMB signing requirement blocks ordinary SMB relay to this target.'
            })
        } else {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateId=('SMB-RELAY-{0}' -f $Target);Technique='SMBRelay';Target=$Target
                Priority='P3';State='Inconclusive';Preconditions=@();BlockingControls=@();NextValidator='SMBSigningEvidenceRefinement'
                Interpretation='SMB signing evidence was unavailable or ambiguous.'
            })
        }

        if ($Ldap389 -eq 'Bound') {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateId=('LDAP-RELAY-{0}' -f $Target);Technique='LDAPRelay';Target=$Target
                Priority='P2';State='BehavioralValidationRequired'
                Preconditions=@('TCP/389 reachable','Authenticated Negotiate bind succeeded')
                BlockingControls=@();NextValidator='LDAPSigningBehavioralValidation'
                Interpretation='LDAP reachability survived baseline screening. Signing enforcement must be tested behaviorally.'
            })
        } else {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateId=('LDAP-RELAY-{0}' -f $Target);Technique='LDAPRelay';Target=$Target
                Priority='P4';State=if($Ldap389 -eq 'Failed'){'NotReachableThroughTestedMethod'}else{'Inconclusive'}
                Preconditions=@();BlockingControls=@();NextValidator='None'
                Interpretation='Authenticated LDAP session was not established through the tested method.'
            })
        }

        if ($Ldaps636 -eq 'Bound' -and $Tls636) {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateId=('LDAPS-RELAY-{0}' -f $Target);Technique='LDAPSRelay';Target=$Target
                Priority='P2';State='BehavioralValidationRequired'
                Preconditions=@('TCP/636 reachable','TLS negotiated','Authenticated LDAPS bind succeeded')
                BlockingControls=@();NextValidator='LDAPChannelBindingBehavioralValidation'
                Interpretation='LDAPS is available. Channel binding enforcement requires behavioral validation.'
            })
        } else {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateId=('LDAPS-RELAY-{0}' -f $Target);Technique='LDAPSRelay';Target=$Target
                Priority='P4';State=if($Ldaps636 -eq 'Failed'){'NotReachableThroughTestedMethod'}else{'Inconclusive'}
                Preconditions=@();BlockingControls=@();NextValidator='None'
                Interpretation='A usable LDAPS session was not established through the tested method.'
            })
        }
    }

    $MachineAccountQuota = $BaselineSummary.MachineAccountQuota
    if ($null -ne $MachineAccountQuota -and [int]$MachineAccountQuota -gt 0) {
        $CandidateRows.Add([pscustomobject][ordered]@{
            CandidateId='DOMAIN-MAQ';Technique='MachineAccountQuota';Target=[string]$BaselineSummary.Domain.DnsRoot
            Priority='P2';State='PrerequisiteObserved';Preconditions=@(('MachineAccountQuota={0}' -f $MachineAccountQuota))
            BlockingControls=@();NextValidator='MachineAccountCreationAuthorizationValidation'
            Interpretation='Nonzero quota can support later RBCD or relay chains but is not independently a vulnerability.'
        })
    }

    $Actionable = @($CandidateRows | Where-Object { $_.State -in @('BehavioralValidationRequired','PrerequisiteObserved') })
    $Validators = @($Actionable.NextValidator | Where-Object { $_ -ne 'None' } | Sort-Object -Unique)
    foreach ($Validator in $Validators) {
        $Rows = @($Actionable | Where-Object { $_.NextValidator -eq $Validator })
        $SelectorRows.Add([pscustomobject][ordered]@{
            Validator=$Validator;Priority=(@($Rows.Priority | Sort-Object | Select-Object -First 1)[0])
            CandidateCount=$Rows.Count;Targets=@($Rows.Target);Reason=($Rows.Interpretation -join ' ')
            NetworkActivity=if($Validator -eq 'MachineAccountCreationAuthorizationValidation'){'LDAP/389 or LDAPS/636 against one selected writable DC'}else{'Target-specific protocol validation'}
            ExecutionState='SelectedNotExecuted'
        })
    }

    $TargetJson=Join-Path $OutputDirectory 'relay-target-analysis.json'
    $TargetCsv=Join-Path $OutputDirectory 'relay-target-analysis.csv'
    $CandidatesJson=Join-Path $OutputDirectory 'relay-candidates.json'
    $CandidatesCsv=Join-Path $OutputDirectory 'relay-candidates.csv'
    $SelectorsJson=Join-Path $OutputDirectory 'selected-validators.json'
    $SelectorsCsv=Join-Path $OutputDirectory 'selected-validators.csv'
    Write-JsonArray $TargetRows.ToArray() $TargetJson
    $TargetRows | Export-Csv -LiteralPath $TargetCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $CandidateRows.ToArray() $CandidatesJson
    $CandidateRows | Export-Csv -LiteralPath $CandidatesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $SelectorRows.ToArray() $SelectorsJson
    $SelectorRows | Export-Csv -LiteralPath $SelectorsCsv -NoTypeInformation -Encoding UTF8

    $StateCounts = @(
        $CandidateRows | Group-Object State | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{State=$_.Name;Count=$_.Count}
        }
    )

    # PowerShell 7 can fail with "Argument types do not match" when a generic List[object]
    # is embedded directly in an ordered PSCustomObject. Materialize plain Object[] arrays first.
    $TargetArray = [object[]]$TargetRows.ToArray()
    $CandidateArray = [object[]]$CandidateRows.ToArray()
    $SelectorArray = [object[]]$SelectorRows.ToArray()
    $ActionableArray = [object[]]@($Actionable)
    $StateCountArray = [object[]]@($StateCounts)

    $AnalysisSummary = [pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status='Completed';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        BaselineDirectory=$BaselineDirectory;BaselineSummaryPath=$SummaryPath
        Domain=[string]$BaselineSummary.Domain.DnsRoot
        Counts=[pscustomobject][ordered]@{
            Targets=$Targets.Count;Candidates=$CandidateRows.Count;ActionableCandidates=$Actionable.Count
            SelectedValidators=$SelectorRows.Count;BaselineOperationalErrors=$Errors.Count
        }
        CandidateStateCounts=$StateCountArray
        MachineAccountQuota=$MachineAccountQuota
        SelectedValidators=$SelectorArray
        InterpretationBoundary=@(
            'Candidates are prioritized validation paths, not vulnerability findings.',
            'SMB signing evidence is treated as a blocking control only when Nmap output indicates signing is required.',
            'LDAP signing and LDAP channel binding require dedicated behavioral validators.',
            'MachineAccountQuota is a prerequisite lead only.',
            'No relay, coercion, authentication capture, or directory modification occurred during this analysis.'
        )
        Safety=[pscustomobject]@{NetworkActivity='None';DirectoryChanges='None';RelayAttempts='None';Coercion='None';OllamaActivity='None'}
    }
    $AnalysisSummaryPath=Join-Path $OutputDirectory 'relay-candidate-analysis-summary.json'
    Write-JsonDocument $AnalysisSummary $AnalysisSummaryPath

    $ReportPath=Join-Path $OutputDirectory 'MSADPT-Relay-Candidate-Analysis.html'
    $CandidateHtml = ($CandidateArray | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f `
        (Convert-HtmlText $_.Technique),(Convert-HtmlText $_.Target),(Convert-HtmlText $_.Priority),
        (Convert-HtmlText $_.State),(Convert-HtmlText $_.NextValidator),(Convert-HtmlText $_.Interpretation)
    }) -join "`n"
    $ValidatorHtml = ($SelectorArray | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f `
        (Convert-HtmlText $_.Validator),(Convert-HtmlText $_.Priority),(Convert-HtmlText $_.CandidateCount),
        (Convert-HtmlText ($_.Targets -join ', ')),(Convert-HtmlText $_.ExecutionState)
    }) -join "`n"
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT Relay Candidate Analysis</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body>
<h1>MSADPT Relay Candidate Analysis</h1><div class="card"><b>Status:</b> Completed<br><b>Domain:</b> $(Convert-HtmlText $AnalysisSummary.Domain)<br><b>Targets:</b> $($Targets.Count)<br><b>Actionable candidates:</b> $($Actionable.Count)<br><b>Network activity:</b> None</div>
<h2>Selected Validators</h2><table><tr><th>Validator</th><th>Priority</th><th>Candidates</th><th>Targets</th><th>State</th></tr>$ValidatorHtml</table>
<h2>Candidate Dispositions</h2><table><tr><th>Technique</th><th>Target</th><th>Priority</th><th>State</th><th>Next Validator</th><th>Interpretation</th></tr>$CandidateHtml</table>
<h2>Evidence</h2><ul><li><a href="relay-target-analysis.csv">Target analysis</a></li><li><a href="relay-candidates.csv">Candidates</a></li><li><a href="selected-validators.csv">Selected validators</a></li><li><a href="relay-candidate-analysis-summary.json">Structured summary</a></li><li><a href="../MSADPT-Relay-Prerequisite-Report.html">Baseline HTML report</a></li><li><a href="../operational-errors.json">Baseline operational errors</a></li></ul>
<p class="note">A candidate is not a vulnerability. Confirmation requires a real tool reproduction that demonstrates successful relay and meaningful impact. No relay or coercion occurred during this analysis.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object { $_.Name -ne 'evidence-manifest.json' } | Sort-Object Name)
    $ManifestRows=@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Candidate analysis complete: candidates=$($CandidateRows.Count), actionable=$($Actionable.Count), validators=$($SelectorRows.Count)." Green
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Domain=$AnalysisSummary.Domain;TargetCount=$Targets.Count;CandidateCount=$CandidateRows.Count
        ActionableCandidateCount=$Actionable.Count;SelectedValidatorCount=$SelectorRows.Count
        SelectedValidators=@($SelectorArray.Validator);BaselineOperationalErrorCount=$Errors.Count
        OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$AnalysisSummaryPath
        ManifestPath=$ManifestPath;NetworkActivity='None';DirectoryChanges='None';RelayAttempts='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
