<#
.SYNOPSIS
Builds an autonomous, evidence-based readiness decision for controlled LDAP relay reproduction.
.DESCRIPTION
Consumes completed MSADPT relay behavioral-validation evidence. Selects LDAP targets where unsigned
and unsealed authenticated sessions were reproduced, inventories locally available relay and capture
tooling, checks listener-port availability locally, determines whether a bounded impact and rollback
operation has been selected, and creates one HTML report with linked JSON and CSV evidence.

This readiness stage performs no coercion, credential capture, relay, authentication forwarding,
directory modification, machine creation, ticket operation, or Ollama call. It refuses to mark a
relay execution Ready unless all source, listener, target, tool, impact, rollback, and cleanup gates
are explicitly satisfied.
.NOTES
Version: 0.1.1
Package identity: MSADPT-RELAY-REPRODUCTION-READINESS
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$BehavioralValidationDirectory,

    [string]$OutputDirectory,
    [string]$AuthenticationSource,
    [string]$ExpectedRelayedIdentity,
    [string]$ImpactOperation,
    [string]$RollbackOperation,
    [int[]]$ListenerPorts = @(445,80),
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-RELAY-REPRODUCTION-READINESS'
$PackageVersion = '0.1.1'
$OperationalErrors = New-Object 'System.Collections.Generic.List[object]'

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
function Get-ToolRecord {
    param([string]$Name,[string]$Purpose)
    $Command = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    return [pscustomobject][ordered]@{
        Name=$Name;Purpose=$Purpose;Available=($null-ne$Command)
        Path=if($null-ne$Command){[string]$Command.Source}else{$null}
        Version=if($null-ne$Command){[string]$Command.Version}else{$null}
    }
}
function Test-LocalListenerPort {
    param([int]$Port)

    $Listeners = @()
    $ProcessIds = @()
    $InspectionStatus = 'Completed'
    $ErrorText = $null

    try {
        $Command = Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue
        if ($null -eq $Command) {
            $InspectionStatus = 'Inconclusive'
            $ErrorText = 'Get-NetTCPConnection is unavailable.'
        }
        else {
            $Listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
            foreach ($Listener in $Listeners) {
                $Property = $Listener.PSObject.Properties['OwningProcess']
                if ($null -ne $Property -and $null -ne $Property.Value) {
                    $ProcessIds += [int]$Property.Value
                }
            }
            $ProcessIds = @($ProcessIds | Sort-Object -Unique)
        }
    }
    catch {
        $InspectionStatus = 'Inconclusive'
        $ErrorText = $_.Exception.Message
    }

    $Available = $null
    $Interpretation = 'Listener availability could not be determined.'
    if ($InspectionStatus -eq 'Completed') {
        $Available = ($Listeners.Count -eq 0)
        if ($Available) { $Interpretation = 'No existing local listener detected.' }
        else { $Interpretation = 'Port already has one or more local listeners.' }
    }

    return [pscustomobject][ordered]@{
        Port=$Port;Protocol='TCP';Status=$InspectionStatus;Available=$Available
        ExistingListenerCount=$Listeners.Count;OwningProcessIds=@($ProcessIds)
        Interpretation=$Interpretation;Error=$ErrorText
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local readiness analysis only. No network traffic or relay execution.' DarkGray

    if (-not (Test-Path -LiteralPath $BehavioralValidationDirectory -PathType Container)) {
        throw "BehavioralValidationDirectoryMissing: $BehavioralValidationDirectory"
    }
    if ($null-eq$OutputDirectory -or $OutputDirectory.Trim().Length-eq0) {
        $OutputDirectory = Join-Path $BehavioralValidationDirectory 'RelayReproductionReadiness-v0.1.1'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count-gt0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $BehavioralSummaryPath = Join-Path $BehavioralValidationDirectory 'relay-behavioral-validation-summary.json'
    $SigningPath = Join-Path $BehavioralValidationDirectory 'ldap-signing-behavioral-validation.json'
    $MachinePath = Join-Path $BehavioralValidationDirectory 'machine-account-authorization-validation.json'
    $BehavioralSummary = Read-JsonDocument $BehavioralSummaryPath 'Behavioral summary'
    $SigningRows = Read-JsonArray $SigningPath 'LDAP signing behavior'
    $MachineResult = Read-JsonDocument $MachinePath 'Machine account authorization'

    $Targets = @(
        $SigningRows |
        Where-Object { [bool]$_.BindSucceeded -and [string]$_.Disposition -eq 'PrerequisiteReproduced' } |
        Select-Object -ExpandProperty Target -Unique |
        Sort-Object
    )
    Write-Step 'OK' "Unsigned LDAP prerequisite targets: $($Targets.Count)." Green

    $Tools = @(
        Get-ToolRecord 'python.exe' 'Python runtime for repository-provided protocol tooling'
        Get-ToolRecord 'python' 'Python runtime for repository-provided protocol tooling'
        Get-ToolRecord 'ntlmrelayx.py' 'NTLM relay engine'
        Get-ToolRecord 'impacket-ntlmrelayx' 'NTLM relay engine'
        Get-ToolRecord 'nmap.exe' 'Network validation and evidence collection'
        Get-ToolRecord 'nmap' 'Network validation and evidence collection'
    )
    $ListenerRows = @(
        foreach ($Port in $ListenerPorts) { Test-LocalListenerPort $Port }
    )
    foreach ($ListenerRow in $ListenerRows) {
        if ($ListenerRow.Status -ne 'Completed') {
            $OperationalErrors.Add([pscustomobject][ordered]@{
                Stage='ListenerInspection';Target='localhost';Protocol='TCP';Port=$ListenerRow.Port
                Status='Inconclusive';Error=$ListenerRow.Error
            })
        }
    }

    $RelayToolAvailable = @($Tools | Where-Object { $_.Name -in @('ntlmrelayx.py','impacket-ntlmrelayx') -and $_.Available }).Count-gt0
    $PythonAvailable = @($Tools | Where-Object { $_.Name -in @('python.exe','python') -and $_.Available }).Count-gt0
    $ListenerAvailable = @($ListenerRows | Where-Object { $_.Status -eq 'Completed' -and $_.Available -eq $true }).Count -gt 0
    $SourceDefined = -not [string]::IsNullOrWhiteSpace($AuthenticationSource)
    $IdentityDefined = -not [string]::IsNullOrWhiteSpace($ExpectedRelayedIdentity)
    $ImpactDefined = -not [string]::IsNullOrWhiteSpace($ImpactOperation)
    $RollbackDefined = -not [string]::IsNullOrWhiteSpace($RollbackOperation)
    $TargetDefined = $Targets.Count-gt0
    $CleanupVerified = [bool]$BehavioralSummary.Safety.CleanupVerified
    $MachineCreationBlocked = ([string]$MachineResult.Result -ne 'CreateReadDeleteReproduced')

    $GateRows = @(
        [pscustomobject]@{Gate='Unsigned LDAP target';Passed=$TargetDefined;Evidence=($Targets -join ', ');Required=$true}
        [pscustomobject]@{Gate='Relay tool available';Passed=$RelayToolAvailable;Evidence=(@($Tools|Where-Object{$_.Name-in@('ntlmrelayx.py','impacket-ntlmrelayx')-and$_.Available}).Path -join ', ');Required=$true}
        [pscustomobject]@{Gate='Python runtime available';Passed=$PythonAvailable;Evidence=(@($Tools|Where-Object{$_.Name-in@('python.exe','python')-and$_.Available}).Path -join ', ');Required=$false}
        [pscustomobject]@{Gate='Listener port available';Passed=$ListenerAvailable;Evidence=(@($ListenerRows | Where-Object { $_.Status -eq 'Completed' -and $_.Available -eq $true }).Port -join ', ');Required=$true}
        [pscustomobject]@{Gate='Authentication source defined';Passed=$SourceDefined;Evidence=$AuthenticationSource;Required=$true}
        [pscustomobject]@{Gate='Expected relayed identity bounded';Passed=$IdentityDefined;Evidence=$ExpectedRelayedIdentity;Required=$true}
        [pscustomobject]@{Gate='Impact operation selected';Passed=$ImpactDefined;Evidence=$ImpactOperation;Required=$true}
        [pscustomobject]@{Gate='Rollback operation selected';Passed=$RollbackDefined;Evidence=$RollbackOperation;Required=$true}
        [pscustomobject]@{Gate='Prior cleanup verified';Passed=$CleanupVerified;Evidence=[string]$BehavioralSummary.Safety.RemainingTestObjectDn;Required=$true}
        [pscustomobject]@{Gate='Machine-account path understood';Passed=$true;Evidence=if($MachineCreationBlocked){'Create/read/delete was not reproduced; no RBCD machine-account impact selected.'}else{'Machine creation authorization reproduced; impact still requires separate authorization.'};Required=$false}
    )

    $FailedRequiredGates = @($GateRows | Where-Object { $_.Required -and -not $_.Passed })
    $ExecutionState = if($FailedRequiredGates.Count-eq0){'ReadyForExplicitControlledExecution'}else{'NotReady'}
    $RecommendedAction = if($ExecutionState-eq'ReadyForExplicitControlledExecution'){
        'Generate an explicit controlled relay execution plan with a bounded source, one target, one reversible impact operation, and mandatory rollback verification.'
    }else{
        'Do not launch relay. Resolve the failed readiness gates and regenerate this readiness decision.'
    }

    $ToolsPath = Join-Path $OutputDirectory 'relay-tool-inventory.json'
    $ToolsCsv = Join-Path $OutputDirectory 'relay-tool-inventory.csv'
    $ListenersPath = Join-Path $OutputDirectory 'listener-port-readiness.json'
    $ListenersCsv = Join-Path $OutputDirectory 'listener-port-readiness.csv'
    $GatesPath = Join-Path $OutputDirectory 'relay-readiness-gates.json'
    $GatesCsv = Join-Path $OutputDirectory 'relay-readiness-gates.csv'
    $ErrorsPath = Join-Path $OutputDirectory 'operational-errors.json'
    Write-JsonArray $Tools $ToolsPath
    $Tools | Export-Csv -LiteralPath $ToolsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ListenerRows $ListenersPath
    $ListenerRows | Export-Csv -LiteralPath $ListenersCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $GateRows $GatesPath
    $GateRows | Export-Csv -LiteralPath $GatesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $OperationalErrors.ToArray() $ErrorsPath

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status='Completed';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Domain=[string]$BehavioralSummary.Domain;BehavioralValidationDirectory=$BehavioralValidationDirectory
        CandidateTargets=$Targets;ExecutionState=$ExecutionState
        Counts=[pscustomobject]@{CandidateTargets=$Targets.Count;Tools=$Tools.Count;AvailableListenerPorts=@($ListenerRows | Where-Object { $_.Status -eq 'Completed' -and $_.Available -eq $true }).Count;ReadinessGates=$GateRows.Count;FailedRequiredGates=$FailedRequiredGates.Count;OperationalErrors=$OperationalErrors.Count}
        FailedRequiredGates=@($FailedRequiredGates.Gate)
        RecommendedAction=$RecommendedAction
        Constraints=[pscustomobject]@{AuthenticationSource=$AuthenticationSource;ExpectedRelayedIdentity=$ExpectedRelayedIdentity;ImpactOperation=$ImpactOperation;RollbackOperation=$RollbackOperation}
        InterpretationBoundary=@(
            'Unsigned LDAP acceptance is a prerequisite and not proof of relay impact.',
            'The readiness gate does not perform coercion, capture, relay, or directory modification.',
            'MachineAccountQuota and machine-account authorization are not independently vulnerability findings.',
            'A confirmed vulnerability requires real relay plus meaningful impact and verified rollback.'
        )
        Safety=[pscustomobject]@{NetworkActivity='None';RelayAttempts='None';Coercion='None';DirectoryChanges='None';OllamaActivity='None'}
    }
    $SummaryPath = Join-Path $OutputDirectory 'relay-reproduction-readiness-summary.json'
    Write-JsonDocument $Summary $SummaryPath

    $GateHtml = ($GateRows | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Convert-HtmlText $_.Gate),(Convert-HtmlText $_.Passed),(Convert-HtmlText $_.Required),(Convert-HtmlText $_.Evidence)
    }) -join "`n"
    $ToolHtml = ($Tools | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Convert-HtmlText $_.Name),(Convert-HtmlText $_.Purpose),(Convert-HtmlText $_.Available),(Convert-HtmlText $_.Path)
    }) -join "`n"
    $ReportPath = Join-Path $OutputDirectory 'MSADPT-Relay-Reproduction-Readiness.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT Relay Reproduction Readiness</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.warn{color:#8a4b08}</style></head><body>
<h1>MSADPT Relay Reproduction Readiness</h1><div class="card"><b>Domain:</b> $(Convert-HtmlText $Summary.Domain)<br><b>Execution state:</b> $(Convert-HtmlText $ExecutionState)<br><b>Candidate targets:</b> $(Convert-HtmlText ($Targets -join ', '))<br><b>Failed required gates:</b> $($FailedRequiredGates.Count)<br><b>Network activity:</b> None</div>
<h2>Readiness Gates</h2><table><tr><th>Gate</th><th>Passed</th><th>Required</th><th>Evidence</th></tr>$GateHtml</table>
<h2>Tool Inventory</h2><table><tr><th>Tool</th><th>Purpose</th><th>Available</th><th>Path</th></tr>$ToolHtml</table>
<h2>Recommended Action</h2><p>$(Convert-HtmlText $RecommendedAction)</p>
<h2>Evidence</h2><ul><li><a href="relay-readiness-gates.csv">Readiness gates</a></li><li><a href="relay-tool-inventory.csv">Tool inventory</a></li><li><a href="listener-port-readiness.csv">Listener readiness</a></li><li><a href="relay-reproduction-readiness-summary.json">Structured summary</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="../MSADPT-Relay-Behavioral-Validation.html">Behavioral validation report</a></li></ul>
<p class="warn">This stage does not launch relay. A candidate is not a vulnerability. Real impact and verified rollback are required.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object{$_.Name-ne'evidence-manifest.json'} | Sort-Object Name)
    $ManifestRows=@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Readiness complete: state=$ExecutionState, targets=$($Targets.Count), failed required gates=$($FailedRequiredGates.Count)." Green
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Domain=$Summary.Domain;ExecutionState=$ExecutionState;CandidateTargetCount=$Targets.Count
        CandidateTargets=$Targets;ReadinessGateCount=$GateRows.Count;FailedRequiredGateCount=$FailedRequiredGates.Count
        OperationalErrorCount=$OperationalErrors.Count
        FailedRequiredGates=@($FailedRequiredGates.Gate);RelayToolAvailable=$RelayToolAvailable
        AvailableListenerPorts=@($ListenerRows | Where-Object { $_.Status -eq 'Completed' -and $_.Available -eq $true } | Select-Object -ExpandProperty Port)
        RecommendedAction=$RecommendedAction;OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath
        SummaryPath=$SummaryPath;ManifestPath=$ManifestPath;NetworkActivity='None';RelayAttempts='None';DirectoryChanges='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
