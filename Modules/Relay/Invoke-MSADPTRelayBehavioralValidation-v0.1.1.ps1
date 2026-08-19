<#
.SYNOPSIS
Executes selected MSADPT LDAP signing, LDAPS channel-binding capability, and MachineAccountQuota behavioral validators.
.DESCRIPTION
Consumes selected-validators.json from MSADPT relay candidate analysis. Announces every network and write operation
before execution. Tests LDAP Negotiate binding with signing and sealing explicitly disabled, records LDAPS/CBT test
capability without overstating unsupported CBT behavior, and performs one controlled machine-account create/read/delete
cycle when the machine-account validator is selected. Per-target failures are evidence and do not stop other assets.

The machine account uses a generated neutral name, is created disabled with no SPNs, is read back, deleted immediately,
and its removal is verified. Failure to verify cleanup prevents a Passed result.
.NOTES
Version: 0.1.1
Package identity: MSADPT-RELAY-BEHAVIORAL-VALIDATION
Execution class: authorized_controlled_behavioral_validation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateAnalysisDirectory,

    [string]$OutputDirectory,
    [string]$Server,
    [PSCredential]$Credential,
    [ValidateRange(3,30)][int]$ProtocolTimeoutSeconds = 8,
    [switch]$SkipMachineAccountCreateDelete,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-RELAY-BEHAVIORAL-VALIDATION'
$PackageVersion = '0.1.1'
$OperationalErrors = New-Object 'System.Collections.Generic.List[object]'
$CreatedMachineDn = $null
$CleanupVerified = $true

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
function Add-OperationalError {
    param([string]$Stage,[string]$Target,[string]$Protocol,[object]$Port,[string]$ErrorText)
    $OperationalErrors.Add([pscustomobject][ordered]@{
        Stage=$Stage;Target=$Target;Protocol=$Protocol;Port=$Port;Status='Failed';Error=$ErrorText
    })
}
function Get-FirstTextValue {
    param([object]$Value)
    foreach ($Item in @($Value)) {
        $Text = [string]$Item
        if ($null -ne $Text -and $Text.Trim().Length -gt 0) { return $Text.Trim() }
    }
    return $null
}
function Test-UnsignedNegotiateLdap {
    param([string]$Target,[int]$TimeoutSeconds,[PSCredential]$Credential)
    $Started = Get-Date
    $Connection = $null
    try {
        $Identifier = New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier($Target,389,$false,$false)
        $Connection = New-Object DirectoryServices.Protocols.LdapConnection($Identifier)
        $Connection.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $Connection.SessionOptions.ProtocolVersion = 3
        $Connection.SessionOptions.SecureSocketLayer = $false
        $Connection.SessionOptions.Signing = $false
        $Connection.SessionOptions.Sealing = $false
        $Connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
        if ($null -ne $Credential) { $Connection.Credential = $Credential.GetNetworkCredential() }
        $Connection.Bind()
        $Request = New-Object DirectoryServices.Protocols.SearchRequest('', '(objectClass=*)', [DirectoryServices.Protocols.SearchScope]::Base, @('defaultNamingContext'))
        $Response = $Connection.SendRequest($Request)
        $NamingContext = $null
        if ($Response.Entries.Count -gt 0 -and $Response.Entries[0].Attributes['defaultNamingContext']) {
            $NamingContext = [string]$Response.Entries[0].Attributes['defaultNamingContext'][0]
        }
        return [pscustomobject][ordered]@{
            Validator='LDAPSigningBehavioralValidation';Target=$Target;Port=389;Protocol='LDAP'
            AuthType='Negotiate';SigningRequested=$false;SealingRequested=$false
            BindSucceeded=$true;RootDseRead=$true;DefaultNamingContext=$NamingContext
            Result='UnsignedSessionAccepted';Disposition='PrerequisiteReproduced'
            Interpretation='The tested LDAP client explicitly disabled signing and sealing and completed an authenticated bind plus RootDSE read. Relay impact remains unproven.'
            StartedUtc=$Started.ToUniversalTime().ToString('o');CompletedUtc=(Get-Date).ToUniversalTime().ToString('o');Error=$null
        }
    } catch {
        $Message = $_.Exception.Message
        return [pscustomobject][ordered]@{
            Validator='LDAPSigningBehavioralValidation';Target=$Target;Port=389;Protocol='LDAP'
            AuthType='Negotiate';SigningRequested=$false;SealingRequested=$false
            BindSucceeded=$false;RootDseRead=$false;DefaultNamingContext=$null
            Result='UnsignedSessionRejectedOrUnavailable';Disposition='BlockedOrInconclusive'
            Interpretation='The tested unsigned and unsealed Negotiate LDAP session did not complete. The captured error must distinguish signing enforcement from reachability or authorization failure.'
            StartedUtc=$Started.ToUniversalTime().ToString('o');CompletedUtc=(Get-Date).ToUniversalTime().ToString('o');Error=$Message
        }
    } finally {
        if ($null -ne $Connection) { $Connection.Dispose() }
    }
}
function Get-LdapsCbtCapabilityResult {
    param([string]$Target)
    return [pscustomobject][ordered]@{
        Validator='LDAPChannelBindingBehavioralValidation';Target=$Target;Port=636;Protocol='LDAPS'
        TestMethod='System.DirectoryServices.Protocols LdapConnection'
        DeliberateCbtOmissionSupported=$false;DeliberateInvalidCbtSupported=$false
        Result='NotExecutedUnsupportedByCurrentClient';Disposition='Inconclusive'
        Interpretation='The current client API does not provide a deterministic control to omit or corrupt the CBT while preserving an otherwise equivalent bind. A normal LDAPS bind cannot prove CBT enforcement or absence.'
        NetworkActivity='None for this capability record';Error=$null
    }
}
function New-NeutralMachineName {
    $Suffix = ([Guid]::NewGuid().ToString('N').Substring(0,8)).ToUpperInvariant()
    return ('MSADPT-{0}' -f $Suffix)
}
function Invoke-MachineAccountCreateDelete {
    param([string[]]$CandidateServers,[object]$Domain,[PSCredential]$Credential)

    $Name = New-NeutralMachineName
    $SamAccountName = "$Name`$"
    $ComputersContainer = [string]$Domain.ComputersContainer
    $Attempts = New-Object 'System.Collections.Generic.List[object]'

    foreach ($CandidateServer in $CandidateServers) {
        $Started = Get-Date
        try {
            Write-Step 'CREATE' "$CandidateServer LDAP/ADWS: create disabled computer $Name in $ComputersContainer" Magenta
            $Parameters = @{
                Name=$Name;SamAccountName=$SamAccountName;Path=$ComputersContainer
                Enabled=$false;Server=$CandidateServer;PassThru=$true;ErrorAction='Stop'
                Description='Temporary MSADPT authorized validation object; automatic cleanup required.'
            }
            if ($null -ne $Credential) { $Parameters.Credential = $Credential }
            $Created = New-ADComputer @Parameters
            $script:CreatedMachineDn = [string]$Created.DistinguishedName

            $ReadParameters = @{Identity=$script:CreatedMachineDn;Server=$CandidateServer;Properties='servicePrincipalName','enabled','whenCreated';ErrorAction='Stop'}
            if ($null -ne $Credential) { $ReadParameters.Credential = $Credential }
            $ReadBack = Get-ADComputer @ReadParameters

            Write-Step 'DELETE' "$CandidateServer LDAP/ADWS: delete $($script:CreatedMachineDn)" Magenta
            $RemoveParameters = @{Identity=$script:CreatedMachineDn;Server=$CandidateServer;Confirm=$false;ErrorAction='Stop'}
            if ($null -ne $Credential) { $RemoveParameters.Credential = $Credential }
            Remove-ADComputer @RemoveParameters

            $StillExists = $false
            try {
                $null = Get-ADComputer @ReadParameters
                $StillExists = $true
            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                $StillExists = $false
            }
            $script:CleanupVerified = -not $StillExists
            if (-not $script:CleanupVerified) { throw 'Machine-account cleanup could not be verified.' }
            $script:CreatedMachineDn = $null

            return [pscustomobject][ordered]@{
                Validator='MachineAccountCreationAuthorizationValidation';Target=$CandidateServer
                Port=9389;Protocol='ADWS';ObjectName=$Name;SamAccountName=$SamAccountName
                ObjectPath=$ComputersContainer;CreateSucceeded=$true;ReadBackSucceeded=($null-ne$ReadBack)
                ObjectEnabled=[bool]$ReadBack.Enabled;SpnCount=@($ReadBack.ServicePrincipalName).Count
                DeleteSucceeded=$true;CleanupVerified=$true
                Result='CreateReadDeleteReproduced';Disposition='PrerequisiteReproduced'
                Interpretation='The current identity created, read, and deleted one disabled computer object. This confirms machine-account creation authorization only, not an exploitable RBCD or relay chain.'
                StartedUtc=$Started.ToUniversalTime().ToString('o');CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')
                AttemptedServers=@($Attempts.ToArray());Error=$null
            }
        } catch {
            $Message = $_.Exception.Message
            $Attempts.Add([pscustomobject]@{Target=$CandidateServer;Error=$Message})
            Add-OperationalError 'MachineAccountCreateDelete' $CandidateServer 'ADWS' 9389 $Message
            Write-Step 'WARN' "$CandidateServer machine-account validation failed; continuing." DarkYellow

            if ($null -ne $script:CreatedMachineDn) {
                try {
                    Write-Step 'CLEANUP' "$CandidateServer emergency cleanup: $($script:CreatedMachineDn)" Red
                    $CleanupParameters = @{Identity=$script:CreatedMachineDn;Server=$CandidateServer;Confirm=$false;ErrorAction='Stop'}
                    if ($null -ne $Credential) { $CleanupParameters.Credential = $Credential }
                    Remove-ADComputer @CleanupParameters
                    $script:CleanupVerified = $true
                    $script:CreatedMachineDn = $null
                } catch {
                    $script:CleanupVerified = $false
                    Add-OperationalError 'EmergencyCleanup' $CandidateServer 'ADWS' 9389 $_.Exception.Message
                    break
                }
            }
        }
    }

    return [pscustomobject][ordered]@{
        Validator='MachineAccountCreationAuthorizationValidation';Target=($CandidateServers -join ',')
        Port=9389;Protocol='ADWS';ObjectName=$Name;SamAccountName=$SamAccountName
        ObjectPath=$ComputersContainer;CreateSucceeded=$false;ReadBackSucceeded=$false
        ObjectEnabled=$false;SpnCount=0;DeleteSucceeded=($null-eq$script:CreatedMachineDn)
        CleanupVerified=$script:CleanupVerified;Result='CreateReadDeleteNotReproduced'
        Disposition=if($script:CleanupVerified){'BlockedOrInconclusive'}else{'CleanupFailure'}
        Interpretation='The controlled machine-account create/read/delete cycle did not complete. Individual errors are preserved.'
        StartedUtc=$null;CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')
        AttemptedServers=@($Attempts.ToArray());Error=($Attempts.Error -join ' | ')
    }
}
function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices.Protocols

    if (-not (Test-Path -LiteralPath $CandidateAnalysisDirectory -PathType Container)) {
        throw "CandidateAnalysisDirectoryMissing: $CandidateAnalysisDirectory"
    }
    $SelectedPath = Join-Path $CandidateAnalysisDirectory 'selected-validators.json'
    $AnalysisSummaryPath = Join-Path $CandidateAnalysisDirectory 'relay-candidate-analysis-summary.json'
    $SelectedValidators = Read-JsonArray $SelectedPath 'Selected validators'
    $AnalysisSummary = Read-JsonDocument $AnalysisSummaryPath 'Candidate analysis summary'
    if ($SelectedValidators.Count -eq 0) { throw 'No behavioral validator was selected by candidate analysis.' }

    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $OutputDirectory = Join-Path $CandidateAnalysisDirectory 'BehavioralValidation-v0.1.1'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $Discovery = @{ErrorAction='Stop'}
    if ($null -ne $Credential) { $Discovery.Credential = $Credential }
    $Domain = Get-ADDomain @Discovery
    $AllDcs = @(Get-ADDomainController -Filter * @Discovery | Sort-Object HostName)
    $WritableTargets = @($AllDcs | Where-Object { -not [bool]$_.IsReadOnly } | ForEach-Object { Get-FirstTextValue $_.HostName } | Where-Object { $null-ne$_ } | Sort-Object -Unique)
    if ($null -ne $Server -and $Server.Trim().Length -gt 0) {
        $WritableTargets = @($Server.Trim())
    }

    $SigningSelection = @($SelectedValidators | Where-Object { [string]$_.Validator -eq 'LDAPSigningBehavioralValidation' })
    $CbtSelection = @($SelectedValidators | Where-Object { [string]$_.Validator -eq 'LDAPChannelBindingBehavioralValidation' })
    $MaqSelection = @($SelectedValidators | Where-Object { [string]$_.Validator -eq 'MachineAccountCreationAuthorizationValidation' })
    $SigningTargets = @($SigningSelection.Targets | ForEach-Object { [string]$_ } | Where-Object { $null-ne$_ -and $_.Length-gt0 } | Sort-Object -Unique)
    $CbtTargets = @($CbtSelection.Targets | ForEach-Object { [string]$_ } | Where-Object { $null-ne$_ -and $_.Length-gt0 } | Sort-Object -Unique)

    Write-Step 'NETWORK' 'Selected behavioral network and directory operations follow.' Magenta
    if ($SigningTargets.Count -gt 0) {
        foreach ($Target in $SigningTargets) {
            Write-Step 'TARGET' "$Target TCP/389 LDAP; Negotiate bind with Signing=False and Sealing=False; RootDSE read" DarkCyan
        }
    }
    if ($CbtTargets.Count -gt 0) {
        foreach ($Target in $CbtTargets) {
            Write-Step 'CAPABILITY' "$Target TCP/636 LDAPS; no network probe because current client cannot deliberately omit or corrupt CBT" DarkCyan
        }
    }
    if ($MaqSelection.Count -gt 0 -and -not $SkipMachineAccountCreateDelete) {
        Write-Step 'WRITE PLAN' "Targets=$($WritableTargets -join ', '); Protocol=ADWS/LDAP; Ports=9389 and directory service; ObjectPath=$($Domain.ComputersContainer)" Magenta
        Write-Step 'WRITE PLAN' 'Create exactly one disabled computer with no SPNs, read it, delete it, verify absence. Emergency cleanup on failure.' Magenta
    }
    $ChangeMessage = 'Directory changes=None.'
    if ($MaqSelection.Count -gt 0 -and -not $SkipMachineAccountCreateDelete) {
        $ChangeMessage = 'One temporary disabled computer create/delete cycle planned.'
    }
    Write-Step 'CHANGES' $ChangeMessage DarkCyan

    $SigningRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Target in $SigningTargets) {
        Write-Step 'VALIDATE' "$Target TCP/389 LDAP unsigned and unsealed Negotiate session" Yellow
        $Row = Test-UnsignedNegotiateLdap $Target $ProtocolTimeoutSeconds $Credential
        $SigningRows.Add($Row)
        if (-not [bool]$Row.BindSucceeded) { Add-OperationalError 'LDAPSigningBehavioralValidation' $Target 'LDAP' 389 $Row.Error }
    }

    $CbtRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Target in $CbtTargets) {
        Write-Step 'INCONCLUSIVE' "$Target CBT behavior not tested because deliberate CBT omission/corruption is unsupported by this client" DarkYellow
        $CbtRows.Add((Get-LdapsCbtCapabilityResult $Target))
    }

    $MachineRow = $null
    if ($MaqSelection.Count -gt 0) {
        if ($SkipMachineAccountCreateDelete) {
            $MachineRow = [pscustomobject][ordered]@{
                Validator='MachineAccountCreationAuthorizationValidation';Target=($WritableTargets -join ',')
                Result='SkippedByOperator';Disposition='Inconclusive';CleanupVerified=$true
                Interpretation='Machine-account create/delete validation was explicitly skipped.'
            }
        } else {
            $MachineRow = Invoke-MachineAccountCreateDelete $WritableTargets $Domain $Credential
        }
    }

    $SigningPath = Join-Path $OutputDirectory 'ldap-signing-behavioral-validation.json'
    $SigningCsv = Join-Path $OutputDirectory 'ldap-signing-behavioral-validation.csv'
    $CbtPath = Join-Path $OutputDirectory 'ldap-channel-binding-capability.json'
    $CbtCsv = Join-Path $OutputDirectory 'ldap-channel-binding-capability.csv'
    $MachinePath = Join-Path $OutputDirectory 'machine-account-authorization-validation.json'
    $ErrorsPath = Join-Path $OutputDirectory 'operational-errors.json'
    Write-JsonArray $SigningRows.ToArray() $SigningPath
    $SigningRows | Export-Csv -LiteralPath $SigningCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $CbtRows.ToArray() $CbtPath
    $CbtRows | Export-Csv -LiteralPath $CbtCsv -NoTypeInformation -Encoding UTF8
    if ($null -ne $MachineRow) { Write-JsonDocument $MachineRow $MachinePath } else { Write-JsonDocument ([pscustomobject]@{Status='NotSelected'}) $MachinePath }
    Write-JsonArray $OperationalErrors.ToArray() $ErrorsPath

    $UnsignedAccepted = @($SigningRows | Where-Object { [bool]$_.BindSucceeded }).Count
    $UnsignedRejected = @($SigningRows | Where-Object { -not [bool]$_.BindSucceeded }).Count
    $MachineReproduced = ($null-ne$MachineRow -and [string]$MachineRow.Result -eq 'CreateReadDeleteReproduced')
    $Summary = [pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status=if(-not$CleanupVerified){'CleanupFailure'}elseif($OperationalErrors.Count-gt0){'CompletedWithErrors'}else{'Completed'}
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        CandidateAnalysisDirectory=$CandidateAnalysisDirectory;Domain=[string]$AnalysisSummary.Domain
        Counts=[pscustomobject]@{SelectedValidators=$SelectedValidators.Count;UnsignedLdapAccepted=$UnsignedAccepted;UnsignedLdapRejectedOrUnavailable=$UnsignedRejected;CbtTargetsInconclusive=$CbtRows.Count;MachineAccountCreateDeleteReproduced=[bool]$MachineReproduced;OperationalErrors=$OperationalErrors.Count}
        Dispositions=[pscustomobject]@{
            LdapSigning=if($UnsignedAccepted-gt0){'PrerequisiteReproduced'}elseif($UnsignedRejected-gt0){'BlockedOrInconclusive'}else{'NotSelected'}
            LdapChannelBinding=if($CbtRows.Count-gt0){'Inconclusive'}else{'NotSelected'}
            MachineAccountCreation=if($MachineReproduced){'PrerequisiteReproduced'}elseif($null-ne$MachineRow){[string]$MachineRow.Disposition}else{'NotSelected'}
            VulnerabilityFinding='NotEstablished'
        }
        InterpretationBoundary=@(
            'Unsigned LDAP acceptance is a relay prerequisite, not proof of successful relay.',
            'CBT remains inconclusive because the current client cannot deliberately omit or corrupt CBT.',
            'Machine-account create/delete success proves authorization only, not an exploitable RBCD chain.',
            'A vulnerability requires successful relay and meaningful directory impact using real tooling.'
        )
        Safety=[pscustomobject]@{CleanupVerified=$CleanupVerified;RemainingTestObjectDn=$CreatedMachineDn;RelayAttempts='None';Coercion='None';OllamaActivity='None'}
    }
    $SummaryPath = Join-Path $OutputDirectory 'relay-behavioral-validation-summary.json'
    Write-JsonDocument $Summary $SummaryPath

    $ReportPath = Join-Path $OutputDirectory 'MSADPT-Relay-Behavioral-Validation.html'
    $SigningHtml = ($SigningRows | ForEach-Object { '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Convert-HtmlText $_.Target),(Convert-HtmlText $_.Result),(Convert-HtmlText $_.Disposition),(Convert-HtmlText $_.Interpretation) }) -join "`n"
    $CbtHtml = ($CbtRows | ForEach-Object { '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Convert-HtmlText $_.Target),(Convert-HtmlText $_.Disposition),(Convert-HtmlText $_.Interpretation) }) -join "`n"
    $MachineHtml = if($null-ne$MachineRow){'<p><b>Result:</b> {0}<br><b>Disposition:</b> {1}<br><b>Cleanup verified:</b> {2}<br>{3}</p>' -f (Convert-HtmlText $MachineRow.Result),(Convert-HtmlText $MachineRow.Disposition),(Convert-HtmlText $MachineRow.CleanupVerified),(Convert-HtmlText $MachineRow.Interpretation)}else{'<p>Not selected.</p>'}
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT Relay Behavioral Validation</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.warn{color:#8a4b08}</style></head><body>
<h1>MSADPT Relay Behavioral Validation</h1><div class="card"><b>Status:</b> $(Convert-HtmlText $Summary.Status)<br><b>Domain:</b> $(Convert-HtmlText $Summary.Domain)<br><b>Vulnerability finding:</b> Not established<br><b>Cleanup verified:</b> $(Convert-HtmlText $CleanupVerified)<br><b>Relay attempts:</b> None</div>
<h2>LDAP Signing Behavior</h2><table><tr><th>Target</th><th>Result</th><th>Disposition</th><th>Interpretation</th></tr>$SigningHtml</table>
<h2>LDAP Channel Binding</h2><table><tr><th>Target</th><th>Disposition</th><th>Interpretation</th></tr>$CbtHtml</table>
<h2>Machine Account Authorization</h2>$MachineHtml
<h2>Evidence</h2><ul><li><a href="ldap-signing-behavioral-validation.csv">LDAP signing results</a></li><li><a href="ldap-channel-binding-capability.csv">CBT capability results</a></li><li><a href="machine-account-authorization-validation.json">Machine account validation</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="relay-behavioral-validation-summary.json">Structured summary</a></li><li><a href="../MSADPT-Relay-Candidate-Analysis.html">Candidate analysis report</a></li></ul>
<p class="warn">Prerequisite reproduction is not vulnerability reproduction. No authentication coercion or credential relay was attempted in this stage.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object { $_.Name -ne 'evidence-manifest.json' } | Sort-Object Name)
    $ManifestRows=@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows}) $ManifestPath

    if (-not $CleanupVerified) { throw "Cleanup verification failed. Remaining object: $CreatedMachineDn" }

    Write-Step 'DONE' "Behavioral validation complete: unsigned LDAP accepted=$UnsignedAccepted, CBT inconclusive=$($CbtRows.Count), machine create/delete=$MachineReproduced, errors=$($OperationalErrors.Count)." Green
    [pscustomobject][ordered]@{
        Status=if($OperationalErrors.Count-gt0){'PassedWithErrors'}else{'Passed'}
        PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Domain=$Summary.Domain
        SelectedValidatorCount=$SelectedValidators.Count;UnsignedLdapAcceptedCount=$UnsignedAccepted
        UnsignedLdapRejectedOrUnavailableCount=$UnsignedRejected;CbtInconclusiveTargetCount=$CbtRows.Count
        MachineAccountCreateDeleteReproduced=$MachineReproduced;CleanupVerified=$CleanupVerified
        OperationalErrorCount=$OperationalErrors.Count;VulnerabilityFinding='NotEstablished'
        OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        RelayAttempts='None';Coercion='None';OllamaActivity='None'
    }
}
catch {
    if ($null -ne $CreatedMachineDn -and -not $CleanupVerified) {
        Write-Step 'CRITICAL' "Cleanup not verified for $CreatedMachineDn" Red
    }
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
