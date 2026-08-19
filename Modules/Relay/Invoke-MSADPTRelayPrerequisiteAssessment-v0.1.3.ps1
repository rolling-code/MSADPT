<#
.SYNOPSIS
Runs a resilient LDAP, LDAPS, Global Catalog, SMB, RPC, WinRM, and relay-prerequisite baseline.
.NOTES
Version: 0.1.3
Package identity: MSADPT-RELAY-PREREQUISITE-ASSESSMENT
#>
[CmdletBinding()]
param(
    [string]$Server,
    [PSCredential]$Credential,
    [string]$OutputDirectory,
    [ValidateRange(1,20)][int]$TcpTimeoutSeconds = 3,
    [ValidateRange(3,30)][int]$ProtocolTimeoutSeconds = 8,
    [switch]$SkipNmap,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-RELAY-PREREQUISITE-ASSESSMENT'
$PackageVersion = '0.1.3'
$Ports = @(135,389,445,636,3268,3269,5985,5986)
$OperationalErrors = New-Object 'System.Collections.Generic.List[object]'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-10}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}
function Get-FirstTextValue {
    param([object]$Value)
    foreach ($Item in @($Value)) {
        $Text = [string]$Item
        if ($null -ne $Text -and $Text.Trim().Length -gt 0) { return $Text.Trim() }
    }
    return $null
}
function Get-ProtocolName {
    param([int]$Port)
    switch ($Port) {
        135 {'MS-RPC'};389 {'LDAP'};445 {'SMB'};636 {'LDAPS'}
        3268 {'Global Catalog LDAP'};3269 {'Global Catalog LDAPS'}
        5985 {'WinRM HTTP'};5986 {'WinRM HTTPS'};default {'TCP'}
    }
}
function Add-OperationalError {
    param([string]$Stage,[string]$Target,[string]$Protocol,[object]$Port,[string]$ErrorText)
    $OperationalErrors.Add([pscustomobject][ordered]@{
        Stage=$Stage;Target=$Target;Protocol=$Protocol;Port=$Port;Status='Failed';Error=$ErrorText
    })
}
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=12)
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
    param([object]$Document,[string]$Path,[int]$Depth=12)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Test-TcpPort {
    param([string]$Target,[int]$Port,[int]$TimeoutSeconds)
    $Client = New-Object Net.Sockets.TcpClient
    $Started = Get-Date
    try {
        $Task = $Client.ConnectAsync($Target,$Port)
        if (-not $Task.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            return [pscustomobject]@{Target=$Target;Port=$Port;Protocol=(Get-ProtocolName $Port);Status='TimedOut';Connected=$false;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$null}
        }
        return [pscustomobject]@{Target=$Target;Port=$Port;Protocol=(Get-ProtocolName $Port);Status='Completed';Connected=$Client.Connected;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$null}
    } catch {
        return [pscustomobject]@{Target=$Target;Port=$Port;Protocol=(Get-ProtocolName $Port);Status='Failed';Connected=$false;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$_.Exception.Message}
    } finally { $Client.Dispose() }
}
function Test-LdapSession {
    param([string]$Target,[int]$Port,[bool]$UseSsl,[int]$TimeoutSeconds,[PSCredential]$Credential)
    $Started = Get-Date
    $Connection = $null
    try {
        $Identifier = New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier($Target,$Port,$false,$false)
        $Connection = New-Object DirectoryServices.Protocols.LdapConnection($Identifier)
        $Connection.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $Connection.SessionOptions.ProtocolVersion = 3
        $Connection.SessionOptions.SecureSocketLayer = $UseSsl
        $Connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
        if ($null -ne $Credential) { $Connection.Credential = $Credential.GetNetworkCredential() }
        $Connection.Bind()
        $Request = New-Object DirectoryServices.Protocols.SearchRequest('', '(objectClass=*)', [DirectoryServices.Protocols.SearchScope]::Base, @('defaultNamingContext'))
        $Response = $Connection.SendRequest($Request)
        $NamingContext = $null
        if ($Response.Entries.Count -gt 0 -and $Response.Entries[0].Attributes['defaultNamingContext']) {
            $NamingContext = [string]$Response.Entries[0].Attributes['defaultNamingContext'][0]
        }
        return [pscustomobject]@{Target=$Target;Port=$Port;Protocol=(Get-ProtocolName $Port);AuthType='Negotiate';Status='Bound';RootDseRead=$true;DefaultNamingContext=$NamingContext;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$null}
    } catch {
        return [pscustomobject]@{Target=$Target;Port=$Port;Protocol=(Get-ProtocolName $Port);AuthType='Negotiate';Status='Failed';RootDseRead=$false;DefaultNamingContext=$null;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$_.Exception.Message}
    } finally { if ($null -ne $Connection) { $Connection.Dispose() } }
}
function Get-TlsCertificateObservation {
    param([string]$Target,[int]$Port,[int]$TimeoutSeconds)
    $Client = New-Object Net.Sockets.TcpClient
    $Stream = $null
    $Started = Get-Date
    try {
        $Task = $Client.ConnectAsync($Target,$Port)
        if (-not $Task.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) { throw 'TCP connection timed out.' }
        $Callback = { param($Sender,$Certificate,$Chain,$Errors) return $true }
        $Stream = New-Object Net.Security.SslStream($Client.GetStream(),$false,$Callback)
        $Stream.AuthenticateAsClient($Target)
        $Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($Stream.RemoteCertificate)
        $DnsName = $Cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName,$false)
        return [pscustomobject]@{Target=$Target;Port=$Port;Protocol=(Get-ProtocolName $Port);Status='Negotiated';SslProtocol=[string]$Stream.SslProtocol;Subject=$Cert.Subject;Issuer=$Cert.Issuer;Thumbprint=$Cert.Thumbprint;NotBeforeUtc=$Cert.NotBefore.ToUniversalTime().ToString('o');NotAfterUtc=$Cert.NotAfter.ToUniversalTime().ToString('o');DnsNameMatches=($DnsName -ieq $Target);ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$null}
    } catch {
        return [pscustomobject]@{Target=$Target;Port=$Port;Protocol=(Get-ProtocolName $Port);Status='Failed';SslProtocol=$null;Subject=$null;Issuer=$null;Thumbprint=$null;NotBeforeUtc=$null;NotAfterUtc=$null;DnsNameMatches=$false;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$_.Exception.Message}
    } finally {
        if ($null -ne $Stream) { $Stream.Dispose() }
        $Client.Dispose()
    }
}
function Convert-HtmlText { param([object]$Value) return [Net.WebUtility]::HtmlEncode([string]$Value) }

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices.Protocols

    $Discovery = @{ErrorAction='Stop'}
    if ($null -ne $Credential) { $Discovery.Credential = $Credential }
    $Domain = Get-ADDomain @Discovery
    $Forest = Get-ADForest @Discovery

    if ($null -ne $Server -and $Server.Trim().Length -gt 0) {
        $DomainControllers = @(Get-ADDomainController -Identity $Server.Trim() -Server $Server.Trim() @Discovery)
    } else {
        $DomainControllers = @(Get-ADDomainController -Filter * @Discovery | Sort-Object HostName)
    }
    $Targets = @($DomainControllers | ForEach-Object { Get-FirstTextValue $_.HostName } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
    if ($Targets.Count -eq 0) { throw 'No domain-controller targets were discovered.' }

    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $SafeDomain = [string]$Domain.DNSRoot -replace '[^A-Za-z0-9.-]','_'
        $OutputDirectory = Join-Path (Get-Location) ('MSADPT-Relay-Prerequisites-{0}-{1}' -f $SafeDomain,(Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) { throw "OutputDirectoryNotEmpty: $OutputDirectory" }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step 'NETWORK' 'Planned live network operations follow.' Magenta
    foreach ($Target in $Targets) {
        Write-Step 'TARGET' $Target DarkCyan
        Write-Step 'PORTS' (($Ports | ForEach-Object { "TCP/$_ ($(Get-ProtocolName $_))" }) -join ', ') DarkCyan
    }
    Write-Step 'OPERATIONS' 'TCP reachability; LDAP/LDAPS Negotiate bind; RootDSE; TLS certificates; Nmap SMB signing.' DarkCyan
    Write-Step 'CHANGES' 'Directory=None; credentials=None; coercion=None; relay=None.' DarkCyan

    $DcRows = @(
        foreach ($Dc in $DomainControllers) {
            [pscustomobject]@{HostName=(Get-FirstTextValue $Dc.HostName);Site=[string]$Dc.Site;IPv4Address=(Get-FirstTextValue $Dc.IPv4Address);OperatingSystem=[string]$Dc.OperatingSystem;OperatingSystemVersion=[string]$Dc.OperatingSystemVersion;IsGlobalCatalog=[bool]$Dc.IsGlobalCatalog;IsReadOnly=[bool]$Dc.IsReadOnly;Enabled=[bool]$Dc.Enabled}
        }
    )
    $TcpRows = New-Object 'System.Collections.Generic.List[object]'
    $LdapRows = New-Object 'System.Collections.Generic.List[object]'
    $TlsRows = New-Object 'System.Collections.Generic.List[object]'

    foreach ($Target in $Targets) {
        foreach ($Port in $Ports) {
            Write-Step 'PROBE' "$Target TCP/$Port $(Get-ProtocolName $Port)" Yellow
            $Row = Test-TcpPort $Target $Port $TcpTimeoutSeconds
            $TcpRows.Add($Row)
            if ($Row.Status -eq 'Failed') { Add-OperationalError 'TCP' $Target $Row.Protocol $Port $Row.Error }
        }
        foreach ($Definition in @(@{Port=389;Ssl=$false},@{Port=636;Ssl=$true})) {
            Write-Step 'PROBE' "$Target TCP/$($Definition.Port) $(Get-ProtocolName $Definition.Port) bind" Yellow
            $Row = Test-LdapSession $Target $Definition.Port $Definition.Ssl $ProtocolTimeoutSeconds $Credential
            $LdapRows.Add($Row)
            if ($Row.Status -eq 'Failed') { Add-OperationalError 'LDAPSession' $Target $Row.Protocol $Definition.Port $Row.Error }
        }
        $IsGc = @($DcRows | Where-Object { $_.HostName -eq $Target -and $_.IsGlobalCatalog }).Count -gt 0
        if ($IsGc) {
            foreach ($Definition in @(@{Port=3268;Ssl=$false},@{Port=3269;Ssl=$true})) {
                Write-Step 'PROBE' "$Target TCP/$($Definition.Port) $(Get-ProtocolName $Definition.Port) bind" Yellow
                $Row = Test-LdapSession $Target $Definition.Port $Definition.Ssl $ProtocolTimeoutSeconds $Credential
                $LdapRows.Add($Row)
                if ($Row.Status -eq 'Failed') { Add-OperationalError 'LDAPSession' $Target $Row.Protocol $Definition.Port $Row.Error }
            }
        }
        foreach ($Port in @(636,3269)) {
            $Open = @($TcpRows | Where-Object { $_.Target -eq $Target -and $_.Port -eq $Port -and $_.Connected }).Count -gt 0
            if ($Open) {
                Write-Step 'TLS' "$Target TCP/$Port certificate negotiation" Yellow
                $Row = Get-TlsCertificateObservation $Target $Port $ProtocolTimeoutSeconds
                $TlsRows.Add($Row)
                if ($Row.Status -eq 'Failed') { Add-OperationalError 'TLS' $Target $Row.Protocol $Port $Row.Error }
            }
        }
    }

    $MachineAccountQuota = $null
    $MachineAccountQuotaServer = $null
    foreach ($CandidateServer in $Targets) {
        try {
            Write-Step 'QUERY' "$CandidateServer ADWS MachineAccountQuota read" Yellow
            $DomainAd = Get-ADObject -Identity $Domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -Server $CandidateServer @Discovery
            $MachineAccountQuota = [int]$DomainAd.'ms-DS-MachineAccountQuota'
            $MachineAccountQuotaServer = $CandidateServer
            Write-Step 'OK' "MachineAccountQuota collected from ${CandidateServer}: $MachineAccountQuota" Green
            break
        } catch {
            Add-OperationalError 'MachineAccountQuota' $CandidateServer 'ADWS' 9389 $_.Exception.Message
            Write-Step 'WARN' "$CandidateServer MachineAccountQuota unavailable; continuing." DarkYellow
        }
    }

    $NmapRows = New-Object 'System.Collections.Generic.List[object]'
    $NmapPath = $null
    if (-not $SkipNmap) {
        $Command = Get-Command nmap.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $Command) { $Command = Get-Command nmap -ErrorAction SilentlyContinue | Select-Object -First 1 }
        if ($null -ne $Command) { $NmapPath = $Command.Source }
    }
    if ($null -ne $NmapPath) {
        foreach ($Target in $Targets) {
            $SafeTarget = $Target -replace '[^A-Za-z0-9_.-]','_'
            $Prefix = Join-Path $OutputDirectory "nmap-smb-$SafeTarget"
            Write-Step 'NMAP' "$Target TCP/445 SMB signing validation" Magenta
            try {
                $Lines = @(& $NmapPath -Pn -sT -p 445 --script 'smb2-security-mode,smb2-time' -oA $Prefix $Target 2>&1 | ForEach-Object { [string]$_ })
                $ExitCode = $LASTEXITCODE
                $SigningEvidence = ($Lines | Where-Object { $_ -match '(?i)message signing|signing' } | ForEach-Object { $_.Trim() }) -join ' | '
                $NmapRows.Add([pscustomobject]@{Target=$Target;Status=if($ExitCode -eq 0){'Completed'}else{'Failed'};ExitCode=$ExitCode;SigningEvidence=$SigningEvidence;OutputPrefix=$Prefix;RawConsole=($Lines -join "`n")})
                if ($ExitCode -ne 0) { Add-OperationalError 'NmapSMB' $Target 'SMB' 445 ($Lines -join ' ') }
            } catch {
                Add-OperationalError 'NmapSMB' $Target 'SMB' 445 $_.Exception.Message
                $NmapRows.Add([pscustomobject]@{Target=$Target;Status='Failed';ExitCode=$null;SigningEvidence=$null;OutputPrefix=$Prefix;RawConsole=$_.Exception.Message})
            }
        }
    }

    $TcpPath=Join-Path $OutputDirectory 'tcp-reachability.json';$TcpCsv=Join-Path $OutputDirectory 'tcp-reachability.csv';Write-JsonArray $TcpRows.ToArray() $TcpPath;$TcpRows|Export-Csv $TcpCsv -NoTypeInformation -Encoding UTF8
    $LdapPath=Join-Path $OutputDirectory 'ldap-session-observations.json';$LdapCsv=Join-Path $OutputDirectory 'ldap-session-observations.csv';Write-JsonArray $LdapRows.ToArray() $LdapPath;$LdapRows|Export-Csv $LdapCsv -NoTypeInformation -Encoding UTF8
    $TlsPath=Join-Path $OutputDirectory 'tls-certificate-observations.json';$TlsCsv=Join-Path $OutputDirectory 'tls-certificate-observations.csv';Write-JsonArray $TlsRows.ToArray() $TlsPath;$TlsRows|Export-Csv $TlsCsv -NoTypeInformation -Encoding UTF8
    $DcPath=Join-Path $OutputDirectory 'domain-controllers.json';$DcCsv=Join-Path $OutputDirectory 'domain-controllers.csv';Write-JsonArray $DcRows $DcPath;$DcRows|Export-Csv $DcCsv -NoTypeInformation -Encoding UTF8
    $NmapPathJson=Join-Path $OutputDirectory 'smb-signing-nmap.json';Write-JsonArray $NmapRows.ToArray() $NmapPathJson
    $ErrorsPath=Join-Path $OutputDirectory 'operational-errors.json';Write-JsonArray $OperationalErrors.ToArray() $ErrorsPath

    $Facts = @(
        [pscustomobject]@{Fact='MachineAccountQuota';State=if($null-eq$MachineAccountQuota){'Inconclusive'}elseif($MachineAccountQuota-gt0){'Observed'}else{'Not observed'};Value=$MachineAccountQuota;Interpretation='Nonzero quota is a relay/RBCD prerequisite lead, not a vulnerability.'}
        [pscustomobject]@{Fact='Authenticated LDAP bind';State=if(@($LdapRows|Where-Object{$_.Port-eq389-and$_.Status-eq'Bound'}).Count-eq$Targets.Count){'Observed'}else{'Partial or failed'};Value=@($LdapRows|Where-Object{$_.Port-eq389-and$_.Status-eq'Bound'}).Count;Interpretation='Negotiate bind success does not prove unsigned simple binds are accepted.'}
        [pscustomobject]@{Fact='LDAPS available';State=if(@($TlsRows|Where-Object{$_.Port-eq636-and$_.Status-eq'Negotiated'}).Count-gt0){'Observed'}else{'Not detected'};Value=@($TlsRows|Where-Object{$_.Port-eq636-and$_.Status-eq'Negotiated'}).Count;Interpretation='Channel binding remains separate behavioral validation.'}
        [pscustomobject]@{Fact='SMB signing evidence';State=if($NmapRows.Count-gt0){'Collected'}else{'Inconclusive'};Value=$NmapRows.Count;Interpretation='Raw Nmap output requires deterministic parsing.'}
    )
    $FactsPath=Join-Path $OutputDirectory 'relay-prerequisite-facts.json';Write-JsonArray $Facts $FactsPath
    $Summary=[pscustomobject][ordered]@{SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Status=if($OperationalErrors.Count-gt0){'CompletedWithErrors'}else{'Completed'};GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');Domain=[pscustomobject]@{DnsRoot=[string]$Domain.DNSRoot;Forest=[string]$Forest.Name;DomainMode=[string]$Domain.DomainMode;ForestMode=[string]$Forest.ForestMode};NetworkPlan=[pscustomobject]@{Targets=$Targets;Ports=$Ports;Protocols=@($Ports|ForEach-Object{Get-ProtocolName $_})};Counts=[pscustomobject]@{DomainControllers=$Targets.Count;TcpChecks=$TcpRows.Count;OpenPorts=@($TcpRows|Where-Object{$_.Connected}).Count;LdapSessions=$LdapRows.Count;SuccessfulLdapSessions=@($LdapRows|Where-Object{$_.Status-eq'Bound'}).Count;TlsCertificates=$TlsRows.Count;NmapSmbTargets=$NmapRows.Count};MachineAccountQuota=$MachineAccountQuota;MachineAccountQuotaServer=$MachineAccountQuotaServer;OperationalErrorCount=$OperationalErrors.Count;OperationalErrorsPath=$ErrorsPath;Facts=$Facts;Safety=[pscustomobject]@{DirectoryChanges='None';CredentialChanges='None';AuthenticationCoercion='None';RelayAttempts='None';OllamaActivity='None'}}
    $SummaryPath=Join-Path $OutputDirectory 'relay-prerequisite-summary.json';Write-JsonDocument $Summary $SummaryPath

    $ReportPath=Join-Path $OutputDirectory 'MSADPT-Relay-Prerequisite-Report.html'
    $RowsHtml=($Facts|ForEach-Object{"<tr><td>$(Convert-HtmlText $_.Fact)</td><td>$(Convert-HtmlText $_.State)</td><td>$(Convert-HtmlText $_.Value)</td><td>$(Convert-HtmlText $_.Interpretation)</td></tr>"})-join"`n"
    $TargetHtml=($Targets|ForEach-Object{"<li>$(Convert-HtmlText $_)</li>"})-join"`n"
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT Relay Prerequisite Assessment</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left}th{background:#eaf2f8}</style></head><body><h1>MSADPT Relay-Prerequisite Assessment</h1><div class="card"><b>Status:</b> $(Convert-HtmlText $Summary.Status)<br><b>Domain:</b> $(Convert-HtmlText $Domain.DNSRoot)<br><b>Operational errors:</b> $($OperationalErrors.Count)<br><b>Relay attempts:</b> None</div><h2>Network Plan</h2><ul>$TargetHtml</ul><p>Ports: $(Convert-HtmlText ($Ports-join', '))</p><h2>Deterministic Facts</h2><table><tr><th>Fact</th><th>State</th><th>Value</th><th>Interpretation</th></tr>$RowsHtml</table><h2>Evidence</h2><ul><li><a href="domain-controllers.csv">Domain controllers</a></li><li><a href="tcp-reachability.csv">TCP reachability</a></li><li><a href="ldap-session-observations.csv">LDAP sessions</a></li><li><a href="tls-certificate-observations.csv">TLS certificates</a></li><li><a href="smb-signing-nmap.json">SMB signing</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="relay-prerequisite-summary.json">Structured summary</a></li></ul><p>Prerequisites are not vulnerabilities. Confirmation requires technique-appropriate reproduction and demonstrated impact.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name-ne'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Assessment complete: targets=$($Targets.Count), errors=$($OperationalErrors.Count), report=$ReportPath" Green
    [pscustomobject][ordered]@{Status=if($OperationalErrors.Count-gt0){'PassedWithErrors'}else{'Passed'};PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Domain=[string]$Domain.DNSRoot;TargetCount=$Targets.Count;Targets=$Targets;TcpCheckCount=$TcpRows.Count;OpenPortCount=$Summary.Counts.OpenPorts;SuccessfulLdapSessionCount=$Summary.Counts.SuccessfulLdapSessions;TlsCertificateCount=$TlsRows.Count;MachineAccountQuota=$MachineAccountQuota;MachineAccountQuotaServer=$MachineAccountQuotaServer;OperationalErrorCount=$OperationalErrors.Count;NmapSmbTargetCount=$NmapRows.Count;OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath;DirectoryChanges='None';RelayAttempts='None';OllamaActivity='None'}
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
