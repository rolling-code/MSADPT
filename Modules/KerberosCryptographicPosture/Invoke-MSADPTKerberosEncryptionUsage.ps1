<#
.SYNOPSIS
Collects and analyzes Kerberos encryption usage for MSADPT from a domain-joined Windows host.
.DESCRIPTION
MSADPT Kerberos Encryption Usage v0.1.2 prioritizes execution from a normal domain-joined workstation.
It discovers writable domain controllers, attempts bounded read-only Security-log queries for events 4768 and 4769,
and can also analyze local Security logs or imported EVTX files. Each source is handled independently so inaccessible
DCs do not terminate the assessment.

The module distinguishes observed RC4 ticket use, observed RC4 session-key use, DES use, AES use, event-schema
compatibility, and collection coverage. It does not request Kerberos tickets, change audit policy, enable remoting,
modify a firewall, install software, alter Active Directory, or access password material.
.NOTES
Version: 0.1.2
PowerShell: Windows PowerShell 5.1 and PowerShell 7 on Windows
#>
[CmdletBinding(DefaultParameterSetName='DomainControllers')]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$EngagementDirectory,

    [Parameter(ParameterSetName='DomainControllers')]
    [ValidateSet('Auto','DomainControllers','Local')]
    [string]$CollectionMode='Auto',

    [Parameter(ParameterSetName='Evtx',Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$EvtxPath,

    [Parameter(ParameterSetName='DomainControllers')]
    [string[]]$DomainController,

    [Parameter(ParameterSetName='DomainControllers')]
    [PSCredential]$Credential,

    [ValidateRange(1,365)]
    [int]$LookbackDays=30,

    [ValidateRange(100,1000000)]
    [int]$MaximumEventsPerSource=50000,

    [switch]$IncludeAllEvents,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ModuleVersion='0.1.2'
function Show([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray){$t='[{0,-12}] {1}'-f$State,$Message;if($NoColor){Write-Host $t}else{Write-Host $t -ForegroundColor $Color}}
function Write-Json([string]$Path,[object]$Value){
    $json = ConvertTo-Json -InputObject $Value -Depth 14 -WarningAction Stop
    if ([string]::IsNullOrWhiteSpace($json)) { $json = '[]' }
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Write-EventCsv([string]$Path,[object[]]$Rows){
    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        $headers = @('SchemaVersion','Source','MachineName','RecordId','TimeCreatedUtc','EventId','RequestType','Account','Target','ClientAddress','TicketEncryption','TicketEncryptionValue','SessionKeyEncryption','SessionKeyEncryptionValue','ObservedRC4Ticket','ObservedRC4SessionKey','ObservedDES','ObservedAES','AccountSupportedEncryptionTypes','ServiceSupportedEncryptionTypes','AccountAvailableKeys','ServiceAvailableKeys','DCAvailableKeys','NewEncryptionMetadataPresent')
        Set-Content -LiteralPath $Path -Value (($headers | ForEach-Object { '"{0}"' -f $_ }) -join ',') -Encoding UTF8
    }
}
function Get-EventDataMap([System.Diagnostics.Eventing.Reader.EventRecord]$Event){
    $map=@{};$xml=[xml]$Event.ToXml()
    foreach($d in @($xml.Event.EventData.Data)){if($null -ne $d.Name){$map[[string]$d.Name]=[string]$d.'#text'}}
    return $map
}
function Convert-EType([object]$Value){
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)){return [pscustomobject]@{Value=$null;Hex=$null;Name='Unknown'}}
    $text=([string]$Value).Trim();$number=$null
    try{if($text-match'^0x'){$number=[Convert]::ToInt32($text.Substring(2),16)}else{$number=[int]$text}}catch{return [pscustomobject]@{Value=$null;Hex=$text;Name='Unknown'}}
    $name=switch($number){1{'DES-CRC'}3{'DES-MD5'}17{'AES128-SHA96'}18{'AES256-SHA96'}19{'AES128-SHA256'}20{'AES256-SHA384'}23{'RC4'}default{'Unknown'}}
    [pscustomobject]@{Value=$number;Hex=('0x{0:X}'-f$number);Name=$name}
}
function Get-FirstValue([hashtable]$Map,[string[]]$Names){foreach ($n in $Names){if($Map.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Map[$n])){return [string]$Map[$n]}};return $null}
function Convert-KerberosEvent([System.Diagnostics.Eventing.Reader.EventRecord]$Event,[string]$SourceName){
    $m=Get-EventDataMap $Event
    if($Event.Id -eq 4769){
        $ticket=Convert-EType (Get-FirstValue $m @('TicketEncryptionType'))
        $session=Convert-EType (Get-FirstValue $m @('SessionKeyEncryptionType'))
        $account=Get-FirstValue $m @('TargetUserName','AccountName')
        $target=Get-FirstValue $m @('ServiceName','TargetServerName')
        $address=Get-FirstValue $m @('IpAddress','ClientAddress')
        $type='TGS'
    }elseif($Event.Id -eq 4768){
        $ticket=Convert-EType (Get-FirstValue $m @('TicketEncryptionType'))
        $session=Convert-EType (Get-FirstValue $m @('SessionKeyEncryptionType'))
        $account=Get-FirstValue $m @('TargetUserName','AccountName')
        $target='krbtgt';$address=Get-FirstValue $m @('IpAddress','ClientAddress');$type='AS'
    }else{return $null}
    $ticketRc4=$ticket.Name -eq 'RC4';$sessionRc4=$session.Name -eq 'RC4';$des=$ticket.Name -like 'DES*' -or $session.Name -like 'DES*'
    [pscustomobject][ordered]@{
        SchemaVersion='1.0';Source=$SourceName;MachineName=[string]$Event.MachineName;RecordId=[long]$Event.RecordId
        TimeCreatedUtc=$Event.TimeCreated.ToUniversalTime().ToString('o');EventId=[int]$Event.Id;RequestType=$type
        Account=$account;Target=$target;ClientAddress=$address;TicketEncryption=$ticket.Name;TicketEncryptionValue=$ticket.Hex
        SessionKeyEncryption=$session.Name;SessionKeyEncryptionValue=$session.Hex;ObservedRC4Ticket=$ticketRc4
        ObservedRC4SessionKey=$sessionRc4;ObservedDES=$des;ObservedAES=($ticket.Name -like 'AES*' -or $session.Name -like 'AES*')
        AccountSupportedEncryptionTypes=Get-FirstValue $m @('AccountSupportedEncryptionTypes','ClientAdvertizedEncryptionTypes')
        ServiceSupportedEncryptionTypes=Get-FirstValue $m @('ServiceSupportedEncryptionTypes')
        AccountAvailableKeys=Get-FirstValue $m @('AccountAvailableKeys')
        ServiceAvailableKeys=Get-FirstValue $m @('ServiceAvailableKeys')
        DCAvailableKeys=Get-FirstValue $m @('DCAvailableKeys')
        NewEncryptionMetadataPresent=$m.ContainsKey('SessionKeyEncryptionType')
    }
}
$EngagementDirectory=[IO.Path]::GetFullPath($EngagementDirectory)
if(-not(Test-Path $EngagementDirectory -PathType Container)){throw"EngagementDirectoryMissing: $EngagementDirectory"}
$OutputDirectory=Join-Path $EngagementDirectory 'evidence\KerberosEncryptionUsage'
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$Since=(Get-Date).ToUniversalTime().AddDays(-$LookbackDays)
$Iso=$Since.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$XPath="*[System[(EventID=4768 or EventID=4769) and TimeCreated[@SystemTime >= '$Iso']]]"
Show 'START' "MSADPT Kerberos Encryption Usage v$ModuleVersion" Cyan
Show 'SAFETY' 'Read-only event-log analysis. Ticket requests=None; audit-policy changes=None; remote changes=None.' Green
Show 'WINDOW' "SinceUtc=$($Since.ToString('o')); maximum-events-per-source=$MaximumEventsPerSource" Yellow
$Sources=New-Object 'System.Collections.Generic.List[object]'
if ($PSCmdlet.ParameterSetName -eq 'Evtx'){
 foreach ($path in $EvtxPath){$full=[IO.Path]::GetFullPath($path);$Sources.Add([pscustomobject]@{Kind='Evtx';Name=$full;ComputerName=$null;Path=$full})}
}else{
 if($CollectionMode -eq 'Local'){$Sources.Add([pscustomobject]@{Kind='Local';Name=$env:COMPUTERNAME;ComputerName=$null;Path=$null})}
 else{
   if ($null -eq $DomainController -or $DomainController.Count -eq 0){
     try{Import-Module ActiveDirectory -ErrorAction Stop;$DomainController=@(Get-ADDomainController -Filter *|Select-Object -ExpandProperty HostName)}catch{Show 'DISCOVERY' "AD module/DC discovery unavailable: $($_.Exception.Message)" Yellow;$DomainController=@()}
   }
   foreach ($dc in @($DomainController | Sort-Object -Unique)){$Sources.Add([pscustomobject]@{Kind='Remote';Name=[string]$dc;ComputerName=[string]$dc;Path=$null})}
   if($CollectionMode -eq 'Auto'){$Sources.Add([pscustomobject]@{Kind='Local';Name=$env:COMPUTERNAME;ComputerName=$null;Path=$null})}
 }
}
if ($Sources.Count -eq 0){throw'NoCollectionSourcesAvailable'}
Show 'NETWORK' ("Sources: "+(($Sources|ForEach-Object{"$($_.Kind):$($_.Name)"})-join'; ')) Yellow
$Events=New-Object 'System.Collections.Generic.List[object]';$Coverage=New-Object 'System.Collections.Generic.List[object]'
foreach ($source in $Sources){
 Show 'COLLECT' "$($source.Kind):$($source.Name)" DarkCyan;$started=(Get-Date).ToUniversalTime();$raw=@();$errorText=$null
 try{
   if($source.Kind -eq 'Evtx'){$raw=@(Get-WinEvent -Path $source.Path -FilterXPath $XPath -MaxEvents $MaximumEventsPerSource -ErrorAction Stop)}
   elseif($source.Kind -eq 'Remote'){$gp=@{ComputerName=$source.ComputerName;LogName='Security';FilterXPath=$XPath;MaxEvents=$MaximumEventsPerSource;ErrorAction='Stop'};if($null -ne $Credential){$gp.Credential=$Credential};$raw=@(Get-WinEvent @gp)}
   else{$raw=@(Get-WinEvent -LogName Security -FilterXPath $XPath -MaxEvents $MaximumEventsPerSource -ErrorAction Stop)}
 }catch{if($_.FullyQualifiedErrorId-like'NoMatchingEventsFound*'){$raw=@()}else{$errorText=$_.Exception.Message}}
 $parsed=0;$parseErrors=0
 foreach ($event in $raw){try{$r=Convert-KerberosEvent $event $source.Name;if($null -ne $r){if ($IncludeAllEvents -or $r.ObservedRC4Ticket -or $r.ObservedRC4SessionKey -or $r.ObservedDES){$Events.Add($r)};$parsed++}}catch{$parseErrors++}}
 $status=if ($null -ne $errorText){'Failed'} elseif ($parseErrors -gt 0){'CompletedWithErrors'}else{'Completed'}
 $Coverage.Add([pscustomobject][ordered]@{Source=$source.Name;Kind=$source.Kind;Status=$status;StartedUtc=$started.ToString('o');CompletedUtc=(Get-Date).ToUniversalTime().ToString('o');EventsRead=$raw.Count;EventsParsed=$parsed;ParseErrorCount=$parseErrors;Error=$errorText})
 if ($null -ne $errorText){Show 'NONFATAL' "$($source.Name): $errorText" Yellow}else{Show 'COLLECTED' "$($source.Name): read=$($raw.Count); parsed=$parsed" Green}
}
$EventRows=[object[]]$Events.ToArray();$CoverageRows=[object[]]$Coverage.ToArray()
$Rc4Rows=@($EventRows|Where-Object{$_.ObservedRC4Ticket -or $_.ObservedRC4SessionKey})
$AccountSummary=@($Rc4Rows|Group-Object Account,Target|ForEach-Object{[pscustomobject][ordered]@{Account=[string]$_.Group[0].Account;Target=[string]$_.Group[0].Target;RC4EventCount=$_.Count;RC4TicketCount=@($_.Group|Where-Object ObservedRC4Ticket).Count;RC4SessionKeyCount=@($_.Group|Where-Object ObservedRC4SessionKey).Count;FirstObservedUtc=($_.Group.TimeCreatedUtc|Sort-Object|Select-Object -First 1);LastObservedUtc=($_.Group.TimeCreatedUtc|Sort-Object|Select-Object -Last 1);Sources=@($_.Group.Source|Sort-Object -Unique)}})
$EvidencePath=Join-Path $OutputDirectory 'kerberos-encryption-events.json';$CsvPath=Join-Path $OutputDirectory 'kerberos-encryption-events.csv';$SummaryPath=Join-Path $OutputDirectory 'rc4-account-summary.json';$CoveragePath=Join-Path $OutputDirectory 'collection-coverage.json';$ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json'
Write-Json $EvidencePath $EventRows;Write-EventCsv -Path $CsvPath -Rows $EventRows;Write-Json $SummaryPath $AccountSummary;Write-Json $CoveragePath $CoverageRows
$files=@($EvidencePath,$CsvPath,$SummaryPath,$CoveragePath)|ForEach-Object{[pscustomobject]@{Name=(Split-Path -Leaf $_);Size=(Get-Item $_).Length;SHA256=(Get-FileHash $_ -Algorithm SHA256).Hash}}
$successful=@($CoverageRows|Where-Object{$_.Status -ne 'Failed'}).Count;$failed=@($CoverageRows|Where-Object{$_.Status -eq 'Failed'}).Count
$manifest=[pscustomobject][ordered]@{SchemaVersion='1.0';Status=if($successful -eq 0){'Inconclusive'}elseif($failed -gt 0){'CompletedWithErrors'}else{'Completed'};ModuleId='KerberosEncryptionUsage';ModuleVersion=$ModuleVersion;GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');LookbackDays=$LookbackDays;SourceCount=$CoverageRows.Count;SuccessfulSourceCount=$successful;FailedSourceCount=$failed;RetainedEventCount=$EventRows.Count;ObservedRC4EventCount=$Rc4Rows.Count;ObservedRC4TicketCount=@($Rc4Rows|Where-Object ObservedRC4Ticket).Count;ObservedRC4SessionKeyCount=@($Rc4Rows|Where-Object ObservedRC4SessionKey).Count;ObservedDESEventCount=@($EventRows|Where-Object ObservedDES).Count;UniqueRC4AccountTargetCount=$AccountSummary.Count;Disposition=if($successful -eq 0){'Inconclusive'}elseif($Rc4Rows.Count -gt 0){'ConfirmedRC4Usage'}else{'NotDetected'};Limitations='NotDetected does not confirm absence when DC coverage, event retention, audit policy, event schema, or permissions are incomplete. This module reports observed use, not static account key readiness.';RemoteChanges='None';TicketRequests='None';AuditPolicyChanges='None';Files=$files}
Write-Json $ManifestPath $manifest
Show 'DONE' "status=$($manifest.Status); disposition=$($manifest.Disposition); sources=$successful/$($CoverageRows.Count); rc4-events=$($Rc4Rows.Count); errors=$failed" Green
[pscustomobject][ordered]@{Status=$manifest.Status;Version=$ModuleVersion;Disposition=$manifest.Disposition;SourceCount=$CoverageRows.Count;SuccessfulSourceCount=$successful;FailedSourceCount=$failed;ObservedRC4EventCount=$Rc4Rows.Count;UniqueRC4AccountTargetCount=$AccountSummary.Count;EvidenceDirectory=$OutputDirectory;ManifestPath=$ManifestPath;RemoteChanges='None';TicketRequests='None'}
