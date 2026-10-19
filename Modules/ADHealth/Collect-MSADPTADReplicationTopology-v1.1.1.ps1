<#
.SYNOPSIS
Collects structured, read-only Active Directory forest replication and topology evidence.
.DESCRIPTION
Version 1.1.0 adds explicit ADWS reachability preflight, assessed/unavailable coverage, expected naming-context coverage, safe relative-path handling, and optional bounded repadmin fallback.
.NOTES
Version: 1.1.1
Supports Windows PowerShell 5.1 and PowerShell 7 on Windows with RSAT ActiveDirectory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [string]$ForestName,
    [ValidateRange(1,30)][int]$TcpTimeoutSeconds=5,
    [ValidateRange(10,600)][int]$RepadminTimeoutSeconds=90,
    [switch]$PlanOnly,
    [switch]$SkipQueue,
    [switch]$SkipFailures,
    [switch]$EnableRepadminFallback
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Version='1.1.1'
function Show { param([string]$State,[string]$Message,[ConsoleColor]$Color='Gray'); Write-Host ('[{0,-12}] {1}' -f $State,$Message) -ForegroundColor $Color }
function Resolve-LocalPath { param([string]$Path); if([IO.Path]::IsPathRooted($Path)){return [IO.Path]::GetFullPath($Path)}; return [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path)) }
function Write-Json { param([object]$Value,[string]$Path,[int]$Depth=12); ConvertTo-Json -InputObject $Value -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8 }
function New-OperationalError { param([string]$Stage,[string]$Target,[string]$Message,[string]$Type='Operational'); [pscustomobject][ordered]@{Stage=$Stage;Target=$Target;Type=$Type;Message=$Message;RecordedUtc=(Get-Date).ToUniversalTime().ToString('o')} }
function Test-TcpPort {
    param([string]$ComputerName,[int]$Port,[int]$TimeoutSeconds)
    $Client=[Net.Sockets.TcpClient]::new()
    try{$Task=$Client.ConnectAsync($ComputerName,$Port);if(-not $Task.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))){return [pscustomobject]@{Succeeded=$false;Error='Timeout'}};return [pscustomobject]@{Succeeded=$Client.Connected;Error=if($Client.Connected){$null}else{'Connection failed'}}}catch{return [pscustomobject]@{Succeeded=$false;Error=$_.Exception.Message}}finally{$Client.Dispose()}
}
function Invoke-RepadminFallback {
    param([string]$Target,[string]$OutputPath,[int]$TimeoutSeconds)
    $Exe=Get-Command repadmin.exe -ErrorAction SilentlyContinue
    if(-not $Exe){return [pscustomobject]@{Status='Unavailable';ExitCode=$null;TimedOut=$false;OutputPath=$null;Message='repadmin.exe was not found.'}}
    $Psi=[Diagnostics.ProcessStartInfo]::new();$Psi.FileName=$Exe.Source;$Psi.Arguments='/showrepl "{0}" /all /verbose' -f $Target;$Psi.UseShellExecute=$false;$Psi.RedirectStandardOutput=$true;$Psi.RedirectStandardError=$true;$Psi.CreateNoWindow=$true
    $Process=[Diagnostics.Process]::new();$Process.StartInfo=$Psi;$null=$Process.Start()
    $OutTask=$Process.StandardOutput.ReadToEndAsync();$ErrTask=$Process.StandardError.ReadToEndAsync()
    if(-not $Process.WaitForExit($TimeoutSeconds*1000)){try{$Process.Kill()}catch{};$Text=$OutTask.Result+"`r`n"+$ErrTask.Result;Set-Content -LiteralPath $OutputPath -Value $Text -Encoding UTF8;return [pscustomobject]@{Status='TimedOut';ExitCode=$null;TimedOut=$true;OutputPath=$OutputPath;Message='repadmin fallback timed out.'}}
    $Text=$OutTask.Result+"`r`n"+$ErrTask.Result;Set-Content -LiteralPath $OutputPath -Value $Text -Encoding UTF8
    return [pscustomobject]@{Status=if($Process.ExitCode-eq 0){'Completed'}else{'Failed'};ExitCode=$Process.ExitCode;TimedOut=$false;OutputPath=$OutputPath;Message=$ErrTask.Result.Trim()}
}
$OutputRoot=Resolve-LocalPath $OutputRoot
$Plan=@(
 [pscustomobject]@{Stage='ForestDiscovery';Target=if($ForestName){$ForestName}else{'Current forest'};Protocol='ADWS';Ports='9389 TCP';Operation='Read forest, domains, sites, subnets, links, connections and naming contexts'},
 [pscustomobject]@{Stage='ADWSPreflight';Target='Discovered domain controllers';Protocol='DNS and TCP';Ports='9389 TCP';Operation='Resolve DNS and test ADWS TCP reachability'},
 [pscustomobject]@{Stage='ReplicationMetadata';Target='ADWS-reachable domain controllers';Protocol='ADWS';Ports='9389 TCP';Operation='Read partner metadata, failures and queue operations'}
)
if($EnableRepadminFallback){$Plan+= [pscustomobject]@{Stage='RepadminFallback';Target='ADWS-unreachable domain controllers';Protocol='RPC and LDAP';Ports='135 TCP; 389 TCP; dynamic RPC';Operation='Run bounded repadmin /showrepl fallback and preserve raw text'}}
Show 'PLAN' 'Read-only forest replication and topology collection.' Cyan
$Plan|Format-Table Target,Protocol,Ports,Operation -AutoSize -Wrap
if($PlanOnly){return [pscustomobject][ordered]@{Status='Planned';Version=$Version;Plan=$Plan;NetworkExecuted=$false;OutputRoot=$OutputRoot}}
if(-not (Get-Module -ListAvailable ActiveDirectory)){throw 'ActiveDirectoryModuleMissing: install RSAT Active Directory PowerShell.'}
Import-Module ActiveDirectory -ErrorAction Stop
$Raw=Join-Path $OutputRoot 'Raw';$FallbackRoot=Join-Path $Raw 'Repadmin';New-Item -ItemType Directory -Path $Raw,$FallbackRoot -Force|Out-Null
$Errors=[Collections.Generic.List[object]]::new();$Started=(Get-Date).ToUniversalTime()
try{$Forest=if($ForestName){Get-ADForest -Identity $ForestName -ErrorAction Stop}else{Get-ADForest -ErrorAction Stop}}catch{throw "ForestDiscoveryFailed: $($_.Exception.Message)"}
$Domains=[Collections.Generic.List[object]]::new();$Dcs=[Collections.Generic.List[object]]::new()
foreach($DomainName in @($Forest.Domains)){
 try{$Domain=Get-ADDomain -Identity $DomainName -ErrorAction Stop;$Domains.Add([pscustomobject][ordered]@{DNSRoot=$Domain.DNSRoot;DistinguishedName=$Domain.DistinguishedName;NetBIOSName=$Domain.NetBIOSName;DomainMode=[string]$Domain.DomainMode;PDCEmulator=[string]$Domain.PDCEmulator;RIDMaster=[string]$Domain.RIDMaster;InfrastructureMaster=[string]$Domain.InfrastructureMaster})}catch{$Errors.Add((New-OperationalError 'DomainDiscovery' $DomainName $_.Exception.Message));continue}
 try{foreach($Dc in @(Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop)){$Dcs.Add([pscustomobject][ordered]@{HostName=$Dc.HostName;Name=$Dc.Name;Domain=$DomainName;Site=$Dc.Site;IPv4Address=$Dc.IPv4Address;IsGlobalCatalog=[bool]$Dc.IsGlobalCatalog;IsReadOnly=[bool]$Dc.IsReadOnly;OperatingSystem=$Dc.OperatingSystem;Enabled=[bool]$Dc.Enabled})}}catch{$Errors.Add((New-OperationalError 'DomainControllerDiscovery' $DomainName $_.Exception.Message))}
}
$RootDse=$null;try{$RootDse=Get-ADRootDSE -Server $Forest.RootDomain -ErrorAction Stop}catch{$Errors.Add((New-OperationalError 'RootDSE' $Forest.RootDomain $_.Exception.Message))}
$Sites=@();$Subnets=@();$SiteLinks=@();$Connections=@()
try{$Sites=@(Get-ADReplicationSite -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Name=$_.Name;DistinguishedName=$_.DistinguishedName;Description=$_.Description}})}catch{$Errors.Add((New-OperationalError 'Sites' $Forest.Name $_.Exception.Message))}
try{$Subnets=@(Get-ADReplicationSubnet -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Name=$_.Name;Site=[string]$_.Site;Location=$_.Location;DistinguishedName=$_.DistinguishedName}})}catch{$Errors.Add((New-OperationalError 'Subnets' $Forest.Name $_.Exception.Message))}
try{$SiteLinks=@(Get-ADReplicationSiteLink -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Name=$_.Name;Cost=$_.Cost;ReplicationFrequencyInMinutes=$_.ReplicationFrequencyInMinutes;SitesIncluded=@($_.SitesIncluded|ForEach-Object{[string]$_});Transport=[string]$_.InterSiteTransportProtocol;DistinguishedName=$_.DistinguishedName}})}catch{$Errors.Add((New-OperationalError 'SiteLinks' $Forest.Name $_.Exception.Message))}
try{$Connections=@(Get-ADReplicationConnection -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Name=$_.Name;From=[string]$_.ReplicateFromDirectoryServer;To=[string]$_.ReplicateToDirectoryServer;AutoGenerated=[bool]$_.AutoGenerated;Enabled=[bool]$_.Enabled;DistinguishedName=$_.DistinguishedName}})}catch{$Errors.Add((New-OperationalError 'Connections' $Forest.Name $_.Exception.Message))}
$Reachability=[Collections.Generic.List[object]]::new();$Partners=@();$Failures=@();$Queues=@();$Fallback=@()
foreach($Dc in @($Dcs)){
 $Target=[string]$Dc.HostName;Show 'PREFLIGHT' "DNS and TCP 9389: $Target" Cyan
 $Dns=$false;$Addresses=@();$DnsError=$null
 try{$Addresses=@([Net.Dns]::GetHostAddresses($Target)|ForEach-Object{$_.IPAddressToString}|Sort-Object -Unique);$Dns=$Addresses.Count-gt 0}catch{$DnsError=$_.Exception.Message}
 $Tcp=if($Dns){Test-TcpPort $Target 9389 $TcpTimeoutSeconds}else{[pscustomobject]@{Succeeded=$false;Error='Skipped because DNS failed'}}
 $Reachability.Add([pscustomobject][ordered]@{Target=$Target;Site=$Dc.Site;Addresses=($Addresses-join'; ');DnsSucceeded=$Dns;DnsError=$DnsError;Tcp9389Succeeded=[bool]$Tcp.Succeeded;Tcp9389Error=$Tcp.Error;Disposition=if(-not $Dns){'DnsResolutionFailed'}elseif(-not $Tcp.Succeeded){'AdwsTcpUnreachable'}else{'AdwsTcpReachable'}})
 if(-not $Tcp.Succeeded){
   if($EnableRepadminFallback){$Safe=$Target-replace'[^A-Za-z0-9._-]','_';$Fallback+=Invoke-RepadminFallback $Target (Join-Path $FallbackRoot ("Repadmin-ShowRepl-{0}.txt"-f$Safe)) $RepadminTimeoutSeconds}
   continue
 }
 Show 'COLLECT' "Structured replication metadata: $Target" Cyan
 try{$Partners+=@(Get-ADReplicationPartnerMetadata -Target $Target -Scope Server -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Server=$Target;Partner=[string]$_.Partner;Partition=[string]$_.Partition;PartnerType=[string]$_.PartnerType;LastReplicationAttempt=$_.LastReplicationAttempt;LastReplicationSuccess=$_.LastReplicationSuccess;LastReplicationResult=$_.LastReplicationResult;ConsecutiveReplicationFailures=$_.ConsecutiveReplicationFailures}})}catch{$Errors.Add((New-OperationalError 'PartnerMetadata' $Target $_.Exception.Message))}
 if(-not $SkipFailures){try{$Failures+=@(Get-ADReplicationFailure -Target $Target -Scope Server -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Server=$Target;Partner=[string]$_.Partner;FirstFailureTime=$_.FirstFailureTime;FailureCount=$_.FailureCount;LastError=$_.LastError}})}catch{$Errors.Add((New-OperationalError 'ReplicationFailure' $Target $_.Exception.Message))}}
 if(-not $SkipQueue){try{$Queues+=@(Get-ADReplicationQueueOperation -Server $Target -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Server=$Target;OperationId=$_.OperationId;OperationType=[string]$_.OperationType;PartitionName=[string]$_.PartitionName;PartnerDN=[string]$_.PartnerDN;Priority=$_.Priority;EnqueueTime=$_.EnqueueTime}})}catch{$Errors.Add((New-OperationalError 'ReplicationQueue' $Target $_.Exception.Message))}}
}
$ExpectedNc=if($RootDse){@($RootDse.namingContexts|ForEach-Object{[string]$_})}else{@()};$ObservedNc=@($Partners|ForEach-Object{$_.Partition}|Sort-Object -Unique)
$ForestRecord=[pscustomobject][ordered]@{Name=$Forest.Name;RootDomain=$Forest.RootDomain;ForestMode=[string]$Forest.ForestMode;SchemaMaster=[string]$Forest.SchemaMaster;DomainNamingMaster=[string]$Forest.DomainNamingMaster;Domains=@($Forest.Domains);ExpectedNamingContexts=$ExpectedNc;ObservedNamingContexts=$ObservedNc}
$Data=[ordered]@{'forest.json'=$ForestRecord;'domains.json'=@($Domains);'domain-controllers.json'=@($Dcs);'sites.json'=@($Sites);'subnets.json'=@($Subnets);'site-links.json'=@($SiteLinks);'connections.json'=@($Connections);'reachability.json'=@($Reachability);'partner-metadata.json'=@($Partners);'replication-failures.json'=@($Failures);'replication-queue.json'=@($Queues);'repadmin-fallback.json'=@($Fallback);'operational-errors.json'=@($Errors);'collection-plan.json'=@($Plan)}
foreach($Name in $Data.Keys){Write-Json $Data[$Name] (Join-Path $Raw $Name)}
$Completed=(Get-Date).ToUniversalTime();$Files=@(Get-ChildItem $Raw -File -Recurse|ForEach-Object{[pscustomobject]@{RelativePath=[IO.Path]::GetRelativePath($OutputRoot,$_.FullName);Length=$_.Length;SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash}})
$Reachable=@($Reachability|Where-Object{$_.Tcp9389Succeeded}).Count;$Unavailable=$Dcs.Count-$Reachable
$Manifest=[pscustomobject][ordered]@{SchemaVersion='1.1';ModuleId='Collect-MSADPTADReplicationTopology';ModuleVersion=$Version;StartedUtc=$Started.ToString('o');CompletedUtc=$Completed.ToString('o');Forest=$Forest.Name;DiscoveredDomainControllerCount=$Dcs.Count;AdwsReachableControllerCount=$Reachable;AdwsUnavailableControllerCount=$Unavailable;AssessedControllerCount=@($Partners|ForEach-Object{$_.Server}|Sort-Object -Unique).Count;ExpectedNamingContextCount=$ExpectedNc.Count;ObservedNamingContextCount=$ObservedNc.Count;PartnerMetadataCount=$Partners.Count;OperationalErrorCount=$Errors.Count;RepadminFallbackEnabled=[bool]$EnableRepadminFallback;ReadOnly=$true;Files=$Files}
Write-Json $Manifest (Join-Path $OutputRoot 'evidence-manifest.json')
$Status=if($Unavailable-gt0-or$Errors.Count-gt0){'Partial'}else{'Completed'};Show $Status "Collection complete: $OutputRoot" $(if($Status-eq'Completed'){'Green'}else{'Yellow'})
[pscustomobject][ordered]@{Status=$Status;Version=$Version;OutputRoot=$OutputRoot;Forest=$Forest.Name;DiscoveredDomainControllerCount=$Dcs.Count;AdwsReachableControllerCount=$Reachable;AdwsUnavailableControllerCount=$Unavailable;AssessedControllerCount=$Manifest.AssessedControllerCount;ExpectedNamingContextCount=$ExpectedNc.Count;ObservedNamingContextCount=$ObservedNc.Count;PartnerMetadataCount=$Partners.Count;OperationalErrorCount=$Errors.Count;ManifestPath=(Join-Path $OutputRoot 'evidence-manifest.json')}
