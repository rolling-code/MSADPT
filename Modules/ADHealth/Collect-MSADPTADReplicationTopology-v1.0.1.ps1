<#
.SYNOPSIS
Collects structured, read-only Active Directory forest replication and topology evidence.
.NOTES
Version: 1.0.1
Supports Windows PowerShell 5.1 and PowerShell 7 on Windows with the ActiveDirectory module.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$OutputRoot,
 [string]$ForestName,
 [ValidateRange(30,3600)][int]$CommandTimeoutSeconds=180,
 [switch]$PlanOnly,
 [switch]$SkipQueue,
 [switch]$SkipFailures
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Version='1.0.1'
function Show{param([string]$State,[string]$Message,[ConsoleColor]$Color='Gray');Write-Host ('[{0,-12}] {1}'-f $State,$Message)-ForegroundColor $Color}
function Write-JsonFile{param([object]$Value,[string]$Path,[int]$Depth=12);ConvertTo-Json -InputObject $Value -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8}
function Get-ErrorRecord{param([string]$Stage,[string]$Target,[System.Management.Automation.ErrorRecord]$Record);[pscustomobject][ordered]@{Stage=$Stage;Target=$Target;Message=$Record.Exception.Message;ExceptionType=$Record.Exception.GetType().FullName;Category=[string]$Record.CategoryInfo.Category;FullyQualifiedErrorId=$Record.FullyQualifiedErrorId;RecordedUtc=(Get-Date).ToUniversalTime().ToString('o')}}
$OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
$plan=[System.Collections.Generic.List[object]]::new()
$plan.Add([pscustomobject]@{Stage='ForestDiscovery';Target=if($ForestName){$ForestName}else{'Current forest'};Protocol='ADWS';Ports='9389 TCP';Operation='Read forest, domains, sites, subnets, site links and naming contexts'})
$plan.Add([pscustomobject]@{Stage='ReplicationMetadata';Target='Discovered domain controllers';Protocol='ADWS';Ports='9389 TCP';Operation='Read partner metadata, connection objects and replication failures'})
if(-not $SkipQueue){$plan.Add([pscustomobject]@{Stage='ReplicationQueue';Target='Discovered domain controllers';Protocol='ADWS';Ports='9389 TCP';Operation='Read replication queue operations'})}
Show 'PLAN' 'Read-only forest replication and topology collection.' Cyan
$plan|Format-Table Target,Protocol,Ports,Operation -AutoSize -Wrap
if($PlanOnly){return [pscustomobject][ordered]@{Status='Planned';Version=$Version;Plan=@($plan);NetworkExecuted=$false;OutputRoot=$OutputRoot}}
if(-not(Get-Module -ListAvailable -Name ActiveDirectory)){throw 'ActiveDirectoryModuleMissing: install the Active Directory RSAT PowerShell module.'}
Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
$raw=Join-Path $OutputRoot 'Raw';New-Item -ItemType Directory -Path $raw -Force|Out-Null
$errors=[System.Collections.Generic.List[object]]::new();$started=(Get-Date).ToUniversalTime()
try{$forest=if($ForestName){Get-ADForest -Identity $ForestName -ErrorAction Stop}else{Get-ADForest -ErrorAction Stop}}catch{throw "ForestDiscoveryFailed: $($_.Exception.Message)"}
$domains=[System.Collections.Generic.List[object]]::new();$dcs=[System.Collections.Generic.List[object]]::new()
foreach($domainName in @($forest.Domains)){
 try{$domain=Get-ADDomain -Identity $domainName -ErrorAction Stop;$domains.Add([pscustomobject][ordered]@{DNSRoot=$domain.DNSRoot;DistinguishedName=$domain.DistinguishedName;NetBIOSName=$domain.NetBIOSName;DomainMode=[string]$domain.DomainMode;PDCEmulator=[string]$domain.PDCEmulator;RIDMaster=[string]$domain.RIDMaster;InfrastructureMaster=[string]$domain.InfrastructureMaster})}catch{$errors.Add((Get-ErrorRecord 'DomainDiscovery' $domainName $_));continue}
 try{foreach($dc in @(Get-ADDomainController -Filter * -Server $domainName -ErrorAction Stop)){$dcs.Add([pscustomobject][ordered]@{HostName=$dc.HostName;Name=$dc.Name;Domain=$domainName;Site=$dc.Site;IPv4Address=$dc.IPv4Address;IsGlobalCatalog=[bool]$dc.IsGlobalCatalog;IsReadOnly=[bool]$dc.IsReadOnly;OperatingSystem=$dc.OperatingSystem;Enabled=[bool]$dc.Enabled})}}catch{$errors.Add((Get-ErrorRecord 'DomainControllerDiscovery' $domainName $_))}
}
$rootDse=$null;try{$rootDse=Get-ADRootDSE -Server $forest.RootDomain -ErrorAction Stop}catch{$errors.Add((Get-ErrorRecord 'RootDSE' $forest.RootDomain $_))}
$sites=@();$subnets=@();$siteLinks=@();$connections=@();$partners=@();$failures=@();$queues=@()
try{$sites=@(Get-ADReplicationSite -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;DistinguishedName=$_.DistinguishedName;Description=$_.Description}})}catch{$errors.Add((Get-ErrorRecord 'Sites' $forest.Name $_))}
try{$subnets=@(Get-ADReplicationSubnet -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;Site=[string]$_.Site;Location=$_.Location;DistinguishedName=$_.DistinguishedName}})}catch{$errors.Add((Get-ErrorRecord 'Subnets' $forest.Name $_))}
try{$siteLinks=@(Get-ADReplicationSiteLink -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;Cost=$_.Cost;ReplicationFrequencyInMinutes=$_.ReplicationFrequencyInMinutes;SitesIncluded=@($_.SitesIncluded|ForEach-Object{[string]$_});InterSiteTransportProtocol=[string]$_.InterSiteTransportProtocol;DistinguishedName=$_.DistinguishedName}})}catch{$errors.Add((Get-ErrorRecord 'SiteLinks' $forest.Name $_))}
try{$connections=@(Get-ADReplicationConnection -Filter * -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;ReplicateFromDirectoryServer=[string]$_.ReplicateFromDirectoryServer;ReplicateToDirectoryServer=[string]$_.ReplicateToDirectoryServer;AutoGenerated=[bool]$_.AutoGenerated;Enabled=[bool]$_.Enabled;DistinguishedName=$_.DistinguishedName}})}catch{$errors.Add((Get-ErrorRecord 'Connections' $forest.Name $_))}
foreach($dc in @($dcs)){
 $target=$dc.HostName;Show 'COLLECT' "Replication metadata: $target" Cyan
 try{$partners+=@(Get-ADReplicationPartnerMetadata -Target $target -Scope Server -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Server=$target;Partner=[string]$_.Partner;Partition=[string]$_.Partition;PartnerType=[string]$_.PartnerType;LastReplicationAttempt=$_.LastReplicationAttempt;LastReplicationSuccess=$_.LastReplicationSuccess;LastReplicationResult=$_.LastReplicationResult;ConsecutiveReplicationFailures=$_.ConsecutiveReplicationFailures}})}catch{$errors.Add((Get-ErrorRecord 'PartnerMetadata' $target $_))}
 if(-not $SkipFailures){try{$failures+=@(Get-ADReplicationFailure -Target $target -Scope Server -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Server=$target;Partner=[string]$_.Partner;FirstFailureTime=$_.FirstFailureTime;FailureCount=$_.FailureCount;LastError=$_.LastError}})}catch{$errors.Add((Get-ErrorRecord 'ReplicationFailure' $target $_))}}
 if(-not $SkipQueue){try{$queues+=@(Get-ADReplicationQueueOperation -Server $target -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Server=$target;OperationId=$_.OperationId;OperationType=[string]$_.OperationType;PartitionName=[string]$_.PartitionName;PartnerDN=[string]$_.PartnerDN;Priority=$_.Priority;EnqueueTime=$_.EnqueueTime}})}catch{$errors.Add((Get-ErrorRecord 'ReplicationQueue' $target $_))}}
}
$forestRecord=[pscustomobject][ordered]@{Name=$forest.Name;RootDomain=$forest.RootDomain;ForestMode=[string]$forest.ForestMode;SchemaMaster=[string]$forest.SchemaMaster;DomainNamingMaster=[string]$forest.DomainNamingMaster;Domains=@($forest.Domains);Sites=@($forest.Sites);GlobalCatalogs=@($forest.GlobalCatalogs);NamingContexts=if($rootDse){@($rootDse.namingContexts)}else{@()}}
$datasets=[ordered]@{'forest.json'=$forestRecord;'domains.json'=@($domains);'domain-controllers.json'=@($dcs);'sites.json'=@($sites);'subnets.json'=@($subnets);'site-links.json'=@($siteLinks);'connections.json'=@($connections);'partner-metadata.json'=@($partners);'replication-failures.json'=@($failures);'replication-queue.json'=@($queues);'operational-errors.json'=@($errors);'collection-plan.json'=@($plan)}
foreach($name in $datasets.Keys){Write-JsonFile $datasets[$name] (Join-Path $raw $name)}
$completed=(Get-Date).ToUniversalTime();$manifestFiles=@(Get-ChildItem -LiteralPath $raw -File|ForEach-Object{[pscustomobject][ordered]@{RelativePath=('Raw/'+$_.Name);Length=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
$manifest=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleId='Collect-MSADPTADReplicationTopology';ModuleVersion=$Version;StartedUtc=$started.ToString('o');CompletedUtc=$completed.ToString('o');DurationSeconds=[math]::Round(($completed-$started).TotalSeconds,3);Forest=$forest.Name;DomainCount=$domains.Count;DomainControllerCount=$dcs.Count;PartnerMetadataCount=@($partners).Count;FailureCount=@($failures).Count;QueueOperationCount=@($queues).Count;OperationalErrorCount=$errors.Count;ReadOnly=$true;Files=$manifestFiles}
Write-JsonFile $manifest (Join-Path $OutputRoot 'evidence-manifest.json')
$status=if($errors.Count){'Partial'}else{'Completed'};Show $status "Collection complete: $OutputRoot" $(if($errors.Count){'Yellow'}else{'Green'})
[pscustomobject][ordered]@{Status=$status;Version=$Version;OutputRoot=$OutputRoot;Forest=$forest.Name;DomainControllerCount=$dcs.Count;PartnerMetadataCount=@($partners).Count;FailureCount=@($failures).Count;QueueOperationCount=@($queues).Count;OperationalErrorCount=$errors.Count;ManifestPath=(Join-Path $OutputRoot 'evidence-manifest.json')}
