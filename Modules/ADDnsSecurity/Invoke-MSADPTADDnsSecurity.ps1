<#
.SYNOPSIS
Assesses AD-integrated DNS and optionally performs a bounded create-read-delete-verify validation.
.NOTES
Version: 0.2.2. Windows PowerShell 5.1 and PowerShell 7 compatible.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$EngagementDirectory,
 [string]$Server,
 [PSCredential]$Credential,
 [int]$Port=389,
 [switch]$UseSSL,
 [switch]$EnableBehavioralValidation,
 [string]$Zone,
 [string]$RecordIp='127.0.0.1',
 [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Version='0.2.2'
function Show([string]$S,[string]$M,[ConsoleColor]$C=[ConsoleColor]::Gray){$t='[{0,-12}] {1}'-f $S,$M;if($NoColor){Write-Host $t}else{Write-Host $t -ForegroundColor $C}}
function WriteJson([string]$P,[AllowEmptyCollection()][object]$V){$d=Split-Path -Parent $P;New-Item -ItemType Directory -Path $d -Force|Out-Null;if($V -is [System.Array] -and @($V).Count -eq 0){[IO.File]::WriteAllText($P,"[]`r`n",(New-Object Text.UTF8Encoding($false)))}else{$V|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $P -Encoding UTF8};$null=Get-Content $P -Raw|ConvertFrom-Json}
function GetAttr($A,[string]$N){try{$v=$A[$N];if($null-ne$v){Write-Output -NoEnumerate $v;return}}catch{};return $null}
function DnToDns([string]$Dn){(@([regex]::Matches($Dn,'DC=([^,]+)','IgnoreCase')|ForEach-Object{$_.Groups[1].Value})-join'.').ToLowerInvariant()}
function TcpTest([string]$HostName,[int]$TargetPort){$c=New-Object Net.Sockets.TcpClient;try{$a=$c.BeginConnect($HostName,$TargetPort,$null,$null);if(-not$a.AsyncWaitHandle.WaitOne(5000)){return $false};$c.EndConnect($a);return $true}catch{return $false}finally{$c.Close()}}
function Search($Connection,[string]$Base,[string]$Filter,[System.DirectoryServices.Protocols.SearchScope]$Scope,[string[]]$Attributes){$q=New-Object System.DirectoryServices.Protocols.SearchRequest($Base,$Filter,$Scope,$Attributes);$Connection.SendRequest($q)}
function NewARecord([string]$Ip,[uint32]$Serial){$b=New-Object 'Collections.Generic.List[byte]';$b.AddRange([BitConverter]::GetBytes([uint16]4));$b.AddRange([BitConverter]::GetBytes([uint16]1));$b.Add(5);$b.Add(0);$b.AddRange([BitConverter]::GetBytes([uint16]0));$b.AddRange([BitConverter]::GetBytes($Serial));$ttl=[BitConverter]::GetBytes([uint32]300);[Array]::Reverse($ttl);$b.AddRange($ttl);$b.AddRange([BitConverter]::GetBytes([uint32]0));$b.AddRange([BitConverter]::GetBytes([uint32]0));$b.AddRange([Net.IPAddress]::Parse($Ip).GetAddressBytes());return [byte[]]$b.ToArray()}
$Evidence=Join-Path $EngagementDirectory 'evidence\ADDnsSecurity';$Analysis=Join-Path $EngagementDirectory 'analysis\ADDnsSecurity';New-Item -ItemType Directory -Path $Evidence,$Analysis -Force|Out-Null
$SummaryPath=Join-Path $Analysis 'ad-dns-security-summary.json';$ValidationPath=Join-Path $Evidence 'ad-dns-write-validation.json';$ZonesPath=Join-Path $Evidence 'ad-dns-zones.json';$CleanupPath=Join-Path $Evidence 'ad-dns-cleanup-manifest.json';$AuthorizationPath=Join-Path $Evidence 'ad-dns-effective-write-context.json';$ResolutionPath=Join-Path $Evidence 'ad-dns-resolution-validation.json';$InventoryPath=Join-Path $Evidence 'ad-dns-inventory.json';$CandidatesPath=Join-Path $Analysis 'ad-dns-dangling-reference-candidates.json'
if([string]::IsNullOrWhiteSpace($Server)){try{Import-Module ActiveDirectory -ErrorAction Stop;$Server=(Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName}catch{throw "WritableDomainControllerDiscoveryFailed: $($_.Exception.Message)"}}
$Protocol=if($UseSSL){'LDAPS'}else{'LDAP'};if($UseSSL-and$Port-eq389){$Port=636}
$OperationDescription = if ($EnableBehavioralValidation) { 'Read DNS partitions and perform one temporary create-read-delete-verify validation' } else { 'Read-only DNS partition and zone discovery' }
Show TARGET "Server=$Server" Cyan;Show PORTS "TCP/$Port" Cyan;Show PROTOCOL "$Protocol with Negotiate authentication; signing and sealing requested" Cyan;Show OPERATION $OperationDescription Yellow
if(-not(TcpTest $Server $Port)){throw "TcpPreflightFailed: $Server`:$Port"};Show CONNECT 'TCP preflight succeeded.' Green
Add-Type -AssemblyName System.DirectoryServices.Protocols
$id=New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server,$Port,$false,$false);$conn=New-Object System.DirectoryServices.Protocols.LdapConnection($id);$conn.AuthType=[System.DirectoryServices.Protocols.AuthType]::Negotiate;if($null-ne$Credential){$conn.Credential=$Credential.GetNetworkCredential()};if($UseSSL){$conn.SessionOptions.SecureSocketLayer=$true};try{$conn.SessionOptions.Signing=$true;$conn.SessionOptions.Sealing=$true}catch{};$conn.Timeout=New-TimeSpan -Seconds 15;$conn.Bind();Show BIND "$Protocol bind succeeded." Green
$root=Search $conn '' '(objectClass=*)' ([System.DirectoryServices.Protocols.SearchScope]::Base) @('defaultNamingContext','namingContexts');if($root.Entries.Count -lt 1){throw 'RootDseReturnedNoEntries'};$attrs=$root.Entries[0].Attributes;$defaultNcAttribute=$attrs['defaultNamingContext'];if($null-eq$defaultNcAttribute){throw 'DefaultNamingContextAttributeMissing'};$defaultNcValues=[string[]]$defaultNcAttribute.GetValues([string]);if(@($defaultNcValues).Count -lt 1 -or [string]::IsNullOrWhiteSpace([string]$defaultNcValues[0])){throw 'DefaultNamingContextUnavailable'};$domainNc=[string]$defaultNcValues[0];if($domainNc -notmatch '^DC='){throw "DefaultNamingContextInvalid: $domainNc"};$domainName=DnToDns $domainNc;Show DISCOVERY "defaultNamingContext=$domainNc; derived zone=$domainName" Green
$bases=@("CN=MicrosoftDNS,DC=DomainDnsZones,$domainNc","CN=MicrosoftDNS,DC=ForestDnsZones,$domainNc","CN=MicrosoftDNS,CN=System,$domainNc")
$zones=New-Object 'Collections.Generic.List[object]';foreach($base in $bases){try{$res=Search $conn $base '(objectClass=dnsZone)' ([System.DirectoryServices.Protocols.SearchScope]::Subtree) @('name','dc','distinguishedName');foreach($e in $res.Entries){$n=GetAttr $e.Attributes 'name';if(-not$n){$n=GetAttr $e.Attributes 'dc'};$zones.Add([pscustomobject][ordered]@{Name=if($n){[string]$n[0]}else{$null};DistinguishedName=$e.DistinguishedName;Partition=$base;Server=$Server;Protocol=$Protocol;Port=$Port})}}catch{Show WARNING "Zone search unavailable at $base`: $($_.Exception.Message)" DarkYellow}}
$zoneRows=[object[]]$zones.ToArray();WriteJson $ZonesPath $zoneRows
$RequestedZone = if ($Zone) { $Zone } else { $domainName }
$selected = @($zoneRows | Where-Object { $_.Name -eq $RequestedZone } | Select-Object -First 1)
$CurrentIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
$IdentityGroups=New-Object 'Collections.Generic.List[object]'
foreach($GroupSid in @($CurrentIdentity.Groups)){
 try{$Resolved=$GroupSid.Translate([Security.Principal.NTAccount]).Value}catch{$Resolved=$GroupSid.Value}
 $IdentityGroups.Add([pscustomobject][ordered]@{Sid=$GroupSid.Value;Name=$Resolved})
}
$PrivilegedPatterns=@('Domain Admins','Enterprise Admins','Administrators','DNSAdmins','Schema Admins','Account Operators','Server Operators')
$PrivilegedMemberships=@($IdentityGroups.ToArray()|Where-Object{$n=[string]$_.Name;@($PrivilegedPatterns|Where-Object{$n -like "*\\$_"}).Count-gt0})
$Authorization=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleVersion=$Version;TestedIdentity=$CurrentIdentity.Name;IdentitySid=$CurrentIdentity.User.Value;GroupCount=$IdentityGroups.Count;Groups=[object[]]$IdentityGroups.ToArray();PrivilegedGroupMemberships=$PrivilegedMemberships;Zone=$RequestedZone;ZoneDistinguishedName=$null;AclReadSucceeded=$false;Owner=$null;EffectiveWriteAces=@();BroadPrincipalWriteDetected=$false;AuthorizationBreadth='Unknown';AuthorizationIntent='Unknown';Limitation='ACL correlation explains candidate authorization. Behavioral create-read-resolve-delete verification remains authoritative.'}
if($selected.Count-gt0){
 $Authorization.ZoneDistinguishedName=$selected[0].DistinguishedName
 try{
  $ZoneLdapPath="LDAP://$Server/$($selected[0].DistinguishedName)"
  $ZoneEntry=New-Object System.DirectoryServices.DirectoryEntry($ZoneLdapPath)
  if($null-ne$Credential){
   $NetworkCredential=$Credential.GetNetworkCredential()
   $ZoneEntry.Username=$Credential.UserName
   $ZoneEntry.Password=$NetworkCredential.Password
  }
  $null=$ZoneEntry.NativeObject
  $ZoneSecurity=$ZoneEntry.ObjectSecurity
  $Authorization.AclReadSucceeded=$true
  $Authorization.Owner=[string]$ZoneSecurity.GetOwner([Security.Principal.NTAccount])
  $GroupNames=@($IdentityGroups.ToArray()|ForEach-Object{[string]$_.Name})+@($CurrentIdentity.Name)
  $Applicable=New-Object 'Collections.Generic.List[object]'
  $Rules=$ZoneSecurity.GetAccessRules($true,$true,[Security.Principal.NTAccount])
  foreach($Ace in @($Rules)){
   $Trustee=[string]$Ace.IdentityReference
   if($Trustee -in $GroupNames -and [string]$Ace.AccessControlType -eq 'Allow' -and ([string]$Ace.ActiveDirectoryRights -match 'CreateChild|GenericAll|GenericWrite|WriteDacl|WriteOwner')){
    $Applicable.Add([pscustomobject][ordered]@{Trustee=$Trustee;Rights=[string]$Ace.ActiveDirectoryRights;AccessControlType=[string]$Ace.AccessControlType;IsInherited=[bool]$Ace.IsInherited;ObjectType=[string]$Ace.ObjectType;InheritedObjectType=[string]$Ace.InheritedObjectType})
   }
  }
  $ZoneEntry.Dispose()
  $Authorization.EffectiveWriteAces=[object[]]$Applicable.ToArray()
  $Broad=@($Applicable.ToArray()|Where-Object{$_.Trustee -match 'Authenticated Users|Domain Users|Everyone'})
  $Authorization.BroadPrincipalWriteDetected=($Broad.Count-gt0)
  $Authorization.AuthorizationBreadth=if($Authorization.BroadPrincipalWriteDetected){'BroadAuthenticatedPopulation'}elseif($Applicable.Count-gt0){'IndividualOrDelegatedGroup'}elseif($PrivilegedMemberships.Count-gt0){'PrivilegedContextWithoutMatchedZoneAce'}else{'NoApplicableWriteAceResolved'}
 }catch{$Authorization.AuthorizationBreadth='AclUnavailable';$Authorization|Add-Member -NotePropertyName AclError -NotePropertyValue $_.Exception.Message -Force}
}
WriteJson $AuthorizationPath $Authorization
WriteJson $InventoryPath $zoneRows
WriteJson $CandidatesPath @()

$validation=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleVersion=$Version;Server=$Server;Port=$Port;Protocol=$Protocol;Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;ZoneRequested=if($Zone){$Zone}else{$domainName};ZoneDistinguishedName=$null;RecordFqdn=$null;WriteAttempted=$false;WriteSucceeded=$false;ReadbackSucceeded=$false;RecordMatched=$false;CleanupAttempted=$false;CleanupSucceeded=$false;CleanupVerified=$false;ImpactReproduced=$false;Disposition='NotApplicable';Error=$null}
if($selected.Count-eq0){$validation.Disposition='Inconclusive';$validation.Error='RequestedZoneNotFound'}else{$z=$selected[0];$validation.ZoneDistinguishedName=$z.DistinguishedName;if($EnableBehavioralValidation){$label='_msadpt-'+[guid]::NewGuid().ToString('N').Substring(0,12);$dn="DC=$label,$($z.DistinguishedName)";$validation.RecordFqdn="$label.$($z.Name)";$validation.WriteAttempted=$true;Show WRITE "Create temporary dnsNode $($validation.RecordFqdn) -> $RecordIp" Yellow;try{$serial=0;$soa=Search $conn "DC=@,$($z.DistinguishedName)" '(objectClass=dnsNode)' ([System.DirectoryServices.Protocols.SearchScope]::Base) @('dnsRecord');$records=GetAttr $soa.Entries[0].Attributes 'dnsRecord';if($records-and([byte[]]$records[0]).Length-ge12){$serial=[BitConverter]::ToUInt32(([byte[]]$records[0])[8..11],0)};$blob=NewARecord $RecordIp $serial;$add=New-Object System.DirectoryServices.Protocols.AddRequest($dn);$objectClassAttribute=New-Object System.DirectoryServices.Protocols.DirectoryAttribute;$objectClassAttribute.Name='objectClass';$null=$objectClassAttribute.Add('top');$null=$objectClassAttribute.Add('dnsNode');$add.Attributes.Add($objectClassAttribute)|Out-Null;foreach($pair in @(@('dc',$label),@('name',$label))){$a=New-Object System.DirectoryServices.Protocols.DirectoryAttribute;$a.Name=[string]$pair[0];$null=$a.Add([string]$pair[1]);$add.Attributes.Add($a)|Out-Null};$a=New-Object System.DirectoryServices.Protocols.DirectoryAttribute;$a.Name='dnsRecord';$null=$a.Add([byte[]]$blob);$add.Attributes.Add($a)|Out-Null;$null=$conn.SendRequest($add);$validation.WriteSucceeded=$true;$read=Search $conn $dn '(objectClass=dnsNode)' ([System.DirectoryServices.Protocols.SearchScope]::Base) @('dc','dnsRecord','objectClass');if($read.Entries.Count-eq1){$validation.ReadbackSucceeded=$true;$dc=GetAttr $read.Entries[0].Attributes 'dc';$rr=GetAttr $read.Entries[0].Attributes 'dnsRecord';$validation.RecordMatched=($dc-and[string]$dc[0]-eq$label-and$rr);if($validation.RecordMatched){try{$resolved=@([Net.Dns]::GetHostAddresses($validation.RecordFqdn)|ForEach-Object{$_.IPAddressToString});$resolution=[pscustomobject][ordered]@{RecordFqdn=$validation.RecordFqdn;ExpectedAddress=$RecordIp;ResolvedAddresses=$resolved;ResolutionSucceeded=($resolved.Count-gt0);ExpectedAddressObserved=($RecordIp -in $resolved);ValidatedUtc=(Get-Date).ToUniversalTime().ToString('o')};WriteJson $ResolutionPath $resolution}catch{WriteJson $ResolutionPath ([pscustomobject]@{RecordFqdn=$validation.RecordFqdn;ExpectedAddress=$RecordIp;ResolutionSucceeded=$false;ExpectedAddressObserved=$false;Error=$_.Exception.Message})}}};$validation.Disposition=if($validation.RecordMatched){'BehaviorallyValidated'}else{'Inconclusive'}}catch [System.DirectoryServices.Protocols.DirectoryOperationException]{$validation.Error=$_.Exception.Message;$validation.Disposition=if($_.Exception.Response.ResultCode-eq[System.DirectoryServices.Protocols.ResultCode]::InsufficientAccessRights){'NotDetected'}else{'Inconclusive'}}catch{$validation.Error=$_.Exception.Message;$validation.Disposition='Inconclusive'}finally{if($validation.WriteSucceeded){$validation.CleanupAttempted=$true;Show CLEANUP "Delete only $($validation.RecordFqdn), then verify absence" Yellow;try{$null=$conn.SendRequest((New-Object System.DirectoryServices.Protocols.DeleteRequest($dn)));$validation.CleanupSucceeded=$true;Show CLEANUP 'Delete request succeeded; verifying object absence.' Green;try{$null=Search $conn $dn '(objectClass=*)' ([System.DirectoryServices.Protocols.SearchScope]::Base) @('distinguishedName');$validation.CleanupVerified=$false}catch [System.DirectoryServices.Protocols.DirectoryOperationException]{$validation.CleanupVerified=($_.Exception.Response.ResultCode-eq[System.DirectoryServices.Protocols.ResultCode]::NoSuchObject);if($validation.CleanupVerified){Show CLEANUP 'Generated dnsNode is absent after deletion.' Green}}}catch{$validation.Error="CleanupFailed: $($_.Exception.Message)";$validation.Disposition='Inconclusive'}}};if($validation.WriteSucceeded-and$validation.RecordMatched-and$validation.CleanupVerified){$validation.Disposition='BehaviorallyValidated';Show RESULT 'Controlled DNS write reproduced and cleanup verified.' Green}elseif($validation.WriteSucceeded-and-not$validation.CleanupVerified){$validation.Disposition='Inconclusive';Show WARNING 'DNS write occurred but cleanup could not be verified.' Red}}else{$validation.Disposition='CandidateDetected'}}
WriteJson $ValidationPath $validation;$cleanup=[pscustomobject][ordered]@{RecordFqdn=$validation.RecordFqdn;Attempted=$validation.CleanupAttempted;Succeeded=$validation.CleanupSucceeded;Verified=$validation.CleanupVerified;ManualCleanupRequired=($validation.WriteSucceeded-and-not$validation.CleanupVerified)};WriteJson $CleanupPath $cleanup
$summary=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleVersion=$Version;Status='Completed';Disposition=$validation.Disposition;Server=$Server;Port=$Port;Protocol=$Protocol;ZoneCount=$zoneRows.Count;BehavioralValidationEnabled=[bool]$EnableBehavioralValidation;WriteSucceeded=$validation.WriteSucceeded;ReadbackSucceeded=$validation.ReadbackSucceeded;CleanupVerified=$validation.CleanupVerified;ImpactReproduced=$false;Limitation='DNS write capability does not prove relay, credential capture, privilege escalation, or domain compromise.';ZonesPath=$ZonesPath;ValidationPath=$ValidationPath;CleanupPath=$CleanupPath;AuthorizationPath=$AuthorizationPath;ResolutionPath=$ResolutionPath;InventoryPath=$InventoryPath;CandidatesPath=$CandidatesPath;AuthorizationBreadth=$Authorization.AuthorizationBreadth;BroadPrincipalWriteDetected=$Authorization.BroadPrincipalWriteDetected};WriteJson $SummaryPath $summary;$summary
