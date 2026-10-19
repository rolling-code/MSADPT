<#
.SYNOPSIS
Collects read-only privileged and sensitive group membership paths, principal posture, group ACLs, AdminSDHolder ACLs, and adminCount evidence.
.NOTES
Version: 1.0.3
No directory writes, membership changes, password operations, ticket requests, or secret collection.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter(Mandatory=$true)][string]$Server,
    [switch]$PlanOnly
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Version='1.0.3'
function FullPath([string]$Path){if([IO.Path]::IsPathRooted($Path)){return [IO.Path]::GetFullPath($Path)};[IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))}
function SaveJson([object]$Value,[string]$Path,[int]$Depth=16){ConvertTo-Json -InputObject $Value -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8}
function AddErr([string]$Stage,[string]$Target,[Management.Automation.ErrorRecord]$E){$script:Errors.Add([pscustomobject][ordered]@{Stage=$Stage;Target=$Target;Message=$E.Exception.Message;ExceptionType=$E.Exception.GetType().FullName;FullyQualifiedErrorId=$E.FullyQualifiedErrorId;RecordedUtc=(Get-Date).ToUniversalTime().ToString('o')})}
function Sid($V){if($null-eq$V){return $null};try{[string]$V.Value}catch{[string]$V}}
function ObjRec($O){
 [pscustomobject][ordered]@{Name=[string]$O.Name;SamAccountName=[string]$O.sAMAccountName;DistinguishedName=[string]$O.DistinguishedName;ObjectClass=[string]$O.ObjectClass;ObjectSid=Sid $O.objectSid;Enabled=if($null-ne$O.enabled){[bool]$O.enabled}else{$null};AdminCount=$O.adminCount;ProtectedObjectIndicatorObserved=($O.adminCount-eq 1);PasswordNeverExpires=if($O.PSObject.Properties['PasswordNeverExpires']){[bool]$O.PasswordNeverExpires}else{$null};PasswordLastSet=$O.PasswordLastSet;LastLogonDate=$O.LastLogonDate;WhenCreated=$O.whenCreated;WhenChanged=$O.whenChanged;SidHistory=@($O.sIDHistory|ForEach-Object{Sid $_});AuthenticationPolicy=[string]$O.'msDS-AssignedAuthNPolicy';AuthenticationPolicySilo=[string]$O.'msDS-AssignedAuthNPolicySilo'}
}
function AclRows([string]$Type,[string]$Name,[string]$Dn){$A=Get-Acl -LiteralPath ('AD:\'+$Dn) -ErrorAction Stop;@($A.Access|ForEach-Object{[pscustomobject][ordered]@{TargetType=$Type;TargetName=$Name;TargetDistinguishedName=$Dn;Owner=[string]$A.Owner;Trustee=[string]$_.IdentityReference;AccessControlType=[string]$_.AccessControlType;ActiveDirectoryRights=[string]$_.ActiveDirectoryRights;ObjectTypeGuid=[string]$_.ObjectType;InheritedObjectTypeGuid=[string]$_.InheritedObjectType;IsInherited=[bool]$_.IsInherited;InheritanceType=[string]$_.InheritanceType}})}
$OutputRoot=FullPath $OutputRoot
$Plan=@(
 [pscustomobject]@{Target=$Server;Protocol='ADWS';Ports='9389 TCP';Operation='Resolve privileged and sensitive groups by well-known SID and explicit name'},
 [pscustomobject]@{Target=$Server;Protocol='ADWS';Ports='9389 TCP';Operation='Collect direct membership and preserve recursive membership paths'},
 [pscustomobject]@{Target=$Server;Protocol='ADWS / AD provider';Ports='9389 TCP';Operation='Read group and AdminSDHolder ACLs'},
 [pscustomobject]@{Target=$Server;Protocol='ADWS';Ports='9389 TCP';Operation='Collect effective privileged-principal posture and adminCount inventory'}
)
Write-Host "`n=== MSADPT privileged group path collection ===" -ForegroundColor Cyan
$Plan|Format-Table -AutoSize -Wrap
Write-Host "`nOutput directory : $OutputRoot"
Write-Host 'Directory writes  : None' -ForegroundColor Green
Write-Host 'Membership changes: None' -ForegroundColor Green
Write-Host 'Passwords/secrets : Not requested' -ForegroundColor Green
if($PlanOnly){return [pscustomobject][ordered]@{Status='Planned';Version=$Version;Server=$Server;Plan=$Plan;NetworkExecuted=$false;DirectoryChanges='None';OutputRoot=$OutputRoot}}
if(-not(Get-Module -ListAvailable ActiveDirectory)){throw 'ActiveDirectoryModuleMissing'}
Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null;$Raw=Join-Path $OutputRoot 'Raw';New-Item -ItemType Directory -Path $Raw -Force|Out-Null
$script:Errors=[Collections.Generic.List[object]]::new();$Started=(Get-Date).ToUniversalTime();$Domain=Get-ADDomain -Server $Server -ErrorAction Stop;$Forest=Get-ADForest -Server $Server -ErrorAction Stop
$RootSid=[string]$Domain.DomainSID
$Specs=@(
 @{Name='Administrators';Sid='S-1-5-32-544'},@{Name='Account Operators';Sid='S-1-5-32-548'},@{Name='Server Operators';Sid='S-1-5-32-549'},@{Name='Print Operators';Sid='S-1-5-32-550'},@{Name='Backup Operators';Sid='S-1-5-32-551'},
 @{Name='Domain Admins';Sid="$RootSid-512"},@{Name='Schema Admins';Sid="$RootSid-518"},@{Name='Enterprise Admins';Sid="$RootSid-519"},@{Name='Group Policy Creator Owners';Sid="$RootSid-520"},@{Name='Protected Users';Sid="$RootSid-525"},@{Name='Key Admins';Sid="$RootSid-526"},@{Name='Enterprise Key Admins';Sid="$RootSid-527"},
 @{Name='DNSAdmins';Sid=$null},@{Name='Incoming Forest Trust Builders';Sid=$null}
)
$Groups=[Collections.Generic.List[object]]::new();$GroupObjects=[Collections.Generic.List[object]]::new()
foreach($S in $Specs){try{$G=if($S.ContainsKey('Sid') -and -not [string]::IsNullOrWhiteSpace([string]$S['Sid'])){Get-ADGroup -Identity $S.Sid -Server $Server -Properties objectSid,adminCount,isCriticalSystemObject,groupCategory,groupScope,member,whenCreated,whenChanged -ErrorAction Stop}else{Get-ADGroup -Identity $S.Name -Server $Server -Properties objectSid,adminCount,isCriticalSystemObject,groupCategory,groupScope,member,whenCreated,whenChanged -ErrorAction Stop};$GroupObjects.Add($G);$Groups.Add([pscustomobject][ordered]@{Name=$G.Name;SamAccountName=$G.SamAccountName;DistinguishedName=$G.DistinguishedName;ObjectSid=Sid $G.objectSid;AdminCount=$G.adminCount;IsCriticalSystemObject=[bool]$G.isCriticalSystemObject;GroupCategory=[string]$G.GroupCategory;GroupScope=[string]$G.GroupScope;DirectMemberCount=@($G.member).Count;WhenCreated=$G.whenCreated;WhenChanged=$G.whenChanged})}catch{AddErr 'ResolveSensitiveGroup' $S.Name $_}}
# Add environment-specific Tier 0 groups without relying only on names for privilege conclusions.
try{foreach($G in @(Get-ADGroup -LDAPFilter '(|(name=*Tier0*)(name=*Tier 0*)(name=*T0*)(description=*Tier 0*))' -Server $Server -Properties objectSid,adminCount,isCriticalSystemObject,groupCategory,groupScope,member,whenCreated,whenChanged -ErrorAction Stop)){if(-not($GroupObjects.DistinguishedName -contains $G.DistinguishedName)){$GroupObjects.Add($G);$Groups.Add([pscustomobject][ordered]@{Name=$G.Name;SamAccountName=$G.SamAccountName;DistinguishedName=$G.DistinguishedName;ObjectSid=Sid $G.objectSid;AdminCount=$G.adminCount;IsCriticalSystemObject=[bool]$G.isCriticalSystemObject;GroupCategory=[string]$G.GroupCategory;GroupScope=[string]$G.GroupScope;DirectMemberCount=@($G.member).Count;WhenCreated=$G.whenCreated;WhenChanged=$G.whenChanged})}}}catch{AddErr 'DiscoverNamedTierGroups' $Domain.DistinguishedName $_}
$Direct=[Collections.Generic.List[object]]::new();$Paths=[Collections.Generic.List[object]]::new();$Principals=@{};$VisitedEdges=[Collections.Generic.HashSet[string]]::new()
function Walk([object]$Root,[object]$Current,[string[]]$Path,[int]$Depth){
 if($Depth-gt 32){AddErr 'MembershipDepthLimit' $Current.DistinguishedName ([Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Maximum membership depth exceeded.'),'MembershipDepthLimit',[Management.Automation.ErrorCategory]::LimitsExceeded,$Current.DistinguishedName));return}
 $MemberDns=@($Current.member)
 foreach($MemberDn in $MemberDns){
  $Edge=$Current.DistinguishedName+'|'+$MemberDn
  if(-not$VisitedEdges.Add($Root.DistinguishedName+'|'+$Edge)){continue}
  $O=$null
  try{
   $Candidates=@(Get-ADObject -LDAPFilter '(objectClass=*)' -SearchBase $MemberDn -SearchScope Base -Server $Server -Properties objectSid,sAMAccountName,objectClass,enabled,adminCount,userAccountControl,pwdLastSet,lastLogonTimestamp,whenCreated,whenChanged,sIDHistory,msDS-AssignedAuthNPolicy,msDS-AssignedAuthNPolicySilo,member -ResultSetSize 2 -ErrorAction Stop)
   if($Candidates.Count -eq 0){throw 'Directory object not found by exact-base search.'}
   if($Candidates.Count -gt 1){throw 'Multiple directory objects returned by exact-base search.'}
   $O=$Candidates[0]
  }catch{AddErr 'ResolveMember' $MemberDn $_;continue}
  $R=ObjRec $O
  $Direct.Add([pscustomobject][ordered]@{RootGroup=$Root.Name;ParentGroup=$Current.Name;Depth=$Depth;MemberName=$R.Name;MemberSamAccountName=$R.SamAccountName;MemberDistinguishedName=$R.DistinguishedName;MemberObjectClass=$R.ObjectClass;MemberObjectSid=$R.ObjectSid})
  $NewPath=@($Path+$R.DistinguishedName)
  $Paths.Add([pscustomobject][ordered]@{RootGroup=$Root.Name;RootGroupDistinguishedName=$Root.DistinguishedName;LeafName=$R.Name;LeafSamAccountName=$R.SamAccountName;LeafDistinguishedName=$R.DistinguishedName;LeafObjectClass=$R.ObjectClass;LeafObjectSid=$R.ObjectSid;Depth=$Depth;PathDistinguishedNames=$NewPath;PathText=($NewPath-join ' -> ')})
  if($R.ObjectSid){$Principals[$R.ObjectSid]=$R}
  if($R.ObjectClass-eq'group'){Walk $Root $O $NewPath ($Depth+1)}
 }
}
foreach($G in $GroupObjects){Walk $G $G @($G.DistinguishedName) 1}
$Acls=[Collections.Generic.List[object]]::new();foreach($G in $GroupObjects){try{foreach($R in @(AclRows 'SensitiveGroup' $G.Name $G.DistinguishedName)){$Acls.Add($R)}}catch{AddErr 'SensitiveGroupAcl' $G.DistinguishedName $_}}
$AdminSdDn='CN=AdminSDHolder,CN=System,'+$Domain.DistinguishedName;$AdminSdAcl=@();try{$AdminSdAcl=@(AclRows 'AdminSDHolder' 'AdminSDHolder' $AdminSdDn)}catch{AddErr 'AdminSDHolderAcl' $AdminSdDn $_}
$AdminCount=@();try{$AdminCount=@(Get-ADObject -LDAPFilter '(adminCount=1)' -SearchBase $Domain.DistinguishedName -Server $Server -Properties objectSid,sAMAccountName,objectClass,enabled,adminCount,userAccountControl,pwdLastSet,lastLogonTimestamp,whenCreated,whenChanged,sIDHistory,msDS-AssignedAuthNPolicy,msDS-AssignedAuthNPolicySilo,member -ErrorAction Stop|ForEach-Object{ObjRec $_})}catch{AddErr 'AdminCountInventory' $Domain.DistinguishedName $_}
$ProtectedUsers=@($Paths|Where-Object{$_.RootGroup-eq'Protected Users'});$Effective=@($Principals.Values|Sort-Object DistinguishedName -Unique)
$Files=[ordered]@{'sensitive-groups.json'=@($Groups);'direct-memberships.json'=@($Direct);'membership-paths.json'=@($Paths);'effective-privileged-principals.json'=@($Effective);'sensitive-group-acls.json'=@($Acls);'adminsdholder-acl.json'=@($AdminSdAcl);'admincount-objects.json'=@($AdminCount);'protected-users-paths.json'=@($ProtectedUsers);'operational-errors.json'=@($script:Errors);'collection-plan.json'=$Plan}
foreach($N in $Files.Keys){SaveJson $Files[$N] (Join-Path $Raw $N)}
$Completed=(Get-Date).ToUniversalTime();$Evidence=@(Get-ChildItem $Raw -File|ForEach-Object{[pscustomobject]@{RelativePath=[IO.Path]::GetRelativePath($OutputRoot,$_.FullName);Length=$_.Length;SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash}})
$Manifest=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleId='Collect-MSADPTPrivilegedGroupPaths';ModuleVersion=$Version;StartedUtc=$Started.ToString('o');CompletedUtc=$Completed.ToString('o');Server=$Server;SensitiveGroupCount=$Groups.Count;DirectMembershipCount=$Direct.Count;MembershipPathCount=$Paths.Count;EffectivePrivilegedPrincipalCount=$Effective.Count;SensitiveGroupAclCount=$Acls.Count;AdminSdHolderAclCount=$AdminSdAcl.Count;AdminCountObjectCount=$AdminCount.Count;ProtectedUsersPathCount=$ProtectedUsers.Count;OperationalErrorCount=$script:Errors.Count;DirectoryChanges='None';MembershipChanges=0;SecretsCollected=0;Files=$Evidence}
$ManifestPath=Join-Path $OutputRoot 'evidence-manifest.json';SaveJson $Manifest $ManifestPath
$Status=if($script:Errors.Count){'Partial'}else{'Completed'};Write-Host "[$(if($Status-eq'Completed'){'PASS'}else{'WARN'})] Collection complete: $OutputRoot" -ForegroundColor $(if($Status-eq'Completed'){'Green'}else{'Yellow'})
[pscustomobject][ordered]@{Status=$Status;Version=$Version;OutputRoot=$OutputRoot;Server=$Server;SensitiveGroupCount=$Groups.Count;DirectMembershipCount=$Direct.Count;MembershipPathCount=$Paths.Count;EffectivePrivilegedPrincipalCount=$Effective.Count;SensitiveGroupAclCount=$Acls.Count;AdminSdHolderAclCount=$AdminSdAcl.Count;AdminCountObjectCount=$AdminCount.Count;ProtectedUsersPathCount=$ProtectedUsers.Count;OperationalErrorCount=$script:Errors.Count;DirectoryChanges='None';MembershipChanges=0;ManifestPath=$ManifestPath}
