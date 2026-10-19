<#
.SYNOPSIS
Collects read-only Active Directory trust-security evidence.
.NOTES
Version: 1.0.1
No trust validation, password reset, ticket request, remote-domain enumeration, or directory write is performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputRoot,
    [Parameter(Mandatory)][string]$Server,
    [switch]$PlanOnly
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.1'
function FullPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}
function SaveJson([object]$Value,[string]$Path,[int]$Depth=12) {
    ConvertTo-Json -InputObject $Value -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
}
function AddError([string]$Stage,[string]$Target,[Management.Automation.ErrorRecord]$Record) {
    $script:Errors.Add([pscustomobject][ordered]@{Stage=$Stage;Target=$Target;Message=$Record.Exception.Message;ExceptionType=$Record.Exception.GetType().FullName;FullyQualifiedErrorId=$Record.FullyQualifiedErrorId;RecordedUtc=(Get-Date).ToUniversalTime().ToString('o')})
}
function SidText($Value) {
    if ($null -eq $Value) { return $null }
    try { return [string]$Value.Value } catch { return [string]$Value }
}
function FlagNames([int64]$Value) {
    $Map=[ordered]@{
        NON_TRANSITIVE=0x1;UPLEVEL_ONLY=0x2;QUARANTINED_DOMAIN=0x4;FOREST_TRANSITIVE=0x8;
        CROSS_ORGANIZATION=0x10;WITHIN_FOREST=0x20;TREAT_AS_EXTERNAL=0x40;USES_RC4_ENCRYPTION=0x80;
        CROSS_ORGANIZATION_NO_TGT_DELEGATION=0x200;PIM_TRUST=0x400
    }
    @($Map.Keys | Where-Object { ($Value -band $Map[$_]) -ne 0 })
}
$OutputRoot=FullPath $OutputRoot
$Plan=@(
 [pscustomobject]@{Target=$Server;Protocol='ADWS';Ports='9389 TCP';Operation='Read domain/forest metadata and trustedDomain objects'},
 [pscustomobject]@{Target=$Server;Protocol='ADWS / AD provider';Ports='9389 TCP';Operation='Read trust-object ACLs'},
 [pscustomobject]@{Target=$Server;Protocol='ADWS';Ports='9389 TCP';Operation='Read SIDHistory-bearing principals and ForeignSecurityPrincipals'},
 [pscustomobject]@{Target=$Server;Protocol='Local nltest';Ports='No additional declared target';Operation='Capture local trust and domain-controller discovery output'}
)
Write-Host "`n=== MSADPT AD trust-security collection ===" -ForegroundColor Cyan
$Plan | Format-Table -AutoSize -Wrap
Write-Host "`nOutput directory : $OutputRoot"
Write-Host 'Directory writes : None' -ForegroundColor Green
Write-Host 'Trust validation : Not performed' -ForegroundColor Green
Write-Host 'Remote enumeration: Not performed' -ForegroundColor Green
Write-Host 'Tickets/secrets  : Not requested' -ForegroundColor Green
if($PlanOnly){return [pscustomobject]@{Status='Planned';Version=$Version;Server=$Server;Plan=$Plan;NetworkExecuted=$false;DirectoryChanges='None';OutputRoot=$OutputRoot}}
if(-not(Get-Module -ListAvailable ActiveDirectory)){throw 'ActiveDirectoryModuleMissing'}
Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
$Raw=Join-Path $OutputRoot 'Raw';New-Item -ItemType Directory -Path $Raw -Force|Out-Null
$script:Errors=[Collections.Generic.List[object]]::new();$Started=(Get-Date).ToUniversalTime()
$Domain=$null;$Forest=$null;$Trusts=@();$TrustObjects=@();$TrustAcls=[Collections.Generic.List[object]]::new();$SidHistory=@();$Fsps=@();$Nltest=[Collections.Generic.List[object]]::new()
try{$Domain=Get-ADDomain -Server $Server -ErrorAction Stop}catch{AddError 'DomainMetadata' $Server $_}
try{$Forest=Get-ADForest -Server $Server -ErrorAction Stop}catch{AddError 'ForestMetadata' $Server $_}
try{
 $Trusts=@(Get-ADTrust -Filter * -Server $Server -Properties * -ErrorAction Stop|ForEach-Object{
  [pscustomobject][ordered]@{Name=$_.Name;Source=$_.Source;Target=$_.Target;Direction=[string]$_.Direction;TrustType=[string]$_.TrustType;ForestTransitive=[bool]$_.ForestTransitive;IntraForest=[bool]$_.IntraForest;SelectiveAuthentication=[bool]$_.SelectiveAuthentication;SIDFilteringForestAware=[bool]$_.SIDFilteringForestAware;SIDFilteringQuarantined=[bool]$_.SIDFilteringQuarantined;TGTDelegation=[bool]$_.TGTDelegation;DistinguishedName=$_.DistinguishedName;ObjectGuid=[string]$_.ObjectGuid;WhenCreated=$_.whenCreated;WhenChanged=$_.whenChanged}
 })
}catch{AddError 'GetADTrust' $Server $_}
if($Domain){
 try{
  $TrustObjects=@(Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase $Domain.DistinguishedName -Server $Server -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,msDS-TrustForestTrustInfo,whenCreated,whenChanged -ErrorAction Stop|ForEach-Object{
   $a=[int64]($_.trustAttributes);[pscustomobject][ordered]@{Name=$_.Name;DistinguishedName=$_.DistinguishedName;FlatName=$_.flatName;SecurityIdentifier=SidText $_.securityIdentifier;TrustDirection=[int]$_.trustDirection;TrustType=[int]$_.trustType;TrustAttributes=$a;TrustAttributeFlags=FlagNames $a;ForestTrustInfoPresent=($null-ne $_.'msDS-TrustForestTrustInfo');ForestTrustInfoLength=if($_.'msDS-TrustForestTrustInfo'){@($_.'msDS-TrustForestTrustInfo').Count}else{0};WhenCreated=$_.whenCreated;WhenChanged=$_.whenChanged}
  })
 }catch{AddError 'TrustedDomainObjects' $Domain.DistinguishedName $_}
 foreach($t in $TrustObjects){try{$acl=Get-Acl -LiteralPath ('AD:\'+$t.DistinguishedName) -ErrorAction Stop;foreach($r in $acl.Access){$TrustAcls.Add([pscustomobject][ordered]@{TrustName=$t.Name;TargetDistinguishedName=$t.DistinguishedName;Owner=[string]$acl.Owner;IdentityReference=[string]$r.IdentityReference;AccessControlType=[string]$r.AccessControlType;ActiveDirectoryRights=[string]$r.ActiveDirectoryRights;ObjectTypeGuid=[string]$r.ObjectType;InheritedObjectTypeGuid=[string]$r.InheritedObjectType;IsInherited=[bool]$r.IsInherited;InheritanceType=[string]$r.InheritanceType})}}catch{AddError 'TrustObjectAcl' $t.DistinguishedName $_}}
 try{$SidHistory=@(Get-ADObject -LDAPFilter '(sIDHistory=*)' -SearchBase $Domain.DistinguishedName -Server $Server -Properties objectSid,sIDHistory,sAMAccountName,objectClass,enabled,whenChanged -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;SamAccountName=$_.sAMAccountName;DistinguishedName=$_.DistinguishedName;ObjectClass=[string]$_.ObjectClass;ObjectSid=SidText $_.objectSid;SidHistory=@($_.sIDHistory|ForEach-Object{SidText $_});Enabled=if($null-ne $_.enabled){[bool]$_.enabled}else{$null};WhenChanged=$_.whenChanged}})}catch{AddError 'SidHistory' $Domain.DistinguishedName $_}
 try{$fspBase='CN=ForeignSecurityPrincipals,'+$Domain.DistinguishedName;$Fsps=@(Get-ADObject -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -SearchBase $fspBase -Server $Server -Properties objectSid,memberOf,whenCreated,whenChanged -ErrorAction Stop|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;DistinguishedName=$_.DistinguishedName;ObjectSid=SidText $_.objectSid;MemberOf=@($_.memberOf);WhenCreated=$_.whenCreated;WhenChanged=$_.whenChanged}})}catch{AddError 'ForeignSecurityPrincipals' $Domain.DistinguishedName $_}
}
foreach($args in @(@('/domain_trusts'),@('/trusted_domains'),@('/dsgetdc:'+$Domain.DNSRoot))){try{$o=& nltest.exe @args 2>&1;$Nltest.Add([pscustomobject]@{Arguments=($args-join ' ');ExitCode=$LASTEXITCODE;Output=@($o|ForEach-Object{[string]$_})})}catch{AddError 'Nltest' ($args-join ' ') $_}}
$Context=[pscustomobject][ordered]@{
 Version=$Version;Server=$Server
 Domain=if($Domain){[pscustomobject][ordered]@{DNSRoot=$Domain.DNSRoot;DistinguishedName=$Domain.DistinguishedName;NetBIOSName=$Domain.NetBIOSName;DomainMode=[string]$Domain.DomainMode;DomainSID=[string]$Domain.DomainSID;PDCEmulator=$Domain.PDCEmulator;RIDMaster=$Domain.RIDMaster;InfrastructureMaster=$Domain.InfrastructureMaster}}else{$null}
 Forest=if($Forest){[pscustomobject][ordered]@{Name=$Forest.Name;RootDomain=$Forest.RootDomain;ForestMode=[string]$Forest.ForestMode;Domains=@($Forest.Domains);CrossForestReferences=@($Forest.CrossForestReferences);UPNSuffixes=@($Forest.UPNSuffixes);SPNSuffixes=@($Forest.SPNSuffixes);DomainNamingMaster=$Forest.DomainNamingMaster;SchemaMaster=$Forest.SchemaMaster}}else{$null}
 DirectoryChanges='None';RemoteTrustValidation=$false;TicketsRequested=0;SecretsCollected=0
}
$Files=[ordered]@{'trust-context.json'=$Context;'ad-trusts.json'=@($Trusts);'trusted-domain-objects.json'=@($TrustObjects);'trusted-domain-acls.json'=@($TrustAcls);'sid-history-principals.json'=@($SidHistory);'foreign-security-principals.json'=@($Fsps);'nltest-output.json'=@($Nltest);'operational-errors.json'=@($script:Errors);'collection-plan.json'=$Plan}
foreach($n in $Files.Keys){SaveJson $Files[$n] (Join-Path $Raw $n)}
$Completed=(Get-Date).ToUniversalTime();$Evidence=@(Get-ChildItem $Raw -File|ForEach-Object{[pscustomobject]@{RelativePath=[IO.Path]::GetRelativePath($OutputRoot,$_.FullName);Length=$_.Length;SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash}})
$Manifest=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleId='Collect-MSADPTADTrustSecurity';ModuleVersion=$Version;StartedUtc=$Started.ToString('o');CompletedUtc=$Completed.ToString('o');Server=$Server;TrustCount=$Trusts.Count;TrustedDomainObjectCount=$TrustObjects.Count;TrustAclCount=$TrustAcls.Count;SidHistoryPrincipalCount=$SidHistory.Count;ForeignSecurityPrincipalCount=$Fsps.Count;NltestCommandCount=$Nltest.Count;OperationalErrorCount=$script:Errors.Count;DirectoryChanges='None';RemoteTrustValidation=$false;TicketsRequested=0;SecretsCollected=0;Files=$Evidence}
$ManifestPath=Join-Path $OutputRoot 'evidence-manifest.json';SaveJson $Manifest $ManifestPath
$Status=if($script:Errors.Count){'Partial'}else{'Completed'}
Write-Host "[$(if($Status-eq'Completed'){'PASS'}else{'WARN'})] Collection complete: $OutputRoot" -ForegroundColor $(if($Status-eq'Completed'){'Green'}else{'Yellow'})
[pscustomobject][ordered]@{Status=$Status;Version=$Version;OutputRoot=$OutputRoot;Server=$Server;TrustCount=$Trusts.Count;TrustedDomainObjectCount=$TrustObjects.Count;TrustAclCount=$TrustAcls.Count;SidHistoryPrincipalCount=$SidHistory.Count;ForeignSecurityPrincipalCount=$Fsps.Count;NltestCommandCount=$Nltest.Count;OperationalErrorCount=$script:Errors.Count;DirectoryChanges='None';RemoteTrustValidation=$false;ManifestPath=$ManifestPath}
