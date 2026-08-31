<#
.SYNOPSIS
Collects focused ADCS closure evidence using the validated AD provider ACL method.
.NOTES
Version: 1.0.2
Package identity: MSADPT-ADCS-CLOSURE-EVIDENCE-COLLECTION
#>
[CmdletBinding()]
param(
 [string]$EngagementPath='C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT\Engagements\MSADPT-Assessment-Example',
 [string]$BootstrapServer='DC01.example.com',
 [string]$CAHost='CA01.example.com',
 [string]$CAName='ExampleOrg-GLOBAL-CA',
 [string]$CADistinguishedName='CN=ExampleOrg-GLOBAL-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com',
 [ValidateRange(1,15)][int]$TcpTimeoutSeconds=3,
 [ValidateRange(3,30)][int]$HttpTimeoutSeconds=8,
 [ValidateRange(10,90)][int]$HotfixTimeoutSeconds=30,
 [switch]$SkipHotfixInventory
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Identity='MSADPT-ADCS-CLOSURE-EVIDENCE-COLLECTION';$Version='1.0.2'
function W([string]$S,[string]$M,[ConsoleColor]$C){Write-Host ('[{0,-8}] {1}' -f $S,$M) -ForegroundColor $C}
function H([string]$P){(Get-FileHash -LiteralPath $P -Algorithm SHA256).Hash.ToUpperInvariant()}
function Tcp([string]$HostName,[int]$Port,[int]$Timeout){$Client=New-Object Net.Sockets.TcpClient;$Start=Get-Date;try{$Task=$Client.ConnectAsync($HostName,$Port);if(-not $Task.Wait([TimeSpan]::FromSeconds($Timeout))){return [pscustomobject]@{host=$HostName;port=$Port;status='TimedOut';connected=$false;elapsedMs=[int]((Get-Date)-$Start).TotalMilliseconds;error=$null}};[pscustomobject]@{host=$HostName;port=$Port;status='Completed';connected=$Client.Connected;elapsedMs=[int]((Get-Date)-$Start).TotalMilliseconds;error=$null}}catch{[pscustomobject]@{host=$HostName;port=$Port;status='Failed';connected=$false;elapsedMs=[int]((Get-Date)-$Start).TotalMilliseconds;error=$_.Exception.Message}}finally{$Client.Dispose()}}
function Http([string]$Uri,[int]$Timeout){$Start=Get-Date;try{$R=Invoke-WebRequest -Uri $Uri -Method Get -MaximumRedirection 0 -TimeoutSec $Timeout -SkipCertificateCheck -ErrorAction Stop;[pscustomobject]@{uri=$Uri;status='Responded';statusCode=[int]$R.StatusCode;reason=[string]$R.StatusDescription;location=[string]$R.Headers.Location;wwwAuthenticate=[string]$R.Headers.'WWW-Authenticate';server=[string]$R.Headers.Server;elapsedMs=[int]((Get-Date)-$Start).TotalMilliseconds;error=$null}}catch{$Code=$null;$Reason=$null;$Location=$null;$Auth=$null;$Server=$null;if($null-ne$_.Exception.Response){try{$Code=[int]$_.Exception.Response.StatusCode}catch{};try{$Reason=[string]$_.Exception.Response.ReasonPhrase}catch{};try{$Location=[string]$_.Exception.Response.Headers.Location}catch{};try{$Auth=[string]$_.Exception.Response.Headers.WwwAuthenticate}catch{};try{$Server=[string]$_.Exception.Response.Headers.Server}catch{}};[pscustomobject]@{uri=$Uri;status=if($null-ne$Code){'Responded'}else{'Failed'};statusCode=$Code;reason=$Reason;location=$Location;wwwAuthenticate=$Auth;server=$Server;elapsedMs=[int]((Get-Date)-$Start).TotalMilliseconds;error=$_.Exception.Message}}}
function Tool([string]$Name){$C=Get-Command $Name -ErrorAction SilentlyContinue|Select-Object -First 1;[pscustomobject]@{name=$Name;available=$null-ne$C;source=if($null-ne$C){[string]$C.Source}else{$null};version=if($null-ne$C){[string]$C.Version}else{$null}}}
W START "$Identity v$Version" Cyan;W INFO 'Validated AD provider ACL retrieval plus bounded live probes.' DarkGray
if(-not(Test-Path -LiteralPath $EngagementPath -PathType Container)){throw "EngagementPathMissing: $EngagementPath"}
$Out=Join-Path $EngagementPath ('evidence\ADCSClosureValidation\'+(Get-Date -Format 'yyyyMMdd-HHmmss'));New-Item -ItemType Directory -Path $Out -Force|Out-Null
Import-Module ActiveDirectory -ErrorAction Stop
if(-not(Test-Path 'AD:\')){New-PSDrive -Name AD -PSProvider ActiveDirectory -Root '' -Server $BootstrapServer -ErrorAction Stop|Out-Null}
$Acl=Get-Acl -LiteralPath "AD:\$CADistinguishedName" -ErrorAction Stop
if(@($Acl.Access).Count -eq 0 -or [string]::IsNullOrWhiteSpace([string]$Acl.Sddl)){throw'CAAclValidationFailed'}
$Aces=@(foreach($A in @($Acl.Access)){[pscustomobject][ordered]@{identityReference=[string]$A.IdentityReference;accessControlType=[string]$A.AccessControlType;activeDirectoryRights=[string]$A.ActiveDirectoryRights;objectType=[string]$A.ObjectType;inheritedObjectType=[string]$A.InheritedObjectType;inheritanceType=[string]$A.InheritanceType;isInherited=[bool]$A.IsInherited;inheritanceFlags=[string]$A.InheritanceFlags;propagationFlags=[string]$A.PropagationFlags}})
$AclDoc=[pscustomobject][ordered]@{schemaVersion='1.0';owner=[string]$Acl.Owner;group=[string]$Acl.Group;sddl=[string]$Acl.Sddl;accessEntryCount=$Aces.Count;access=@($Aces)}
$AclDoc|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Out 'ca-directory-acl.json') -Encoding UTF8;$Aces|Export-Csv (Join-Path $Out 'ca-directory-acl.csv') -NoTypeInformation -Encoding UTF8
W OK "CA ACL collected through AD provider: owner=$($Acl.Owner), ACEs=$($Aces.Count)." Green
$AD=@{Server=$BootstrapServer;ErrorAction='Stop'}
$Comp=Get-ADComputer -Identity (($CAHost-split'\.')[0]) -Properties operatingSystem,operatingSystemVersion,operatingSystemServicePack,enabled,servicePrincipalName @AD
[pscustomobject]@{name=[string]$Comp.Name;dnsHostName=[string]$Comp.DNSHostName;enabled=[bool]$Comp.Enabled;operatingSystem=[string]$Comp.operatingSystem;operatingSystemVersion=[string]$Comp.operatingSystemVersion;servicePack=[string]$Comp.operatingSystemServicePack;distinguishedName=[string]$Comp.DistinguishedName;servicePrincipalNames=@($Comp.servicePrincipalName|ForEach-Object{[string]$_})}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Out 'ca-computer-metadata.json') -Encoding UTF8
W OK "CA host metadata: $($Comp.operatingSystem) $($Comp.operatingSystemVersion)." Green
$Ports=@(80,443,135,139,445,593,5985,5986);$PR=@();foreach($P in $Ports){W PROBE "$CAHost TCP/$P" Yellow;$PR+=,(Tcp $CAHost $P $TcpTimeoutSeconds)};$PR|ConvertTo-Json -Depth 4|Set-Content (Join-Path $Out 'ca-tcp-reachability.json') -Encoding UTF8
$Paths=@('/certsrv/','/CertSrv/mscep/','/CertSrv/mscep_admin/','/ADPolicyProvider_CEP_Kerberos/service.svc/CEP','/ADPolicyProvider_CES_Kerberos/service.svc/CES');$HR=@();foreach($Scheme in @('http','https')){foreach($Path in $Paths){$Uri="${Scheme}://${CAHost}${Path}";W PROBE $Uri Yellow;$HR+=,(Http $Uri $HttpTimeoutSeconds)}};$HR|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Out 'adcs-http-observations.json') -Encoding UTF8;$HR|Export-Csv (Join-Path $Out 'adcs-http-observations.csv') -NoTypeInformation -Encoding UTF8
$Tools=@(Tool 'certutil.exe';Tool 'nmap.exe';Tool 'nmap';Tool 'certipy.exe';Tool 'certipy';Tool 'python.exe');$Tools|ConvertTo-Json -Depth 4|Set-Content (Join-Path $Out 'tool-inventory.json') -Encoding UTF8
$HotStatus='Skipped';$HotError=$null;$Hot=@();if(-not$SkipHotfixInventory){W PROBE "Bounded hotfix inventory (${HotfixTimeoutSeconds}s maximum)." Yellow;$Job=Start-Job -ScriptBlock{param($HostName) Get-HotFix -ComputerName $HostName -ErrorAction Stop} -ArgumentList $CAHost;try{if(Wait-Job $Job -Timeout $HotfixTimeoutSeconds){$Hot=@(Receive-Job $Job -ErrorAction Stop);$HotStatus='Completed'}else{$HotStatus='TimedOut';Stop-Job $Job -ErrorAction SilentlyContinue}}catch{$HotStatus='Failed';$HotError=$_.Exception.Message}finally{Remove-Job $Job -Force -ErrorAction SilentlyContinue}}
if($Hot.Count-gt0){$Hot|Select-Object Source,Description,HotFixID,InstalledBy,InstalledOn|Export-Csv (Join-Path $Out 'ca-hotfix-inventory.csv') -NoTypeInformation -Encoding UTF8}else{'Source,Description,HotFixID,InstalledBy,InstalledOn'|Set-Content (Join-Path $Out 'ca-hotfix-inventory.csv') -Encoding UTF8}
$Leads=@($Aces|Where-Object{$_.accessControlType -eq 'Allow' -and $_.activeDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight' -and $_.identityReference -notmatch '(?i)\\(Domain Admins|Enterprise Admins|Administrators)$|^NT AUTHORITY\\SYSTEM$'});$Open=@($PR|Where-Object{$_.connected});$Respond=@($HR|Where-Object{$_.status -eq 'Responded'})
$Summary=[pscustomobject][ordered]@{schemaVersion='1.0';packageIdentity=$Identity;packageVersion=$Version;status='Completed';target=[pscustomobject]@{caHost=$CAHost;caName=$CAName;distinguishedName=$CADistinguishedName};acl=[pscustomobject]@{owner=[string]$Acl.Owner;sddlLength=$Acl.Sddl.Length;entryCount=$Aces.Count;suspiciousLeadCount=$Leads.Count};counts=[pscustomobject]@{openPorts=$Open.Count;respondingHttpEndpoints=$Respond.Count;hotfixes=$Hot.Count};hotfix=[pscustomobject]@{status=$HotStatus;error=$HotError};leads=[pscustomobject]@{directoryAces=$Leads;openPorts=$Open;httpResponses=$Respond};tools=$Tools;safety=[pscustomobject]@{directoryChanges='None';caConfigurationChanges='None';certificateRequests='None';authenticationTesting='None'}}
$SP=Join-Path $Out 'adcs-closure-evidence-summary.json';$Summary|ConvertTo-Json -Depth 12|Set-Content $SP -Encoding UTF8;$SC=Get-Content $SP -Raw|ConvertFrom-Json;if([string]$SC.status -ne 'Completed'){throw'SummaryValidationFailed'}
$Files=@(Get-ChildItem $Out -File|Sort-Object Name);$Manifest=@($Files|ForEach-Object{[pscustomobject]@{name=$_.Name;size=[int64]$_.Length;sha256=H $_.FullName}});$Manifest|ConvertTo-Json -Depth 4|Set-Content (Join-Path $Out 'evidence-manifest.json') -Encoding UTF8
W DONE "Closure evidence complete: ACL leads=$($Leads.Count), HTTP responses=$($Respond.Count), open ports=$($Open.Count), hotfix=$HotStatus." Green
[pscustomobject][ordered]@{Status='Passed';PackageIdentity=$Identity;PackageVersion=$Version;CAHost=$CAHost;CAOwner=[string]$Acl.Owner;DirectoryAclEntryCount=$Aces.Count;SuspiciousDirectoryAceLeadCount=$Leads.Count;OpenTcpPorts=@($Open.port);RespondingHttpEndpointCount=$Respond.Count;HotfixInventoryStatus=$HotStatus;HotfixCount=$Hot.Count;CertipyAvailable=[bool](@($Tools|Where-Object{$_.name -match '^certipy' -and $_.available}).Count-gt0);NmapAvailable=[bool](@($Tools|Where-Object{$_.name -match '^nmap' -and $_.available}).Count-gt0);OutputRoot=$Out;SummaryPath=$SP;DirectoryChanges='None';CAConfigurationChanges='None';CertificateRequests='None';AuthenticationTesting='None'}
