<#
.SYNOPSIS
Performs deterministic, offline effective-access evaluation for MSADPT Directory Control candidates.
.DESCRIPTION
Correlates reduced Directory Control candidate evidence with the raw ACE inventory and optional
pre-collected token-membership evidence. The module evaluates exact trustee/target/capability ACE
semantics, object-specific rights, inheritance restrictions, Allow and Deny applicability, and
evidence completeness. It never modifies Active Directory and never claims downstream impact.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$DirectoryControlEvidenceDirectory,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CandidateReductionDirectory,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [string]$TokenEvidencePath,
    [ValidateRange(1,1000000)][int]$MaximumCandidates = 100000,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ModuleId='Invoke-MSADPTDirectoryControlEffectiveAccess'
$ModuleVersion='1.0.1'
function Show { param([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray);$t='[{0,-12}] {1}' -f $State,$Message;if($NoColor){Write-Host $t}else{Write-Host $t -ForegroundColor $Color} }
function Field { param([object]$Object,[string]$Name,[object]$Default=$null);if($null-eq$Object){return $Default};$p=$Object.PSObject.Properties[$Name];if($null-eq$p-or$null-eq$p.Value){return $Default};return $p.Value }
function Norm { param([object]$Value);$s=[string]$Value;if([string]::IsNullOrWhiteSpace($s)){return $null};return $s.Trim().ToLowerInvariant() }
function GuidText { param([object]$Value);$s=Norm $Value;if($null-eq$s-or$s-eq'00000000-0000-0000-0000-000000000000'){return $null};return $s.Trim('{}') }
function Bool { param([object]$Value);if($Value-is[bool]){return [bool]$Value};return ([string]$Value).Trim().Equals('True',[StringComparison]::OrdinalIgnoreCase) }
function Int { param([object]$Value,[int]$Default=0);$x=0;if([int]::TryParse([string]$Value,[ref]$x)){return $x};return $Default }
function Json { param([object]$Value,[string]$Path);$Value|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8;$null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop }
function ArrayJson { param([object[]]$Value,[string]$Path);$a=[object[]]@($Value);if($a.Count-eq0){[IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))}else{$a|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8};$null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop }
$GuidMap=@{
'bf9679c0-0de6-11d0-a285-00aa003049e2'='WriteGroupMembership';'bf967a7f-0de6-11d0-a285-00aa003049e2'='WriteServicePrincipalName';'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'='WriteRBCD';'5b47d60f-6090-40b2-9f37-2a4de88f3063'='WriteKeyCredentialLink';'00299570-246d-11d0-a768-00aa006e0529'='ResetPassword';'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'='ReplicatingDirectoryChanges';'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'='ReplicatingDirectoryChangesAll';'89e95b76-444d-4c62-991a-0facbeda640c'='ReplicatingDirectoryChangesFilteredSet';'f30e3bbe-9ff0-11d1-b603-0000f80367c1'='WriteGPLink'
}
function Capabilities { param([object]$Ace);$rights=[string](Field $Ace 'ActiveDirectoryRights' '');$g=GuidText (Field $Ace 'ObjectTypeGuid');$r=New-Object 'Collections.Generic.List[string]';foreach($x in @('GenericAll','GenericWrite','WriteDacl','WriteOwner')){if($rights-match$x){$r.Add($x)}};if($null-ne$g-and$GuidMap.ContainsKey($g)){$r.Add([string]$GuidMap[$g])}elseif($rights-match'WriteProperty|ExtendedRight|Self'){$r.Add('UnresolvedObjectSpecificRight')};return [string[]]@($r|Sort-Object -Unique) }
function TrusteeSid { param([object]$Row);foreach($v in @([string](Field $Row 'TrusteeSid' ''),[string](Field $Row 'Trustee' ''))){if($v.Trim()-match'^S-1-'){return $v.Trim().ToUpperInvariant()}};return $null }
function TargetApplicable { param([string]$Capability,[string]$TargetType);switch($Capability){'WriteGroupMembership'{return $TargetType-eq'Group'}'WriteRBCD'{return $TargetType-in@('Computer','User')}'WriteServicePrincipalName'{return $TargetType-in@('Computer','User')}'WriteKeyCredentialLink'{return $TargetType-in@('Computer','User')}'WriteGPLink'{return $TargetType-in@('OrganizationalUnit','Domain','Site')}'ReplicatingDirectoryChanges'{return $TargetType-eq'Domain'}'ReplicatingDirectoryChangesAll'{return $TargetType-eq'Domain'}'ReplicatingDirectoryChangesFilteredSet'{return $TargetType-eq'Domain'}default{return $true}} }
$e=[IO.Path]::GetFullPath($DirectoryControlEvidenceDirectory);$r=[IO.Path]::GetFullPath($CandidateReductionDirectory);$o=[IO.Path]::GetFullPath($OutputDirectory)
$candidatePath=Join-Path $r 'directory-control-prioritized-target-details.csv';if(-not(Test-Path -LiteralPath $candidatePath -PathType Leaf)){$candidatePath=Join-Path $e 'directory-control-first-hop-candidates.csv'}
$acePath=Join-Path $e 'directory-control-ace-inventory.csv'
foreach($p in @($candidatePath,$acePath)){if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "RequiredEvidenceMissing: $p"}}
New-Item -ItemType Directory -Path $o -Force|Out-Null
Show START "$ModuleId v$ModuleVersion" Cyan;Show SAFETY 'Offline evidence correlation only. Network=None; directory queries=None; directory changes=None; impact reproduction=None.' Yellow
$candidates=@(Import-Csv -LiteralPath $candidatePath|Select-Object -First $MaximumCandidates);Show INPUT "Candidates=$($candidates.Count); source=$candidatePath" DarkCyan
$tokenMap=@{};$tokenCompleteMap=@{}
if(-not[string]::IsNullOrWhiteSpace($TokenEvidencePath)){
 if(-not(Test-Path -LiteralPath $TokenEvidencePath -PathType Leaf)){throw "TokenEvidenceMissing: $TokenEvidencePath"}
 foreach($t in @(Import-Csv -LiteralPath $TokenEvidencePath)){ $p=[string](Field $t 'PrincipalSid' '');$s=[string](Field $t 'TokenSid' '');if($p-match'^S-1-' -and $s-match'^S-1-'){if(-not$tokenMap.ContainsKey($p.ToUpperInvariant())){$tokenMap[$p.ToUpperInvariant()]=New-Object 'Collections.Generic.HashSet[string]'};$null=$tokenMap[$p.ToUpperInvariant()].Add($s.ToUpperInvariant());if(Bool (Field $t 'Complete' $false)){$tokenCompleteMap[$p.ToUpperInvariant()]=$true}} }
}
$candidateContexts=New-Object 'Collections.Generic.List[object]'
foreach($c in $candidates){
 $principalSid=TrusteeSid $c
 $dn=Norm (Field $c 'TargetDistinguishedName')
 $cap=[string](Field $c 'Capability' '')
 $tokenSids=New-Object 'Collections.Generic.HashSet[string]'
 $tokenComplete=$false
 if($null-ne$principalSid){$null=$tokenSids.Add($principalSid)}
 if($null-ne$principalSid-and$tokenMap.ContainsKey($principalSid)){
  foreach($tokenSid in $tokenMap[$principalSid]){$null=$tokenSids.Add([string]$tokenSid)}
  $tokenComplete=$tokenCompleteMap.ContainsKey($principalSid)
 }
 $candidateContexts.Add([pscustomobject]@{Candidate=$c;PrincipalSid=$principalSid;TargetDn=$dn;Capability=$cap;TokenSids=$tokenSids;TokenComplete=$tokenComplete})
}
$targetDns=New-Object 'Collections.Generic.HashSet[string]'
$allTokenSids=New-Object 'Collections.Generic.HashSet[string]'
foreach($ctx in $candidateContexts){if($null-ne$ctx.TargetDn){$null=$targetDns.Add([string]$ctx.TargetDn)};foreach($sid in $ctx.TokenSids){$null=$allTokenSids.Add([string]$sid)}}
$aceIndex=@{};$aceCount=0
foreach($a in @(Import-Csv -LiteralPath $acePath)){
 $aceCount++
 $dn=Norm (Field $a 'TargetDistinguishedName')
 $aceSid=TrusteeSid $a
 if($null-eq$dn-or$null-eq$aceSid-or-not$targetDns.Contains($dn)-or-not$allTokenSids.Contains($aceSid)){continue}
 foreach($cap in @(Capabilities $a)){
  $key=$dn+'|'+$cap
  if(-not$aceIndex.ContainsKey($key)){$aceIndex[$key]=New-Object 'Collections.Generic.List[object]'}
  $aceIndex[$key].Add($a)
 }
}
Show CORRELATE "Raw ACE rows=$aceCount; target/capability keys matched=$($aceIndex.Count); token SIDs considered=$($allTokenSids.Count)." DarkCyan
$results=New-Object 'Collections.Generic.List[object]'
$trace=New-Object 'Collections.Generic.List[object]'
$errors=New-Object 'Collections.Generic.List[object]'
$counts=@{}
function Count([string]$k){if(-not$counts.ContainsKey($k)){$counts[$k]=0};$counts[$k]++}
foreach($ctx in $candidateContexts){
 $c=$ctx.Candidate;$principalSid=[string]$ctx.PrincipalSid;$dn=[string]$ctx.TargetDn;$cap=[string]$ctx.Capability;$type=[string](Field $c 'TargetObjectType' 'Unknown')
 $indexKey=$dn+'|'+$cap
 $allRows=if($aceIndex.ContainsKey($indexKey)){[object[]]$aceIndex[$indexKey].ToArray()}else{@()}
 $rows=@($allRows|Where-Object{$ctx.TokenSids.Contains((TrusteeSid $_))})
 $allow=@($rows|Where-Object{[string](Field $_ 'AccessControlType' 'Allow')-eq'Allow'})
 $deny=@($rows|Where-Object{[string](Field $_ 'AccessControlType' 'Allow')-eq'Deny'})
 $directAllow=@($allow|Where-Object{(TrusteeSid $_)-eq$principalSid}).Count
 $derivedAllow=$allow.Count-$directAllow
 $directDeny=@($deny|Where-Object{(TrusteeSid $_)-eq$principalSid}).Count
 $derivedDeny=$deny.Count-$directDeny
 $app=TargetApplicable $cap $type
 $restriction='Applicable'
 foreach($a in $rows){$ig=GuidText (Field $a 'InheritedObjectTypeGuid');if((Bool (Field $a 'IsInherited' $false))-and$null-ne$ig){$restriction='InheritedObjectTypeRequiresClassGuidEvidence'}}
 if(-not$app){$disp='NotApplicable';$reason='CapabilityNotApplicableToTargetType'}
 elseif($rows.Count-eq0){$disp='Inconclusive';$reason='ExactTokenAceEvidenceNotFound'}
 elseif($restriction-ne'Applicable'){$disp='Inconclusive';$reason=$restriction}
 elseif(-not$ctx.TokenComplete){$disp='Inconclusive';$reason=if($deny.Count-gt0){'AllowOrDenyObservedTokenIncomplete'}else{'ApplicableAllowObservedTokenIncomplete'}}
 elseif($deny.Count-gt0){$disp='EffectiveControlNotEstablished';$reason='ApplicableDenyObservedForCollectedToken'}
 elseif($allow.Count-gt0){$disp='EffectiveControlConfirmed';$reason='ApplicableAllowNoApplicableDenyObservedWithCompleteToken'}
 else{$disp='EffectiveControlNotEstablished';$reason='NoApplicableAllowObserved'}
 Count $disp
 $evaluationId=[guid]::NewGuid().ToString('N')
 foreach($a in $rows){
  $aceSid=TrusteeSid $a
  $source='TokenGroupOrSidHistory'
  if($aceSid-eq$principalSid){$source='DirectTrustee'}
  $trace.Add([pscustomobject][ordered]@{EvaluationId=$evaluationId;CandidateId=Field $c 'CandidateId' '';PrincipalSid=$principalSid;AceTrustee=Field $a 'Trustee' '';AceTrusteeSid=$aceSid;TokenSource=$source;AccessControlType=Field $a 'AccessControlType' '';ActiveDirectoryRights=Field $a 'ActiveDirectoryRights' '';ObjectTypeGuid=Field $a 'ObjectTypeGuid' '';InheritedObjectTypeGuid=Field $a 'InheritedObjectTypeGuid' '';IsInherited=Field $a 'IsInherited' $false;TargetDistinguishedName=Field $a 'TargetDistinguishedName' '';Capability=$cap})
 }
 $results.Add([pscustomobject][ordered]@{EvaluationId=$evaluationId;CandidateId=Field $c 'CandidateId' '';FamilyId=Field $c 'FamilyId' '';ValidationPriority=Field $c 'Priority' '';Trustee=Field $c 'Trustee' '';TrusteeSid=$principalSid;TargetName=Field $c 'TargetName' '';TargetDistinguishedName=Field $c 'TargetDistinguishedName' '';TargetObjectType=$type;Capability=$cap;ExactTokenAceCount=$rows.Count;ApplicableAllowAceCount=$allow.Count;DirectAllowAceCount=$directAllow;TokenDerivedAllowAceCount=$derivedAllow;ApplicableDenyAceCount=$deny.Count;DirectDenyAceCount=$directDeny;TokenDerivedDenyAceCount=$derivedDeny;TokenSidCount=$ctx.TokenSids.Count;TokenEvidenceCompleteness=if($ctx.TokenComplete){'Complete'}else{'Incomplete'};ObjectTypeApplicability=if($app){'Applicable'}else{'NotApplicable'};InheritanceRestriction=$restriction;Disposition=$disp;Reason=$reason;EffectiveAccess=if($disp-eq'EffectiveControlConfirmed'){'ConfirmedForCollectedToken'}else{'NotEstablished'};ImpactReproduced=$false;VulnerabilityConfirmed=$false})
}
$trace.ToArray()|Export-Csv (Join-Path $o 'directory-control-effective-access-ace-trace.csv') -NoTypeInformation -Encoding UTF8
ArrayJson $trace.ToArray() (Join-Path $o 'directory-control-effective-access-ace-trace.json')
$results.ToArray()|Export-Csv (Join-Path $o 'directory-control-effective-access-evaluations.csv') -NoTypeInformation -Encoding UTF8
ArrayJson $results.ToArray() (Join-Path $o 'directory-control-effective-access-evaluations.json');ArrayJson $errors.ToArray() (Join-Path $o 'directory-control-effective-access-operational-errors.json')
$summary=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;Status='Completed';Disposition=if($counts.ContainsKey('EffectiveControlConfirmed')){'EffectiveControlCandidateConfirmed'}elseif($counts.ContainsKey('Inconclusive')){'Inconclusive'}else{'NotDetected'};GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');Counts=[pscustomobject]$counts;InputCandidateCount=$candidates.Count;RawAceRowsRead=$aceCount;TokenEvidenceProvided=(-not[string]::IsNullOrWhiteSpace($TokenEvidencePath));InterpretationBoundary=@('EffectiveControlConfirmed establishes only collected-token directory permission applicability.','No downstream security impact was reproduced.','Incomplete token evidence remains Inconclusive.','A confirmed permission is not automatically a confirmed vulnerability.');Safety=[pscustomobject]@{NetworkActivity='None';DirectoryQueries='None';DirectoryChanges='None';ImpactReproduction='None';RemoteChanges='None'}}
Json $summary (Join-Path $o 'directory-control-effective-access-summary.json')
$files=@(Get-ChildItem -LiteralPath $o -File|Where-Object{$_.Name-ne'evidence-manifest.json'}|Sort-Object Name|ForEach-Object{[pscustomobject]@{Name=$_.Name;Size=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}});Json ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;FileCount=$files.Count;Files=$files}) (Join-Path $o 'evidence-manifest.json')
Show DONE "Evaluated=$($results.Count); confirmed=$(Int (Field ([pscustomobject]$counts) 'EffectiveControlConfirmed' 0)); inconclusive=$(Int (Field ([pscustomobject]$counts) 'Inconclusive' 0))." Green
[pscustomobject][ordered]@{Status='Passed';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;Evaluated=$results.Count;SummaryPath=(Join-Path $o 'directory-control-effective-access-summary.json');ManifestPath=(Join-Path $o 'evidence-manifest.json');NetworkActivity='None';DirectoryQueries='None';RemoteChanges='None'}
