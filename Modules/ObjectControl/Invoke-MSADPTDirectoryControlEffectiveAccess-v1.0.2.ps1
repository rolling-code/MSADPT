<#
.SYNOPSIS
Evaluates token-wide Directory Control effective access using exact ACE and target schema-class evidence.
.NOTES
Version: 1.0.2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$DirectoryControlEvidenceDirectory,
    [Parameter(Mandatory=$true)][string]$CandidateReductionDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$TokenEvidencePath,
    [Parameter(Mandatory=$true)][string]$SchemaClassMapPath,
    [ValidateRange(1,1000000)][int]$MaximumCandidates=100000,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ModuleId='Invoke-MSADPTDirectoryControlEffectiveAccess'
$ModuleVersion='1.0.2'
function Show { param([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray);$Text='[{0,-12}] {1}' -f $State,$Message;if($NoColor){Write-Host $Text}else{Write-Host $Text -ForegroundColor $Color} }
function Field { param([object]$Object,[string]$Name,[object]$Default=$null);if($null -eq $Object){return $Default};$Property=$Object.PSObject.Properties[$Name];if($null -eq $Property -or $null -eq $Property.Value){return $Default};return $Property.Value }
function Normalize { param([object]$Value);$Text=[string]$Value;if([string]::IsNullOrWhiteSpace($Text)){return $null};return $Text.Trim().ToLowerInvariant() }
function TrusteeSid { param([object]$Row);foreach($Value in @([string](Field $Row 'TrusteeSid' ''),[string](Field $Row 'Trustee' ''))){if($Value.Trim() -match '^S-1-'){return $Value.Trim().ToUpperInvariant()}};return $null }
function ToBool { param([object]$Value);if($Value -is [bool]){return [bool]$Value};return ([string]$Value).Equals('True',[StringComparison]::OrdinalIgnoreCase) }
function GuidText { param([object]$Value);$Text=Normalize $Value;if($Text -eq '00000000-0000-0000-0000-000000000000'){return $null};if($null -eq $Text){return $null};return $Text.Trim('{}') }
function WriteJson { param([object]$Value,[string]$Path);$Value|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8;$null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop }
function WriteJsonArray { param([object[]]$Value,[string]$Path);$Array=[object[]]@($Value);if($Array.Count -eq 0){[IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))}else{$Array|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8};$null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop }
$GuidMap=@{
 'bf9679c0-0de6-11d0-a285-00aa003049e2'='WriteGroupMembership';'bf967a7f-0de6-11d0-a285-00aa003049e2'='WriteServicePrincipalName';'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'='WriteRBCD';'5b47d60f-6090-40b2-9f37-2a4de88f3063'='WriteKeyCredentialLink';'00299570-246d-11d0-a768-00aa006e0529'='ResetPassword';'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'='ReplicatingDirectoryChanges';'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'='ReplicatingDirectoryChangesAll';'89e95b76-444d-4c62-991a-0facbeda640c'='ReplicatingDirectoryChangesFilteredSet';'f30e3bbe-9ff0-11d1-b603-0000f80367c1'='WriteGPLink'
}
function GetCapabilities { param([object]$Ace);$List=New-Object 'Collections.Generic.List[string]';$Rights=[string](Field $Ace 'ActiveDirectoryRights' '');foreach($Name in @('GenericAll','GenericWrite','WriteDacl','WriteOwner')){if($Rights -match $Name){$List.Add($Name)}};$Guid=GuidText (Field $Ace 'ObjectTypeGuid');if($null -ne $Guid -and $GuidMap.ContainsKey($Guid)){$List.Add([string]$GuidMap[$Guid])};return [string[]]@($List|Sort-Object -Unique) }
$Evidence=[IO.Path]::GetFullPath($DirectoryControlEvidenceDirectory)
$Reduction=[IO.Path]::GetFullPath($CandidateReductionDirectory)
$Output=[IO.Path]::GetFullPath($OutputDirectory)
$CandidatePath=Join-Path $Reduction 'directory-control-prioritized-target-details.csv'
$AcePath=Join-Path $Evidence 'directory-control-ace-inventory.csv'
foreach($Path in @($CandidatePath,$AcePath,$TokenEvidencePath,$SchemaClassMapPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "RequiredEvidenceMissing: $Path"}}
New-Item -ItemType Directory -Path $Output -Force|Out-Null
Show START "$ModuleId v$ModuleVersion" Cyan
Show SAFETY 'Offline evidence correlation only. Network=None; directory changes=None; impact reproduction=None.' Yellow
$TokenMap=@{};$TokenComplete=@{}
foreach($Row in @(Import-Csv -LiteralPath $TokenEvidencePath)){$Principal=[string]$Row.PrincipalSid;$Sid=[string]$Row.TokenSid;if(-not$TokenMap.ContainsKey($Principal)){$TokenMap[$Principal]=New-Object 'Collections.Generic.HashSet[string]'};$null=$TokenMap[$Principal].Add($Sid);if(ToBool $Row.Complete){$TokenComplete[$Principal]=$true}}
$ClassMap=@{}
foreach($Row in @(Import-Csv -LiteralPath $SchemaClassMapPath)){$Name=[string]$Row.LdapDisplayName;$Guid=[string]$Row.SchemaIdGuid;if($Name -and $Guid){$ClassMap[$Name.ToLowerInvariant()]=$Guid.ToLowerInvariant()}}
$Aliases=@{organizationalunit='organizationalunit';domain='domaindns';domaindns='domaindns';user='user';group='group';computer='computer';site='site'}
$Candidates=@(Import-Csv -LiteralPath $CandidatePath|Select-Object -First $MaximumCandidates)
$Contexts=New-Object 'Collections.Generic.List[object]';$TargetDns=New-Object 'Collections.Generic.HashSet[string]';$AllSids=New-Object 'Collections.Generic.HashSet[string]'
foreach($Candidate in $Candidates){$Principal=TrusteeSid $Candidate;$Dn=Normalize (Field $Candidate 'TargetDistinguishedName');$Set=New-Object 'Collections.Generic.HashSet[string]';if($Principal){$null=$Set.Add($Principal)};if($Principal -and $TokenMap.ContainsKey($Principal)){foreach($Sid in $TokenMap[$Principal]){$null=$Set.Add($Sid)}};$Contexts.Add([pscustomobject]@{Candidate=$Candidate;PrincipalSid=$Principal;TargetDn=$Dn;Capability=[string](Field $Candidate 'Capability' '');TokenSids=$Set;Complete=($Principal -and $TokenComplete.ContainsKey($Principal))});if($Dn){$null=$TargetDns.Add($Dn)};foreach($Sid in $Set){$null=$AllSids.Add($Sid)}}
$Index=@{};$AceCount=0
foreach($Ace in @(Import-Csv -LiteralPath $AcePath)){$AceCount++;$Dn=Normalize (Field $Ace 'TargetDistinguishedName');$Sid=TrusteeSid $Ace;if(-not$Dn -or -not$Sid -or -not$TargetDns.Contains($Dn) -or -not$AllSids.Contains($Sid)){continue};foreach($Capability in @(GetCapabilities $Ace)){$Key="$Dn|$Capability";if(-not$Index.ContainsKey($Key)){$Index[$Key]=New-Object 'Collections.Generic.List[object]'};$Index[$Key].Add($Ace)}}
Show CORRELATE "Raw ACE rows=$AceCount; target/capability keys=$($Index.Count); token SIDs=$($AllSids.Count)." DarkCyan
$Results=New-Object 'Collections.Generic.List[object]';$Trace=New-Object 'Collections.Generic.List[object]';$Counts=@{}
foreach($Context in $Contexts){$Candidate=$Context.Candidate;$Type=[string](Field $Candidate 'TargetObjectType' 'Unknown');$Key="$($Context.TargetDn)|$($Context.Capability)";$Rows=if($Index.ContainsKey($Key)){@($Index[$Key].ToArray()|Where-Object{$Context.TokenSids.Contains((TrusteeSid $_))})}else{@()};$Allow=@($Rows|Where-Object{[string](Field $_ 'AccessControlType' 'Allow') -eq 'Allow'});$Deny=@($Rows|Where-Object{[string](Field $_ 'AccessControlType' 'Allow') -eq 'Deny'});$Restriction='Applicable';foreach($Ace in $Rows){$InheritedGuid=GuidText (Field $Ace 'InheritedObjectTypeGuid');if((ToBool (Field $Ace 'IsInherited' $false)) -and $InheritedGuid){$ClassKey=$Type.ToLowerInvariant();if($Aliases.ContainsKey($ClassKey)){$ClassKey=$Aliases[$ClassKey]};if(-not$ClassMap.ContainsKey($ClassKey)){$Restriction='InheritedObjectTypeRequiresClassGuidEvidence'}elseif($ClassMap[$ClassKey] -ne $InheritedGuid){$Restriction='InheritedObjectTypeNotApplicable'}}};if(-not$Context.Complete){$Disposition='Inconclusive';$Reason='TokenEvidenceIncomplete'}elseif($Restriction -eq 'InheritedObjectTypeRequiresClassGuidEvidence'){$Disposition='Inconclusive';$Reason=$Restriction}elseif($Restriction -eq 'InheritedObjectTypeNotApplicable'){$Disposition='NotApplicable';$Reason=$Restriction}elseif($Deny.Count){$Disposition='EffectiveControlNotEstablished';$Reason='ApplicableDenyObservedForCollectedToken'}elseif($Allow.Count){$Disposition='EffectiveControlConfirmed';$Reason='ApplicableAllowNoApplicableDenyObservedWithCompleteToken'}else{$Disposition='EffectiveControlNotEstablished';$Reason='NoApplicableAllowObserved'};if(-not$Counts.ContainsKey($Disposition)){$Counts[$Disposition]=0};$Counts[$Disposition]++;$EvaluationId=[guid]::NewGuid().ToString('N');foreach($Ace in $Rows){$Trace.Add([pscustomobject]@{EvaluationId=$EvaluationId;CandidateId=Field $Candidate 'CandidateId' '';PrincipalSid=$Context.PrincipalSid;AceTrustee=Field $Ace 'Trustee' '';AceTrusteeSid=TrusteeSid $Ace;AccessControlType=Field $Ace 'AccessControlType' '';ActiveDirectoryRights=Field $Ace 'ActiveDirectoryRights' '';ObjectTypeGuid=Field $Ace 'ObjectTypeGuid' '';InheritedObjectTypeGuid=Field $Ace 'InheritedObjectTypeGuid' '';IsInherited=Field $Ace 'IsInherited' $false;Capability=$Context.Capability;TargetDistinguishedName=Field $Ace 'TargetDistinguishedName' ''})};$Results.Add([pscustomobject]@{EvaluationId=$EvaluationId;CandidateId=Field $Candidate 'CandidateId' '';ValidationPriority=Field $Candidate 'Priority' '';Trustee=Field $Candidate 'Trustee' '';TrusteeSid=$Context.PrincipalSid;TargetName=Field $Candidate 'TargetName' '';TargetDistinguishedName=Field $Candidate 'TargetDistinguishedName' '';TargetObjectType=$Type;Capability=$Context.Capability;ExactTokenAceCount=$Rows.Count;ApplicableAllowAceCount=$Allow.Count;ApplicableDenyAceCount=$Deny.Count;TokenSidCount=$Context.TokenSids.Count;TokenEvidenceCompleteness=if($Context.Complete){'Complete'}else{'Incomplete'};InheritanceRestriction=$Restriction;Disposition=$Disposition;Reason=$Reason;EffectiveAccess=if($Disposition -eq 'EffectiveControlConfirmed'){'ConfirmedForCollectedToken'}else{'NotEstablished'};ImpactReproduced=$false;VulnerabilityConfirmed=$false})}
$Results.ToArray()|Export-Csv -LiteralPath (Join-Path $Output 'directory-control-effective-access-evaluations.csv') -NoTypeInformation -Encoding UTF8
$Trace.ToArray()|Export-Csv -LiteralPath (Join-Path $Output 'directory-control-effective-access-ace-trace.csv') -NoTypeInformation -Encoding UTF8
WriteJsonArray $Results.ToArray() (Join-Path $Output 'directory-control-effective-access-evaluations.json');WriteJsonArray $Trace.ToArray() (Join-Path $Output 'directory-control-effective-access-ace-trace.json');WriteJsonArray @() (Join-Path $Output 'directory-control-effective-access-operational-errors.json')
$Summary=[pscustomobject]@{SchemaVersion='1.0';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;Status='Completed';Disposition=if($Counts.ContainsKey('EffectiveControlConfirmed')){'EffectiveControlCandidateConfirmed'}elseif($Counts.ContainsKey('Inconclusive')){'Inconclusive'}else{'NotDetected'};GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');Counts=[pscustomobject]$Counts;InputCandidateCount=$Candidates.Count;RawAceRowsRead=$AceCount;TokenEvidenceProvided=$true;SchemaClassMapProvided=$true;ImpactReproduced=$false;VulnerabilityConfirmed=$false};WriteJson $Summary (Join-Path $Output 'directory-control-effective-access-summary.json')
$Files=@(Get-ChildItem -LiteralPath $Output -File|Where-Object Name -ne 'evidence-manifest.json'|ForEach-Object{[pscustomobject]@{Name=$_.Name;Size=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}});WriteJson ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;FileCount=$Files.Count;Files=$Files}) (Join-Path $Output 'evidence-manifest.json')
Show DONE "Evaluated=$($Results.Count)." Green
[pscustomobject]@{Status='Passed';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;Evaluated=$Results.Count;NetworkActivity='None';RemoteChanges='None'}
