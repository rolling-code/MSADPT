<#
.SYNOPSIS
Runs deterministic offline regression scenarios against the MSADPT per-ACE evaluator.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Evaluator=Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccess-v1.0.3.ps1'
if(-not(Test-Path -LiteralPath $Evaluator -PathType Leaf)){throw "EvaluatorMissing: $Evaluator"}
$Root=Join-Path ([IO.Path]::GetTempPath()) ('MSADPT-PerAceRegression-'+[guid]::NewGuid().ToString('N'))
$Evidence=Join-Path $Root 'evidence';$Reduction=Join-Path $Root 'reduction';$Output=Join-Path $Root 'output'
New-Item -ItemType Directory -Path $Evidence,$Reduction,$Output -Force|Out-Null
try{
 $UserGuid='bf967aba-0de6-11d0-a285-00aa003049e2';$GroupGuid='bf967a9c-0de6-11d0-a285-00aa003049e2';$ComputerGuid='bf967a86-0de6-11d0-a285-00aa003049e2'
 $Candidates=@(
  [pscustomobject]@{CandidateId='T01';Priority='P1';Trustee='TEST\P1';TrusteeSid='S-1-5-21-1-1-1-1001';TargetName='Explicit plus mismatch';TargetDistinguishedName='CN=T01,DC=test,DC=local';TargetObjectType='User';Capability='GenericAll'},
  [pscustomobject]@{CandidateId='T02';Priority='P1';Trustee='TEST\P2';TrusteeSid='S-1-5-21-1-1-1-1002';TargetName='Match plus mismatch';TargetDistinguishedName='CN=T02,DC=test,DC=local';TargetObjectType='User';Capability='GenericAll'},
  [pscustomobject]@{CandidateId='T03';Priority='P1';Trustee='TEST\P3';TrusteeSid='S-1-5-21-1-1-1-1003';TargetName='Allow plus nonapp deny';TargetDistinguishedName='CN=T03,DC=test,DC=local';TargetObjectType='User';Capability='GenericAll'},
  [pscustomobject]@{CandidateId='T04';Priority='P1';Trustee='TEST\P4';TrusteeSid='S-1-5-21-1-1-1-1004';TargetName='Deny plus nonapp allow';TargetDistinguishedName='CN=T04,DC=test,DC=local';TargetObjectType='User';Capability='GenericAll'},
  [pscustomobject]@{CandidateId='T05';Priority='P2';Trustee='TEST\P5';TrusteeSid='S-1-5-21-1-1-1-1005';TargetName='Only mismatch';TargetDistinguishedName='CN=T05,DC=test,DC=local';TargetObjectType='User';Capability='GenericAll'},
  [pscustomobject]@{CandidateId='T06';Priority='P2';Trustee='TEST\P6';TrusteeSid='S-1-5-21-1-1-1-1006';TargetName='Missing class';TargetDistinguishedName='CN=T06,DC=test,DC=local';TargetObjectType='UnknownClass';Capability='GenericAll'},
  [pscustomobject]@{CandidateId='T07';Priority='P2';Trustee='TEST\P7';TrusteeSid='S-1-5-21-1-1-1-1007';TargetName='Incomplete token';TargetDistinguishedName='CN=T07,DC=test,DC=local';TargetObjectType='User';Capability='GenericAll'},
  [pscustomobject]@{CandidateId='T08';Priority='P2';Trustee='TEST\P8';TrusteeSid='S-1-5-21-1-1-1-1008';TargetName='Token derived allow';TargetDistinguishedName='CN=T08,DC=test,DC=local';TargetObjectType='User';Capability='GenericAll'}
 )
 $Candidates|Export-Csv -LiteralPath (Join-Path $Reduction 'directory-control-prioritized-target-details.csv') -NoTypeInformation -Encoding UTF8
 $Aces=New-Object 'Collections.Generic.List[object]'
 function Add-Ace([string]$Dn,[string]$Sid,[string]$Type,[bool]$Inherited,[string]$InheritedGuid){$Aces.Add([pscustomobject]@{TargetDistinguishedName=$Dn;Trustee=$Sid;TrusteeSid=$Sid;AccessControlType=$Type;ActiveDirectoryRights='GenericAll';ObjectTypeGuid='00000000-0000-0000-0000-000000000000';InheritedObjectTypeGuid=$InheritedGuid;IsInherited=$Inherited;TargetObjectType='User';TargetName=$Dn;AceOrder=$Aces.Count})}
 Add-Ace 'CN=T01,DC=test,DC=local' 'S-1-5-21-1-1-1-1001' 'Allow' $false ''
 Add-Ace 'CN=T01,DC=test,DC=local' 'S-1-5-21-1-1-1-1001' 'Allow' $true $GroupGuid
 Add-Ace 'CN=T02,DC=test,DC=local' 'S-1-5-21-1-1-1-1002' 'Allow' $true $UserGuid
 Add-Ace 'CN=T02,DC=test,DC=local' 'S-1-5-21-1-1-1-1002' 'Allow' $true $ComputerGuid
 Add-Ace 'CN=T03,DC=test,DC=local' 'S-1-5-21-1-1-1-1003' 'Allow' $true $UserGuid
 Add-Ace 'CN=T03,DC=test,DC=local' 'S-1-5-21-1-1-1-1003' 'Deny' $true $GroupGuid
 Add-Ace 'CN=T04,DC=test,DC=local' 'S-1-5-21-1-1-1-1004' 'Deny' $true $UserGuid
 Add-Ace 'CN=T04,DC=test,DC=local' 'S-1-5-21-1-1-1-1004' 'Allow' $true $GroupGuid
 Add-Ace 'CN=T05,DC=test,DC=local' 'S-1-5-21-1-1-1-1005' 'Allow' $true $GroupGuid
 Add-Ace 'CN=T06,DC=test,DC=local' 'S-1-5-21-1-1-1-1006' 'Allow' $true $UserGuid
 Add-Ace 'CN=T07,DC=test,DC=local' 'S-1-5-21-1-1-1-1007' 'Allow' $false ''
 Add-Ace 'CN=T08,DC=test,DC=local' 'S-1-5-21-1-1-1-2008' 'Allow' $false ''
 $Aces.ToArray()|Export-Csv -LiteralPath (Join-Path $Evidence 'directory-control-ace-inventory.csv') -NoTypeInformation -Encoding UTF8
 $Tokens=@()
 foreach($n in 1..8){$sid="S-1-5-21-1-1-1-100$n";$complete=($n-ne 7);$Tokens+=[pscustomobject]@{PrincipalSid=$sid;Principal="P$n";TokenSid=$sid;TokenPrincipal="P$n";Source='Self';Depth=0;Complete=$complete;ResolutionState='Resolved'}}
 $Tokens+=[pscustomobject]@{PrincipalSid='S-1-5-21-1-1-1-1008';Principal='P8';TokenSid='S-1-5-21-1-1-1-2008';TokenPrincipal='Nested';Source='NestedGroup';Depth=1;Complete=$true;ResolutionState='Resolved'}
 $TokenPath=Join-Path $Root 'token.csv';$Tokens|Export-Csv -LiteralPath $TokenPath -NoTypeInformation -Encoding UTF8
 $SchemaPath=Join-Path $Root 'schema.csv';@([pscustomobject]@{LdapDisplayName='user';SchemaIdGuid=$UserGuid},[pscustomobject]@{LdapDisplayName='group';SchemaIdGuid=$GroupGuid},[pscustomobject]@{LdapDisplayName='computer';SchemaIdGuid=$ComputerGuid})|Export-Csv -LiteralPath $SchemaPath -NoTypeInformation -Encoding UTF8
 $null=& $Evaluator -DirectoryControlEvidenceDirectory $Evidence -CandidateReductionDirectory $Reduction -OutputDirectory $Output -TokenEvidencePath $TokenPath -SchemaClassMapPath $SchemaPath -NoColor
 $Results=@(Import-Csv -LiteralPath (Join-Path $Output 'directory-control-effective-access-evaluations.csv'))
 $Expected=@{T01='EffectiveControlConfirmed';T02='EffectiveControlConfirmed';T03='EffectiveControlConfirmed';T04='EffectiveControlNotEstablished';T05='NotApplicable';T06='Inconclusive';T07='Inconclusive';T08='EffectiveControlConfirmed'}
 foreach($Id in $Expected.Keys){$Actual=($Results|Where-Object CandidateId -eq $Id).Disposition;if($Actual -ne $Expected[$Id]){throw "ScenarioFailure[$Id]: expected=$($Expected[$Id]); actual=$Actual"}}
 $Trace=@(Import-Csv -LiteralPath (Join-Path $Output 'directory-control-effective-access-ace-trace.csv'))
 if(@($Trace|Where-Object TokenMatchType -eq 'TokenDerived').Count-ne 1){throw 'TokenDerivedTraceFailure'}
 [pscustomobject]@{Status='Passed';TestVersion='1.0.0';ScenarioCount=$Expected.Count;TraceRowCount=$Trace.Count;NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
}finally{Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue}
