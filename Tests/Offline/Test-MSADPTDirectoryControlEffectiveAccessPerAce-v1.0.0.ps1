[CmdletBinding()]param([string]$RepositoryRoot=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$p=Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccess-v1.0.3.ps1';$t=$null;$e=$null
[void][Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e);if(@($e).Count){throw "ParserFailure: $(@($e|ForEach-Object{$_.Message})-join'; ')"}
$x=[IO.File]::ReadAllText($p);foreach($m in @('ApplicableExplicitAce','ApplicableInheritedUnrestricted','ApplicableInheritedTargetClassMatch','NotApplicableInheritedTargetClassMismatch','InconclusiveTargetClassGuidUnavailable','IncludedInEffectiveAccessEvaluation','ApplicableAceCount','NonApplicableAceCount','ApplicableDenyAceCount')){if(-not$x.Contains($m)){throw "ContractMissing: $m"}}
if($x.Contains("$Restriction='Applicable'")){throw 'LegacyEvaluationWideRestrictionDetected'}
[pscustomobject]@{Status='Passed';TestVersion='1.0.0';PerAceApplicability=$true;ParserErrors=0;NetworkActivity='None';RemoteChanges='None'}
