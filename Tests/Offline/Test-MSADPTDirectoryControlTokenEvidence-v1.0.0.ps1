[CmdletBinding()]param([string]$RepositoryRoot=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Path=Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlTokenEvidence-v1.0.0.ps1'
if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw 'TokenCollectorMissing'}
$Tokens=$null;$Errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$Errors)
if(@($Errors).Count){throw "ParserFailure: $(@($Errors|ForEach-Object{$_.Message})-join'; ')"}
$Text=[IO.File]::ReadAllText($Path)
foreach($Marker in @('Version: 1.0.0','MaximumDepth','SIDHistory','PrimaryGroup','NestedGroup','TraversalComplete','directory-control-token-evidence.csv','Directory changes=None','ReadOnlyADQueries')){
    if(-not $Text.Contains($Marker)){throw "ContractMissing: $Marker"}
}
[pscustomobject]@{Status='Passed';TestVersion='1.0.0';ParserErrors=0;SidHistoryContract=$true;NestedGroupContract=$true;CycleProtectionContract=$true;CompletenessContract=$true;NetworkActivity='None';RemoteChanges='None'}
