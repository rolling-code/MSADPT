[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Orchestrator=Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1'
$DnsModule=Join-Path $RepositoryRoot 'Modules\ADDnsSecurity\Invoke-MSADPTADDnsSecurity.ps1'
foreach($Path in @($Orchestrator,$DnsModule)){
 $Tokens=$null;$Errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$Errors)
 if(@($Errors).Count-gt0){throw "$Path`: $(@($Errors|ForEach-Object{$_.Message})-join'; ')"}
}
$Text=[IO.File]::ReadAllText($DnsModule)
foreach($Marker in @('$a.Name=''dnsRecord''','$a.Add([byte[]]$blob)','DirectoryEntry($ZoneLdapPath)','GetAccessRules','CleanupVerified','NoSuchObject')){
 if(-not$Text.Contains($Marker)){throw "ContractMissing: $Marker"}
}
if($Text.Contains('DirectoryAttribute(''dnsRecord'',$blob)')){throw 'UnsafeDirectoryAttributeConstructorStillPresent'}
[pscustomobject][ordered]@{Status='Passed';ADDnsModuleVersion='0.2.1';TypedDnsRecordAttribute=$true;DirectoryEntryAclRead=$true;CleanupVerification=$true}
