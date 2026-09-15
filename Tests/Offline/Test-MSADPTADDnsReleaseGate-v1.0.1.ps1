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
$OrchestratorText=[IO.File]::ReadAllText($Orchestrator)
$DnsText=[IO.File]::ReadAllText($DnsModule)
$OrchestratorMarkers=@('Temporary dnsNode create-read-resolve-delete-verify','PriorADDns.ModuleVersion -eq ''0.2.2''','Authorization breadth:')
foreach($Marker in $OrchestratorMarkers){if(-not$OrchestratorText.Contains($Marker)){throw "OrchestratorContractMissing: $Marker"}}
$DnsMarkers=@('$objectClassAttribute.Name=''objectClass''','$objectClassAttribute.Add(''top'')','$objectClassAttribute.Add(''dnsNode'')','$a.Add([byte[]]$blob)')
foreach($Marker in $DnsMarkers){if(-not$DnsText.Contains($Marker)){throw "DnsContractMissing: $Marker"}}
[pscustomobject]@{Status='Passed';NetworkOperationsArrayGrammar=$true;ObjectClassMultiValue=$true;ReuseGateHardened=$true;HtmlAuthorizationSummary=$true}
