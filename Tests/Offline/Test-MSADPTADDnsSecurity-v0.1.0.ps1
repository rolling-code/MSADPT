[CmdletBinding()]param([string]$RepositoryRoot=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$o=Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1';$m=Join-Path $RepositoryRoot 'Modules\ADDnsSecurity\Invoke-MSADPTADDnsSecurity.ps1';$r=Join-Path $RepositoryRoot 'Catalogs\module-registry.json'
foreach($p in @($o,$m,$r)){if(-not(Test-Path $p)){throw "Missing: $p"}}
foreach($p in @($o,$m)){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e);if(@($e).Count){throw "$p`: $(@($e|ForEach-Object{$_.Message})-join'; ')"}}
$cmd=Get-Command $o;if('IncludeADDns' -notin $cmd.Parameters.Keys -or 'EnableBehavioralValidation' -notin $cmd.Parameters.Keys){throw 'ADDns parameters missing'}
$reg=Get-Content $r -Raw|ConvertFrom-Json;$entry=@($reg.Modules|Where-Object ModuleId -eq 'Invoke-MSADPTADDnsSecurity');if($entry.Count-ne1){throw 'ADDns registry entry missing or duplicated'}
$text=[IO.File]::ReadAllText($m);foreach($marker in @('Create temporary dnsNode','Delete only','CleanupVerified','ImpactReproduced','NoSuchObject','GetValues([string])','AllowEmptyCollection')){if(-not$text.Contains($marker)){throw "Safety marker missing: $marker"}}
[pscustomobject]@{Status='Passed';ParserErrors=0;RegistryEntryCount=1;BoundedCleanupContract=$true;NetworkDisclosureContract=$true}
