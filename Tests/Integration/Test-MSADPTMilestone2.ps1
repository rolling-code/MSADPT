[CmdletBinding()]
param([string]$MSADPTRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$required=@('Controller\MSADPT.Reasoning.psm1','Integrations\Ollama\MSADPT.Ollama.psm1','Start-MSADPTMilestone2.ps1','Policies\msadpt-policy.json','Schemas\ai-decision.schema.json','Promptbooks\MSADPT-Decision-Engine-v1.0.txt','Modules\DomainControllers\DomainControllerEnumeration.module.json','Modules\ADCS\ADCSConfigurationCollection.module.json')
$results=foreach($relative in $required){$path=Join-Path $MSADPTRoot $relative;[pscustomobject]@{Path=$path;Present=Test-Path -LiteralPath $path -PathType Leaf}}
$results|Format-Table -AutoSize
if(@($results|Where-Object{-not$_.Present}).Count-gt0){throw 'Milestone 2 smoke test failed: required files are missing.'}
Import-Module (Join-Path $MSADPTRoot 'Controller\MSADPT.Reasoning.psm1') -Force
$registry=@(Get-MSADPTModuleRegistry -MSADPTRoot $MSADPTRoot)
if($registry.Count-lt2){throw ("Milestone 2 smoke test failed: expected at least two registry entries, found {0}." -f $registry.Count)}
$registeredNames=@($registry|ForEach-Object{[string]$_.Definition.name}|Where-Object{-not[string]::IsNullOrWhiteSpace($_)})
$expectedNames=@('DomainControllerEnumeration','ADCSConfigurationCollection')
$missingNames=@($expectedNames|Where-Object{$registeredNames-notcontains$_})
if($missingNames.Count-gt0){throw ("Milestone 2 smoke test failed: missing registered modules: {0}" -f ($missingNames-join', '))}
Write-Host ("Registered modules: {0}" -f ($registeredNames-join', ')) -ForegroundColor Cyan
Write-Host '[SUCCESS] MSADPT Milestone 2 smoke test passed.' -ForegroundColor Green
