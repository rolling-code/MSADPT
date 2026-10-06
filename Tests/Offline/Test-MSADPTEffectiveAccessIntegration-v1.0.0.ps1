[CmdletBinding()]param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
$ErrorActionPreference='Stop';$fail=New-Object Collections.Generic.List[string]
$orch=Get-Content (Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1') -Raw
foreach($needle in @("`$OrchestratorVersion = '1.11.0'",'EFFECTIVE-ACCESS-INTEGRATION-BEGIN','Invoke-MSADPTDirectoryControlEffectiveAccessPipeline-v1.0.3.ps1')){if(-not$orch.Contains($needle)){$fail.Add("Missing:$needle")}}
$reg=Get-Content (Join-Path $RepositoryRoot 'Catalogs\module-registry.json') -Raw|ConvertFrom-Json
foreach($id in @('Invoke-MSADPTDirectoryControlTokenEvidence','Invoke-MSADPTDirectoryControlSchemaClassMap','Invoke-MSADPTDirectoryControlEffectiveAccess','New-MSADPTDirectoryControlEffectiveAccessReport','Invoke-MSADPTDirectoryControlEffectiveAccessPipeline')){if($id-notin@($reg.Modules.ModuleId)){$fail.Add("RegistryMissing:$id")}}
if($fail.Count){$fail|ForEach-Object{Write-Host "[FAILED      ] $_" -ForegroundColor Red};exit 1};Write-Host '[PASSED      ] Effective-access integration contract validated.' -ForegroundColor Green