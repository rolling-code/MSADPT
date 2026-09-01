[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Failures=New-Object 'System.Collections.Generic.List[object]'
function Fail{param([string]$Gate,[string]$Detail)$Failures.Add([pscustomobject]@{Gate=$Gate;Detail=$Detail})}
$OrchestratorPath=Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1'
$RegistryPath=Join-Path $RepositoryRoot 'Catalogs\module-registry.json'
foreach($Path in @($OrchestratorPath,$RegistryPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){Fail 'RequiredFile' $Path}}
$Tokens=$null;$ParseErrors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($OrchestratorPath,[ref]$Tokens,[ref]$ParseErrors)
foreach($ParseError in [object[]]@($ParseErrors)){Fail 'OrchestratorParse' $ParseError.Message}
$Registry=Get-Content -LiteralPath $RegistryPath -Raw|ConvertFrom-Json
$ExpectedCore=@('Invoke-MSADPTKerberosSPNBaselineCollection','Complete-MSADPTKerberosSPNBaseline','Invoke-MSADPTDomainControllerEnumeration')
$CoreIntegrated=@($Registry.Modules|Where-Object{$_.OrchestrationState -eq 'Integrated'}|Select-Object -ExpandProperty ModuleId)
foreach($ModuleId in $ExpectedCore){if($ModuleId -notin $CoreIntegrated){Fail 'CoreRegistryIntegration' $ModuleId}}
$Optional=@($Registry.Modules|Where-Object{$_.OrchestrationState -eq 'IntegratedOptional'}|Select-Object -ExpandProperty ModuleId)
if('Invoke-MSADPTDomainControllerPatchState' -notin $Optional){Fail 'OptionalRegistryIntegration' 'Invoke-MSADPTDomainControllerPatchState'}
try{
 $PlanResult=&$OrchestratorPath -Mode Plan -Profile Quick -NoColor
 if([string]$PlanResult.Status -ne 'Passed'){Fail 'PlanStatus' ([string]$PlanResult.Status)}
 if([int]$PlanResult.LiveModulesExecuted -ne 0){Fail 'PlanExecutedLiveModule' ([string]$PlanResult.LiveModulesExecuted)}
 $PatchPlan=&$OrchestratorPath -Mode Plan -Profile Quick -IncludePatchState -NoColor
 if([string]$PatchPlan.Status -ne 'Passed'){Fail 'PatchPlanStatus' ([string]$PatchPlan.Status)}
 if([int]$PatchPlan.LiveModulesExecuted -ne 0){Fail 'PatchPlanExecutedLiveModule' ([string]$PatchPlan.LiveModulesExecuted)}
}catch{Fail 'PlanExecution' $_.Exception.Message}
$Rows=[object[]]$Failures.ToArray()
[pscustomobject]@{Status=if($Rows.Count -eq 0){'Passed'}else{'Failed'};FailureCount=$Rows.Count;Failures=$Rows;LiveNetworkActivity='None'}