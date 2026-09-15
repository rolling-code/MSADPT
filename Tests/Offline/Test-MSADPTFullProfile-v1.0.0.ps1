[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Orchestrator=Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1'
$RegistryPath=Join-Path $RepositoryRoot 'Catalogs\module-registry.json'
$Tokens=$null;$Errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($Orchestrator,[ref]$Tokens,[ref]$Errors)
if(@($Errors).Count-gt0){throw "OrchestratorParserFailure: $(@($Errors|ForEach-Object{$_.Message})-join'; ')"}
$Text=[IO.File]::ReadAllText($Orchestrator)
foreach($Marker in @("[ValidateSet('Quick','Full')]","if (`$Profile -eq 'Full')",'MSADPT-Full-Audit.html','No validated first-class Full-profile orchestration contract')){if(-not$Text.Contains($Marker)){throw "FullProfileContractMissing: $Marker"}}
$Registry=Get-Content -LiteralPath $RegistryPath -Raw|ConvertFrom-Json -ErrorAction Stop
$Integrated=@($Registry.Modules|Where-Object{$_.OrchestrationState -in @('Integrated','IntegratedOptional')})
$MissingFull=@($Integrated|Where-Object{'Full' -notin @($_.SupportedProfiles)})
if($MissingFull.Count-gt0){throw "IntegratedModulesMissingFullSupport: $(@($MissingFull.ModuleId)-join', ')"}
$Quick=@(&$Orchestrator -Mode Plan -Profile Quick -NoColor)
$QuickResult=@($Quick|Where-Object{$null-ne$_.PSObject.Properties['Status']})|Select-Object -Last 1
if($null-eq$QuickResult-or[string]$QuickResult.Status-ne'Passed'-or[int]$QuickResult.LiveModulesExecuted-ne0){throw 'QuickPlanRegressionFailed'}
$Full=@(&$Orchestrator -Mode Plan -Profile Full -NoColor)
$FullResult=@($Full|Where-Object{$null-ne$_.PSObject.Properties['Status']})|Select-Object -Last 1
if($null-eq$FullResult-or[string]$FullResult.Status-ne'Passed'-or[int]$FullResult.LiveModulesExecuted-ne0){throw 'FullPlanFailed'}
[pscustomobject][ordered]@{Status='Passed';QuickPlanStatus=[string]$QuickResult.Status;FullPlanStatus=[string]$FullResult.Status;PlanLiveModulesExecuted=[int]$FullResult.LiveModulesExecuted;IntegratedModuleCount=$Integrated.Count;FullAutomaticallyIncludes='PatchState,KerberosCrypto,KdcTelemetry,ADCS,ADDns';BehavioralValidationRemainsExplicit=$true;NetworkActivity='None';RemoteChanges='None'}
