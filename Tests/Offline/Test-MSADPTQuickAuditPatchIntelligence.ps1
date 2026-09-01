[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Failures=New-Object 'System.Collections.Generic.List[object]'
function Fail([string]$Gate,[string]$Detail){$Failures.Add([pscustomobject]@{Gate=$Gate;Detail=$Detail})}
$Orchestrator=Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1'
$Tokens=$null;$Errors=$null
$Ast=[Management.Automation.Language.Parser]::ParseFile($Orchestrator,[ref]$Tokens,[ref]$Errors)
foreach($ErrorRecord in [object[]]@($Errors)){Fail 'Parse' $ErrorRecord.Message}
$Names=@($Ast.ParamBlock.Parameters|ForEach-Object{$_.Name.VariablePath.UserPath})
foreach($Name in @('IncludePatchState','RetryIncompletePatchTargets')){if($Name -notin $Names){Fail 'Parameter' $Name}}
$Plan=&$Orchestrator -Mode Plan -Profile Quick -IncludePatchState -NoColor
if([string]$Plan.Status -ne 'Passed'){Fail 'PlanStatus' ([string]$Plan.Status)}
if([int]$Plan.LiveModulesExecuted -ne 0){Fail 'PlanNetworkActivity' ([string]$Plan.LiveModulesExecuted)}
$Text=Get-Content -LiteralPath $Orchestrator -Raw
foreach($Marker in @('PATCH-STAGE-BEGIN','Current AD Vulnerabilities','PatchStateIncluded','Remote Registry over SMB/RPC')){if($Text -notmatch [regex]::Escape($Marker)){Fail 'Contract' $Marker}}
foreach($Fixture in @('quick-audit-patch-state-complete.json','quick-audit-patch-state-partial.json','quick-audit-patch-state-empty.json')){if(-not(Test-Path -LiteralPath (Join-Path $RepositoryRoot ('Tests\Fixtures\VulnerabilityIntelligence\'+$Fixture)) -PathType Leaf)){Fail 'Fixture' $Fixture}}
$Rows=[object[]]$Failures.ToArray()
[pscustomobject]@{Status=if($Rows.Count -eq 0){'Passed'}else{'Failed'};FailureCount=$Rows.Count;Failures=$Rows;NetworkActivity='None';ActiveDirectoryQueries='None'}