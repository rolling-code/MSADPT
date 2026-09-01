[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Failures = New-Object 'System.Collections.Generic.List[object]'
function Add-Failure { param([string]$Gate,[string]$Detail) $Failures.Add([pscustomobject]@{Gate=$Gate;Detail=$Detail}) }
$ModulePath = Join-Path $RepositoryRoot 'Modules\VulnerabilityIntelligence\Invoke-MSADPTDomainControllerPatchState-v0.1.0.ps1'
$Tokens=$null;$Errors=$null
$Ast=[Management.Automation.Language.Parser]::ParseFile($ModulePath,[ref]$Tokens,[ref]$Errors)
foreach($ErrorRecord in [object[]]@($Errors)){Add-Failure 'Parse' $ErrorRecord.Message}
$Names=@($Ast.ParamBlock.Parameters|ForEach-Object{$_.Name.VariablePath.UserPath})
foreach($Name in @('DomainControllerEvidencePath','OutputDirectory','DefinitionDirectory','Credential','TimeoutSeconds','SkipCimFallback','NoColor')){if($Name -notin $Names){Add-Failure 'Parameter' $Name}}
$Text=Get-Content -LiteralPath $ModulePath -Raw
foreach($Marker in @('Remote changes=None','RemoteRegistry','CIM-WSMan','PatchStateUnknown','evidence-manifest.json')){if($Text -notmatch [regex]::Escape($Marker)){Add-Failure 'Contract' $Marker}}
$Rows=[object[]]$Failures.ToArray()
[pscustomobject]@{Status=if($Rows.Count -eq 0){'Passed'}else{'Failed'};FailureCount=$Rows.Count;Failures=$Rows;NetworkActivity='None'}