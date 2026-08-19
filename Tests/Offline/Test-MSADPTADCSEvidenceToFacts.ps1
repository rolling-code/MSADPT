<# .SYNOPSIS Tests the offline ADCS fact builder against the saved evidence shape. .NOTES Version: 1.0.1 #>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$BuilderPath,[Parameter(Mandatory=$true)][string]$TemplateConfigurationPath,[Parameter(Mandatory=$true)][string]$TemplateAccessPath,[Parameter(Mandatory=$true)][string]$IdentityPrerequisitePath,[Parameter(Mandatory=$true)][string]$OutputRoot,[string]$ConsoleModulePath)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
foreach($Path in @($BuilderPath,$TemplateConfigurationPath,$TemplateAccessPath,$IdentityPrerequisitePath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required file not found: $Path"}}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force};New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
$FactsPath=Join-Path $OutputRoot 'adcs-facts.json';$Output=@(& $BuilderPath -TemplateConfigurationPath $TemplateConfigurationPath -TemplateAccessPath $TemplateAccessPath -IdentityPrerequisitePath $IdentityPrerequisitePath -OutputPath $FactsPath -ConsoleModulePath $ConsoleModulePath -Quiet)
$Terminal=$Output|Where-Object{$null-ne$_.PSObject.Properties['BuilderVersion']}|Select-Object -Last 1
$Document=Get-Content -LiteralPath $FactsPath -Raw|ConvertFrom-Json;$Facts=@($Document.facts)
$Required=@('enterpriseCaPresent','templatePublished','enrolleeSuppliesIdentity','authenticationCapableEku','managerApprovalDisabled','authorizedSignaturesNotRequired','effectiveLowPrivilegeEnrollment','effectiveNonPrivilegedTemplateControl','affectedVersionOneTemplate','principalResolved','editfAttributeSubjectAltName2Observed','encryptedRpcRequestEnforced')
$Checks=@(
[pscustomobject]@{Test='TerminalCompleted';Passed=($Terminal.Status -eq 'Completed')},
[pscustomobject]@{Test='FactsCreated';Passed=($Facts.Count -ge 12)},
[pscustomobject]@{Test='RequiredFactIdsPresent';Passed=(@($Required|Where-Object{$_ -notin $Facts.id}).Count -eq 0)},
[pscustomobject]@{Test='AllowedStatesOnly';Passed=(@($Facts|Where-Object{$_.state -notin @('Confirmed','Not observed','Inconclusive','Not applicable')}).Count -eq 0)},
[pscustomobject]@{Test='RuntimeMissingRemainsInconclusive';Passed=(($Facts|Where-Object id -eq 'editfAttributeSubjectAltName2Observed').state -eq 'Inconclusive')},
[pscustomobject]@{Test='NoVulnerabilityDeclarations';Passed=((Get-Content -LiteralPath $FactsPath -Raw) -notmatch '(?i)"state"\s*:\s*"(vulnerable|exploitable|critical)"')}
)
$Checks|Format-Table -AutoSize;$Failed=@($Checks|Where-Object{-not $_.Passed});if($Failed.Count -gt 0){throw "$($Failed.Count) ADCS fact-builder test(s) failed."};[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;BuilderVersion='0.1.1';FactCount=$Facts.Count;OutputPath=$FactsPath}
