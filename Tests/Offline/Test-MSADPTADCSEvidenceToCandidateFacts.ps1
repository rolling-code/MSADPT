<#
.SYNOPSIS
Tests candidate-specific ADCS facts against preserved evidence.
.NOTES
Version: 1.0.3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BuilderPath,
    [Parameter(Mandatory=$true)][string]$TemplateConfigurationPath,
    [Parameter(Mandatory=$true)][string]$TemplateAccessPath,
    [Parameter(Mandatory=$true)][string]$IdentityPrerequisitePath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter()][string]$ConsoleModulePath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($Path in @($BuilderPath,$TemplateConfigurationPath,$TemplateAccessPath,$IdentityPrerequisitePath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required file not found: $Path"}}
$Tokens=$null;$ParseErrors=$null;$null=[System.Management.Automation.Language.Parser]::ParseFile($BuilderPath,[ref]$Tokens,[ref]$ParseErrors)
if($ParseErrors.Count -gt 0){throw "Builder parse failed: $($ParseErrors.Message -join '; ')"}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
$Output=@(& $BuilderPath -TemplateConfigurationPath $TemplateConfigurationPath -TemplateAccessPath $TemplateAccessPath -IdentityPrerequisitePath $IdentityPrerequisitePath -OutputDirectory $OutputRoot -ConsoleModulePath $ConsoleModulePath -Quiet)
$Terminal=@($Output|Where-Object{$null-ne$_.PSObject.Properties['builderVersion'] -and [string]$_.status -eq 'Completed'})|Select-Object -Last 1
if($null-eq$Terminal){throw 'CandidateFactBuilderTerminalResultMissing'}
$JsonPath=Join-Path $OutputRoot 'adcs-candidate-specific-facts.json';$CsvPath=Join-Path $OutputRoot 'adcs-candidate-specific-summary.csv';$EventPath=Join-Path $OutputRoot 'adcs-candidate-specific-events.json'
$Candidates=@(Get-Content -LiteralPath $JsonPath -Raw|ConvertFrom-Json);$Events=@(Get-Content -LiteralPath $EventPath -Raw|ConvertFrom-Json)
$Esc1=@($Candidates|Where-Object technique -eq 'ESC1');$Esc4=@($Candidates|Where-Object technique -eq 'ESC4')
$Checks=@(
[pscustomobject]@{Test='BuilderParsed';Passed=($ParseErrors.Count -eq 0)},
[pscustomobject]@{Test='TerminalCompleted';Passed=([string]$Terminal.status -eq 'Completed')},
[pscustomobject]@{Test='CandidateRecordsCreated';Passed=($Candidates.Count -gt 0)},
[pscustomobject]@{Test='Esc1RecordsCreated';Passed=($Esc1.Count -gt 0)},
[pscustomobject]@{Test='Esc4RecordsCreated';Passed=($Esc4.Count -gt 0)},
[pscustomobject]@{Test='UniqueCandidateIds';Passed=(@($Candidates|Group-Object candidateId|Where-Object Count -gt 1).Count -eq 0)},
[pscustomobject]@{Test='CandidateDimensionsPresent';Passed=(@($Candidates|Where-Object{[string]::IsNullOrWhiteSpace($_.template) -or [string]::IsNullOrWhiteSpace($_.principal) -or [string]::IsNullOrWhiteSpace($_.certificationAuthority)}).Count -eq 0)},
[pscustomobject]@{Test='Esc1HasExactlyOneTemplatePublishedFact';Passed=(@($Esc1|Where-Object{@($_.facts|Where-Object id -eq 'templatePublished').Count -ne 1}).Count -eq 0)},
[pscustomobject]@{Test='Esc1HasSevenRequiredFacts';Passed=(@($Esc1|Where-Object{@($_.facts|Where-Object{$_.id -in @('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','enrolleeSuppliesIdentity','authenticationCapableEku','managerApprovalDisabled','authorizedSignaturesNotRequired')}).Count -ne 7}).Count -eq 0)},
[pscustomobject]@{Test='AclRowsAggregatedPerCandidate';Passed=(@($Candidates|Where-Object{[int]$_.accessRowCount -lt 1}).Count -eq 0)},
[pscustomobject]@{Test='StructuredEventsCreated';Passed=($Events.Count -ge 2)},
[pscustomobject]@{Test='CsvCreated';Passed=(Test-Path -LiteralPath $CsvPath -PathType Leaf)},
[pscustomobject]@{Test='NoVulnerabilityDeclarations';Passed=((Get-Content -LiteralPath $JsonPath -Raw)-notmatch '(?i)"disposition"\s*:\s*"(vulnerable|exploitable|critical|domain compromise)"')}
)
$Checks|Format-Table -AutoSize;$Failed=@($Checks|Where-Object{-not $_.Passed});if($Failed.Count -gt 0){throw "$($Failed.Count) candidate-specific ADCS test(s) failed."}
[pscustomobject][ordered]@{Status='Passed';TestCount=$Checks.Count;BuilderVersion='0.2.3';CandidateRecordCount=$Candidates.Count;Esc1RecordCount=$Esc1.Count;Esc4RecordCount=$Esc4.Count;PrerequisitesSatisfiedCount=[int]$Terminal.prerequisitesSatisfiedCount;BlockedCount=[int]$Terminal.blockedCount;IncompleteEvidenceCount=[int]$Terminal.incompleteEvidenceCount;OutputRoot=$OutputRoot}
