<#
.SYNOPSIS
Tests planner v0.3.0 with deterministic unified candidate fixtures.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PlannerPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Tokens=$null;$ParseErrors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($PlannerPath,[ref]$Tokens,[ref]$ParseErrors)
if($ParseErrors.Count -gt 0){throw "Planner parse failed: $($ParseErrors.Message -join '; ')"}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
function New-Fact([string]$Id,[string]$State){[pscustomobject]@{id=$Id;state=$State;rationale='synthetic'}}
function New-Candidate([string]$Technique,[string]$Principal,[string]$Disposition,[object[]]$Facts,[int]$Required,[int]$Satisfied){
    [pscustomobject]@{candidateId="$Technique|CA|T|$Principal";technique=$Technique;certificationAuthority='CA';template='T';principal=$Principal;disposition=$Disposition;requiredCount=$Required;satisfiedRequiredCount=$Satisfied;missingOrInconclusive=@($Facts|Where-Object{$_.state -eq 'Inconclusive'});notObserved=@($Facts|Where-Object{$_.state -eq 'Not observed'});facts=$Facts;safeFollowUp='synthetic'}
}
$Esc1Facts=@((New-Fact 'effectiveLowPrivilegeEnrollment' 'Inconclusive'),(New-Fact 'x' 'Confirmed'))
$Esc2Facts=@((New-Fact 'anyPurposeOrNoEkuRestriction' 'Confirmed'),(New-Fact 'effectiveLowPrivilegeEnrollment' 'Inconclusive'))
$Esc4Facts=@((New-Fact 'effectiveNonPrivilegedTemplateControl' 'Inconclusive'))
$Esc15Facts=@((New-Fact 'affectedVersionOneTemplate' 'Confirmed'),(New-Fact 'requesterControlsCertificateIdentity' 'Confirmed'),(New-Fact 'applicationPolicyRequestHandling' 'Inconclusive'),(New-Fact 'relevantPatchState' 'Inconclusive'),(New-Fact 'policyModuleRestriction' 'Inconclusive'))
$Candidates=@(
    (New-Candidate 'ESC1' 'EXAMPLE\Domain Admins' 'Incomplete evidence' $Esc1Facts 2 1)
    (New-Candidate 'ESC2' 'EXAMPLE\AppGroup' 'Incomplete evidence' $Esc2Facts 2 1)
    (New-Candidate 'ESC4' 'EXAMPLE\SERVER01$' 'Incomplete evidence' $Esc4Facts 1 0)
    (New-Candidate 'ESC15' 'EXAMPLE\AppGroup' 'Incomplete evidence' $Esc15Facts 5 2)
)
$Contexts=@(
    [pscustomobject]@{identityReference='EXAMPLE\Domain Admins';category='PrivilegedAdministrative';validationPriorityModifier=-60;isPrivilegedContext=$true;isBroadIdentity=$false}
    [pscustomobject]@{identityReference='EXAMPLE\AppGroup';category='SecurityGroup';validationPriorityModifier=20;isPrivilegedContext=$false;isBroadIdentity=$false}
    [pscustomobject]@{identityReference='EXAMPLE\SERVER01$';category='ComputerIdentity';validationPriorityModifier=15;isPrivilegedContext=$false;isBroadIdentity=$false}
)
$CandidatePath=Join-Path $OutputRoot 'candidates.json';$ContextPath=Join-Path $OutputRoot 'contexts.json';$AnalysisRoot=Join-Path $OutputRoot 'analysis'
$Candidates|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $CandidatePath -Encoding UTF8
$Contexts|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $ContextPath -Encoding UTF8
$Output=@(& $PlannerPath -UnifiedCandidateInventoryPath $CandidatePath -IdentityContextPath $ContextPath -OutputDirectory $AnalysisRoot -TopCandidateCount 4 -Quiet)
$Terminal=@($Output|Where-Object{$null -ne $_ -and $null -ne $_.PSObject.Properties['plannerVersion'] -and $null -ne $_.PSObject.Properties['status'] -and [string]$_.status -eq 'Completed'})|Select-Object -Last 1
if($null -eq $Terminal){throw 'Planner terminal result missing.'}
$Plan=@(Get-Content -LiteralPath (Join-Path $AnalysisRoot 'adcs-unified-validation-plan.json') -Raw|ConvertFrom-Json)
$Esc2=@($Plan|Where-Object{[string]$_.technique -eq 'ESC2'})[0]
$Privileged=@($Plan|Where-Object{[string]$_.principal -eq 'EXAMPLE\Domain Admins'})[0]
$Office=Get-Content -LiteralPath (Join-Path $AnalysisRoot 'adcs-unified-next-lan-plan.json') -Raw|ConvertFrom-Json
$Checks=@(
    [pscustomobject]@{Test='FourCandidates';Passed=($Plan.Count -eq 4)}
    [pscustomobject]@{Test='Esc2CapabilityDetected';Passed=([bool]$Esc2.esc2Capability)}
    [pscustomobject]@{Test='Esc2RanksAbovePrivileged';Passed=([int]$Esc2.rank -lt [int]$Privileged.rank)}
    [pscustomobject]@{Test='Esc15GapsConsolidated';Passed=(@($Office.consolidatedEvidenceActions|Where-Object{$_.actionKey -like 'Esc15*'}).Count -eq 3)}
    [pscustomobject]@{Test='NoPrivilegedTopInflation';Passed=([int]$Terminal.privilegedTopCandidateCount -eq 1)}
    [pscustomobject]@{Test='OutputFilesCreated';Passed=(@($Terminal.evidence|Where-Object{Test-Path -LiteralPath $_ -PathType Leaf}).Count -eq 4)}
)
$Checks|Format-Table -AutoSize
$Failed=@($Checks|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){$Failed|Format-List Test,Passed;throw "$($Failed.Count) planner v0.3.0 test(s) failed."}
[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;PlannerVersion='0.3.0';TestVersion='1.0.0'}
