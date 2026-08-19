<#
.SYNOPSIS
Tests planner v0.2.0 identity-aware ranking and action consolidation.
.NOTES
Version: 1.1.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PlannerPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter()][string]$ConsoleModulePath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not(Test-Path -LiteralPath $PlannerPath -PathType Leaf)){throw "Planner not found: $PlannerPath"}
$Tokens=$null;$ParseErrors=$null;$null=[System.Management.Automation.Language.Parser]::ParseFile($PlannerPath,[ref]$Tokens,[ref]$ParseErrors)
if($ParseErrors.Count -gt 0){throw "Planner parse failed: $($ParseErrors.Message -join '; ')"}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
$CandidatesPath=Join-Path $OutputRoot 'candidate-fixtures.json';$ContextPath=Join-Path $OutputRoot 'identity-context.json'
function New-Fact([string]$Id,[string]$State){[pscustomobject]@{id=$Id;state=$State;rationale='synthetic';sourceEvidence=@('synthetic');limitations=@()}}
$Ids=@('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','enrolleeSuppliesIdentity','authenticationCapableEku','managerApprovalDisabled','authorizedSignaturesNotRequired')
$PrivFacts=foreach($Id in $Ids){New-Fact $Id $(if($Id-eq'effectiveLowPrivilegeEnrollment'){'Inconclusive'}else{'Confirmed'})}
$GroupFacts=foreach($Id in $Ids){New-Fact $Id $(if($Id-eq'effectiveLowPrivilegeEnrollment'){'Inconclusive'}else{'Confirmed'})}
$BroadFacts=foreach($Id in $Ids){New-Fact $Id 'Confirmed'}
$BlockedFacts=foreach($Id in $Ids){New-Fact $Id $(if($Id-eq'authenticationCapableEku'){'Not observed'}else{'Confirmed'})}
$Candidates=@(
[pscustomobject]@{candidateId='ESC1|CA|T|EXAMPLE\Domain Admins';technique='ESC1';certificationAuthority='CA';template='T';principal='EXAMPLE\Domain Admins';accessRowCount=1;disposition='Incomplete evidence';requiredCount=7;satisfiedRequiredCount=6;missingOrInconclusive=@([pscustomobject]@{id='effectiveLowPrivilegeEnrollment'});notObserved=@();facts=@($PrivFacts);safeFollowUp='x'},
[pscustomobject]@{candidateId='ESC1|CA|T|EXAMPLE\AppGroup';technique='ESC1';certificationAuthority='CA';template='T';principal='EXAMPLE\AppGroup';accessRowCount=2;disposition='Incomplete evidence';requiredCount=7;satisfiedRequiredCount=6;missingOrInconclusive=@([pscustomobject]@{id='effectiveLowPrivilegeEnrollment'});notObserved=@();facts=@($GroupFacts);safeFollowUp='x'},
[pscustomobject]@{candidateId='ESC1|CA|T|NT AUTHORITY\Authenticated Users';technique='ESC1';certificationAuthority='CA';template='T';principal='NT AUTHORITY\Authenticated Users';accessRowCount=1;disposition='Prerequisites satisfied';requiredCount=7;satisfiedRequiredCount=7;missingOrInconclusive=@();notObserved=@();facts=@($BroadFacts);safeFollowUp='x'},
[pscustomobject]@{candidateId='ESC1|CA|B|EXAMPLE\AppGroup';technique='ESC1';certificationAuthority='CA';template='B';principal='EXAMPLE\AppGroup';accessRowCount=1;disposition='Blocked';requiredCount=7;satisfiedRequiredCount=6;missingOrInconclusive=@();notObserved=@([pscustomobject]@{id='authenticationCapableEku'});facts=@($BlockedFacts);safeFollowUp='x'},
[pscustomobject]@{candidateId='ESC2|CA|T|EXAMPLE\AppGroup';technique='ESC2';certificationAuthority='CA';template='T';principal='EXAMPLE\AppGroup';accessRowCount=2;disposition='Incomplete evidence';requiredCount=7;satisfiedRequiredCount=6;missingOrInconclusive=@([pscustomobject]@{id='effectiveLowPrivilegeEnrollment'});notObserved=@();facts=@($GroupFacts);safeFollowUp='x'}
)
$Contexts=@(
[pscustomobject]@{identityReference='EXAMPLE\Domain Admins';category='PrivilegedAdministrative';confidence='High';validationPriorityModifier=-60;isPrivilegedContext=$true;isBroadIdentity=$false},
[pscustomobject]@{identityReference='EXAMPLE\AppGroup';category='SecurityGroup';confidence='Medium';validationPriorityModifier=20;isPrivilegedContext=$false;isBroadIdentity=$false},
[pscustomobject]@{identityReference='NT AUTHORITY\Authenticated Users';category='BroadLowPrivilege';confidence='High';validationPriorityModifier=30;isPrivilegedContext=$false;isBroadIdentity=$true}
)
$Candidates|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $CandidatesPath -Encoding UTF8
$Contexts|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $ContextPath -Encoding UTF8
$AnalysisRoot=Join-Path $OutputRoot 'Analysis'
$Output=@(& $PlannerPath -CandidateFactsPath $CandidatesPath -IdentityContextPath $ContextPath -OutputDirectory $AnalysisRoot -ConsoleModulePath $ConsoleModulePath -TopCandidateCount 5 -Quiet)
$Terminal=@($Output|Where-Object{$null-ne$_.PSObject.Properties['plannerVersion'] -and [string]$_.status -eq 'Completed'})|Select-Object -Last 1
if($null-eq$Terminal){throw 'PlannerTerminalResultMissing'}
$Plan=@(Get-Content -LiteralPath (Join-Path $AnalysisRoot 'adcs-candidate-validation-plan.json') -Raw|ConvertFrom-Json)
$Priv=$Plan|Where-Object candidateId -like '*Domain Admins'|Select-Object -First 1
$Group=$Plan|Where-Object candidateId -eq 'ESC1|CA|T|EXAMPLE\AppGroup'|Select-Object -First 1
$Broad=$Plan|Where-Object candidateId -like '*Authenticated Users'|Select-Object -First 1
$Office=Get-Content -LiteralPath (Join-Path $AnalysisRoot 'adcs-next-lan-validation-plan.json') -Raw|ConvertFrom-Json
$Checks=@(
[pscustomobject]@{Test='PlannerParsed';Passed=($ParseErrors.Count-eq0)},
[pscustomobject]@{Test='TerminalCompleted';Passed=([string]$Terminal.status-eq'Completed')},
[pscustomobject]@{Test='FiveCandidatesRanked';Passed=($Plan.Count-eq5)},
[pscustomobject]@{Test='CompletenessPreserved';Passed=([int]$Priv.evidenceCompletenessScore-eq86 -and [int]$Group.evidenceCompletenessScore-eq86)},
[pscustomobject]@{Test='PrivilegedRouteDeprioritized';Passed=([int]$Priv.validationPriorityScore-lt[int]$Group.validationPriorityScore)},
[pscustomobject]@{Test='BroadRouteRanksFirst';Passed=([int]$Broad.rank-eq1)},
[pscustomobject]@{Test='ScoresSeparated';Passed=($null-ne$Plan[0].PSObject.Properties['evidenceCompletenessScore'] -and $null-ne$Plan[0].PSObject.Properties['validationPriorityScore'])},
[pscustomobject]@{Test='IdentityCategoryIncluded';Passed=([string]$Priv.identityCategory-eq'PrivilegedAdministrative')},
[pscustomobject]@{Test='ActionsConsolidated';Passed=(@($Office.consolidatedEvidenceActions).Count-eq4 -and @($Office.consolidatedEvidenceActions|Where-Object supportingCandidateCount -eq 2).Count-eq1)},
[pscustomobject]@{Test='PriorityNotSeverity';Passed=([string]$Office.scoreDefinitions.validationPriorityScore-match'Not severity')},
[pscustomobject]@{Test='NoExploitAuthorization';Passed=((Get-Content -LiteralPath (Join-Path $AnalysisRoot 'adcs-next-lan-validation-plan.json') -Raw)-notmatch '(?i)execute exploit|request malicious certificate')}
)
$Checks|Format-Table -AutoSize;$Failed=@($Checks|Where-Object{-not$_.Passed});if($Failed.Count-gt0){$Failed|Format-List Test,Passed;throw "$($Failed.Count) planner v0.2 test(s) failed."}
[pscustomobject][ordered]@{Status='Passed';TestCount=$Checks.Count;PlannerVersion='0.2.0';TestVersion='1.1.1';CandidateCount=$Plan.Count;TopCandidate=$Plan[0].candidateId;PrivilegedRank=$Priv.rank;GroupRank=$Group.rank;OutputRoot=$AnalysisRoot}
