<#
.SYNOPSIS
Runs the complete MSADPT Directory Control evidence, reduction, token, and effective-access pipeline.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$EngagementDirectory,
 [string]$Server,
 [PSCredential]$Credential,
 [ValidateRange(1,64)][int]$MaximumTokenDepth=16,
 [switch]$ForceRerun,
 [switch]$NoColor
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$Version='1.0.1';$Root=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path
function Show([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray){$t='[{0,-12}] {1}'-f$State,$Message;if($NoColor){Write-Host $t}else{Write-Host $t -ForegroundColor $Color}}
function ReadJson([string]$Path){Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop}
function H([object]$Value){[Net.WebUtility]::HtmlEncode([string]$Value)}
$EngagementDirectory=[IO.Path]::GetFullPath($EngagementDirectory);$Evidence=Join-Path $EngagementDirectory 'evidence\DirectoryControl';$Reduction=Join-Path $EngagementDirectory 'analysis\DirectoryControlReduction';$Token=Join-Path $EngagementDirectory 'evidence\DirectoryControlToken';$Effective=Join-Path $EngagementDirectory 'analysis\DirectoryControlEffectiveAccess';$Reports=Join-Path $EngagementDirectory 'reports';$State=Join-Path $EngagementDirectory 'state\stages'
foreach($d in @($Evidence,$Reduction,$Token,$Effective,$Reports,$State)){New-Item -ItemType Directory -Path $d -Force|Out-Null}
Show START "Directory Control effective-access pipeline v$Version" Cyan
Show SAFETY 'ACL and token collection are read-only ADWS/LDAP operations. Reduction and effective-access evaluation are offline. Directory changes=None; impact reproduction=None.' Yellow
$collector=Join-Path $Root 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlAssessment-v1.0.0.ps1';$reducer=Join-Path $Root 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlCandidateReduction-v1.0.4.ps1';$tokenCollector=Join-Path $Root 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlTokenEvidence-v1.0.0.ps1';$evaluator=Join-Path $Root 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccess-v1.0.1.ps1'
foreach($p in @($collector,$reducer,$tokenCollector,$evaluator)){if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "PipelineComponentMissing: $p"}}
$candidatePath=Join-Path $Evidence 'directory-control-first-hop-candidates.csv';$reducedCandidatePath=Join-Path $Reduction 'directory-control-prioritized-target-details.csv';$tokenPath=Join-Path $Token 'directory-control-token-evidence.csv'
if($ForceRerun -or -not(Test-Path -LiteralPath $candidatePath -PathType Leaf)){
 Show DIRCOLLECT 'Collecting targeted high-impact objects, ACLs, and trustees.' Magenta;$p=@{OutputDirectory=$Evidence;NoColor=[bool]$NoColor};if($Server){$p.Server=$Server};if($Credential){$p.Credential=$Credential};$p.StartingIdentity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;$null=& $collector @p
}else{Show REUSE 'Directory Control candidate evidence exists; collection skipped.' DarkGreen}
if($ForceRerun -or -not(Test-Path -LiteralPath $reducedCandidatePath -PathType Leaf)){
 Show DIRREDUCE 'Reducing raw ACL candidates into reviewable validation families.' Cyan;if(Test-Path $Reduction){Remove-Item $Reduction -Recurse -Force};$null=& $reducer -DirectoryControlEvidenceDirectory $Evidence -OutputDirectory $Reduction -NoColor:$NoColor
}else{Show REUSE 'Directory Control reduction evidence exists; reduction skipped.' DarkGreen}
$TokenTarget='current domain';if($Server){$TokenTarget=$Server};Show TOKENPLAN "Target=$TokenTarget; protocol=ADWS/LDAP; operation=read trustee, SIDHistory, primary group, direct and nested memberships; changes=None." Magenta
if($ForceRerun -or -not(Test-Path -LiteralPath $tokenPath -PathType Leaf)){
 if(Test-Path $Token){Remove-Item $Token -Recurse -Force};$p=@{CandidateEvidencePath=$reducedCandidatePath;OutputDirectory=$Token;MaximumDepth=$MaximumTokenDepth;NoColor=[bool]$NoColor};if($Server){$p.Server=$Server};if($Credential){$p.Credential=$Credential};$null=& $tokenCollector @p
}else{Show REUSE 'Token evidence exists; token collection skipped.' DarkGreen}
Show EFFECTIVE 'Evaluating exact ACE applicability and collected-token evidence offline.' Cyan
if(Test-Path $Effective){Remove-Item $Effective -Recurse -Force};$null=& $evaluator -DirectoryControlEvidenceDirectory $Evidence -CandidateReductionDirectory $Reduction -OutputDirectory $Effective -TokenEvidencePath $tokenPath -NoColor:$NoColor
$tokenSummary=ReadJson (Join-Path $Token 'directory-control-token-summary.json');$effectiveSummary=ReadJson (Join-Path $Effective 'directory-control-effective-access-summary.json');$evals=@(Import-Csv (Join-Path $Effective 'directory-control-effective-access-evaluations.csv'));$confirmed=@($evals|Where-Object{$_.Disposition-eq'EffectiveControlConfirmed'});$inconclusive=@($evals|Where-Object{$_.Disposition-eq'Inconclusive'});$notEstablished=@($evals|Where-Object{$_.Disposition-eq'EffectiveControlNotEstablished'})
$rows=@($confirmed|Select-Object -First 50|ForEach-Object{"<tr><td>$(H $_.ValidationPriority)</td><td>$(H $_.Trustee)</td><td>$(H $_.Capability)</td><td>$(H $_.TargetName)</td><td>$(H $_.Reason)</td></tr>"})-join''
$html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT Directory Control Effective Access</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left}th{background:#eaf2f8}.warn{border-left:5px solid #d68910}</style></head><body><h1>Directory Control Effective Access</h1><div class="card"><b>Pipeline:</b> v$Version<br><b>Token principals:</b> $($tokenSummary.PrincipalCount)<br><b>Complete tokens:</b> $($tokenSummary.CompletePrincipalCount)<br><b>Incomplete tokens:</b> $($tokenSummary.IncompletePrincipalCount)<br><b>Evaluations:</b> $($evals.Count)<br><b>Effective control confirmed:</b> $($confirmed.Count)<br><b>Effective control not established:</b> $($notEstablished.Count)<br><b>Inconclusive:</b> $($inconclusive.Count)</div><div class="card warn"><b>Interpretation boundary:</b> EffectiveControlConfirmed establishes only applicable directory permission for the collected token evidence. Impact was not reproduced and no vulnerability is automatically confirmed.</div><h2>Confirmed Permission Candidates</h2><table><tr><th>Validation Priority</th><th>Trustee</th><th>Capability</th><th>Target</th><th>Reason</th></tr>$rows</table><h2>Evidence</h2><ul><li><a href="../analysis/DirectoryControlEffectiveAccess/directory-control-effective-access-evaluations.csv">Effective-access evaluations</a></li><li><a href="../analysis/DirectoryControlEffectiveAccess/directory-control-effective-access-summary.json">Effective-access summary</a></li><li><a href="../evidence/DirectoryControlToken/directory-control-token-evidence.csv">Token evidence</a></li><li><a href="../evidence/DirectoryControlToken/directory-control-token-summary.json">Token summary</a></li></ul></body></html>
"@
$report=Join-Path $Reports 'MSADPT-Directory-Control-Effective-Access.html';[IO.File]::WriteAllText($report,$html,(New-Object Text.UTF8Encoding($false)))
$stage=[pscustomobject][ordered]@{SchemaVersion='1.0';Stage='DirectoryControlEffectiveAccess';Status='Completed';Disposition=[string]$effectiveSummary.Disposition;GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');TokenPrincipalCount=[int]$tokenSummary.PrincipalCount;CompleteTokenCount=[int]$tokenSummary.CompletePrincipalCount;IncompleteTokenCount=[int]$tokenSummary.IncompletePrincipalCount;EvaluationCount=$evals.Count;EffectiveControlConfirmedCount=$confirmed.Count;EffectiveControlNotEstablishedCount=$notEstablished.Count;InconclusiveCount=$inconclusive.Count;ImpactReproduced=$false;VulnerabilityConfirmed=$false;ReportPath=$report};$stage|ConvertTo-Json -Depth 10|Set-Content (Join-Path $State 'directory-control-effective-access.json') -Encoding UTF8
Show REPORT $report Cyan;Show DONE "Evaluations=$($evals.Count); confirmed=$($confirmed.Count); inconclusive=$($inconclusive.Count)." Green
[pscustomobject][ordered]@{Status='Passed';PipelineVersion=$Version;EngagementDirectory=$EngagementDirectory;TokenPrincipalCount=[int]$tokenSummary.PrincipalCount;CompleteTokenCount=[int]$tokenSummary.CompletePrincipalCount;EvaluationCount=$evals.Count;EffectiveControlConfirmedCount=$confirmed.Count;EffectiveControlNotEstablishedCount=$notEstablished.Count;InconclusiveCount=$inconclusive.Count;ImpactReproduced=$false;VulnerabilityConfirmed=$false;HtmlReportPath=$report;NetworkActivity='ReadOnlyADQueries';RemoteChanges='None'}
