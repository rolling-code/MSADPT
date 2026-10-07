<#
.SYNOPSIS
Creates offline baseline-to-corrected transition evidence and an HTML review report.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$EngagementDirectory,[string]$OutputDirectory)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $EngagementDirectory 'reports\EffectiveAccess-v1.0.3'}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$Base=Import-Csv -LiteralPath (Join-Path $EngagementDirectory 'analysis\DirectoryControlEffectiveAccess\directory-control-effective-access-evaluations.csv')
$New=Import-Csv -LiteralPath (Join-Path $EngagementDirectory 'analysis\DirectoryControlEffectiveAccess-v1.0.3\directory-control-effective-access-evaluations.csv')
$Map=@{};foreach($r in $Base){$Map[$r.CandidateId]=$r}
$Transitions=@(foreach($r in $New){if($Map.ContainsKey($r.CandidateId) -and $Map[$r.CandidateId].Disposition -ne $r.Disposition){[pscustomobject]@{CandidateId=$r.CandidateId;Trustee=$r.Trustee;TargetName=$r.TargetName;TargetObjectType=$r.TargetObjectType;Capability=$r.Capability;BaselineDisposition=$Map[$r.CandidateId].Disposition;CorrectedDisposition=$r.Disposition;CorrectedReason=$r.Reason;ApplicableAceCount=$r.ApplicableAceCount;NonApplicableAceCount=$r.NonApplicableAceCount}})
$Transitions|Export-Csv -LiteralPath (Join-Path $OutputDirectory 'effective-access-v102-to-v103-transitions.csv') -not ypeInformation -Encoding UTF8
$Counts=@($New|Group-Object Disposition|Sort-Object Name|ForEach-Object{[pscustomobject]@{Disposition=$_.Name;Count=$_.Count}});$Families=@($New|Where-Object Disposition -eq 'EffectiveControlConfirmed'|Group-Object Capability|Sort-Object Count -Descending|ForEach-Object{[pscustomobject]@{Capability=$_.Name;Count=$_.Count}})
$Trustees=@($New|Where-Object Disposition -eq 'EffectiveControlConfirmed'|Group-Object Trustee|Sort-Object Count -Descending|Select-Object -First 25|ForEach-Object{[pscustomobject]@{Trustee=$_.Name;Count=$_.Count}})
$Summary=[pscustomobject]@{SchemaVersion='1.0';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');BaselineCount=$Base.Count;CorrectedCount=$New.Count;TransitionCount=$Transitions.Count;DispositionCounts=$Counts;CapabilityCounts=$Families;TopTrustees=$Trustees;ImpactReproduced=$false;VulnerabilityConfirmed=$false;NetworkActivity='None';ActiveDirectoryQueries='None'}
$Summary|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $OutputDirectory 'effective-access-v103-transition-summary.json') -Encoding UTF8
$DispositionRows=@($Counts|ForEach-Object{"<tr><td>$($_.Disposition)</td><td>$($_.Count)</td></tr>"})-join'';$FamilyRows=@($Families|ForEach-Object{"<tr><td>$($_.Capability)</td><td>$($_.Count)</td></tr>"})-join'';$TrusteeRows=@($Trustees|ForEach-Object{"<tr><td>$([Net.WebUtility]::HtmlEncode($_.Trustee))</td><td>$($_.Count)</td></tr>"})-join''
$Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT Effective Access v1.0.3</title><style>body{font-family:Segoe UI,Arial;margin:30px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:9px;padding:16px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.n{font-size:28px;font-weight:700}table{border-collapse:collapse;width:100%;margin:10px 0}th,td{border:1px solid #ccd6dd;padding:7px;text-align:left}th{background:#eaf2f8}.warn{border -le ft:5px solid #d68910}</style></head><body><h1>Directory Control Effective Access v1.0.3</h1><div class="grid"><div class="card"><div class="n">$($New.Count)</div>evaluations</div><div class="card"><div class="n">$(@($New|Where-Object Disposition -eq 'EffectiveControlConfirmed').Count)</div>confirmed permission relationships</div><div class="card"><div class="n">$($Transitions.Count)</div>v1.0.2 classifications corrected</div></div><div class="card warn"><b>Interpretation boundary:</b> These are confirmed directory permission relationships for collected tokens. Impact was not reproduced and vulnerabilities are not automatically confirmed.</div><h2>Disposition</h2><table><tr><th>Disposition</th><th>Count</th></tr>$DispositionRows</table><h2>Confirmed capability families</h2><table><tr><th>Capability</th><th>Count</th></tr>$FamilyRows</table><h2>Top trustees</h2><table><tr><th>Trustee</th><th>Count</th></tr>$TrusteeRows</table><h2>Evidence</h2><ul><li>effective-access-v102-to-v103-transitions.csv</li><li>effective-access-v103-transition-summary.json</li><li>analysis\DirectoryControlEffectiveAccess-v1.0.3</li></ul></body></html>
"@
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'MSADPT-Directory-Control-Effective-Access-v1.0.3.html'),$Html,(New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{Status='Passed';ReportVersion='1.0.0';EvaluationCount=$New.Count;TransitionCount=$Transitions.Count;OutputDirectory=$OutputDirectory;NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
