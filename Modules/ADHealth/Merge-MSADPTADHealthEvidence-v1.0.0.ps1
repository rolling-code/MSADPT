<# .SYNOPSIS Correlates normalized AD health evidence. .NOTES Version: 1.0.0 #>
[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$InputPath,[string[]]$ExpectedTarget=@())
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$rows=@();foreach($p in $InputPath){$v=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json;$rows+=@($v)}
$observed=@($rows|ForEach-Object{$_.Target}|Where-Object{$_ -and $_ -ne 'Unknown'}|Sort-Object -Unique)
$missing=@($ExpectedTarget|Where-Object{$_ -notin $observed});$conflicts=New-Object 'System.Collections.Generic.List[object]'
foreach($g in @($rows|Group-Object Target,Tool)){ $d=@($g.Group.HealthDisposition|Sort-Object -Unique);if('ConfirmedHealthy' -in $d -and 'ConfirmedUnhealthy' -in $d){$conflicts.Add([pscustomobject]@{Key=$g.Name;Dispositions=$d})}}
$unhealthy=@($rows|Where-Object HealthDisposition -eq 'ConfirmedUnhealthy');$inconclusive=@($rows|Where-Object HealthDisposition -eq 'Inconclusive')
$overall=if($unhealthy.Count){'ConfirmedUnhealthy'}elseif($conflicts.Count -or $missing.Count -or $inconclusive.Count){'Inconclusive'}elseif($rows.Count){'ConfirmedHealthy'}else{'Inconclusive'}
[pscustomobject][ordered]@{SchemaVersion='1.0';OverallDisposition=$overall;EvidenceCount=$rows.Count;ExpectedTargetCount=@($ExpectedTarget).Count;ObservedTargetCount=$observed.Count;MissingTargets=$missing;ConfirmedUnhealthyCount=$unhealthy.Count;InconclusiveCount=$inconclusive.Count;ConflictCount=$conflicts.Count;Conflicts=@($conflicts.ToArray());Evidence=$rows;Limitations=@(if($missing.Count){"Missing target evidence: $($missing -join ', ')"};if($conflicts.Count){'Contradictory health observations require review.'})}
